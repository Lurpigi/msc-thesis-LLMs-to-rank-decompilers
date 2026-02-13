import logging
import time
from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch
import gc
import psutil
import os
import unittest
import threading
from huggingface_hub import snapshot_download
from contextlib import contextmanager

from transformers import logging as transformers_logging
transformers_logging.set_verbosity_error()
transformers_logging.disable_progress_bar()

# File logging
metrics_logger = logging.getLogger('metrics')
metrics_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(
    os.path.join(os.getenv("LOG_DIR", "."), 'llm_metrics.csv'))
file_handler.setFormatter(logging.Formatter('%(asctime)s,%(message)s'))
metrics_logger.addHandler(file_handler)
if not os.path.exists(os.path.join(os.getenv("LOG_DIR", "."), 'llm_metrics.csv')) or \
   os.stat(os.path.join(os.getenv("LOG_DIR", "."), 'llm_metrics.csv')).st_size == 0:
    metrics_logger.info(
        "model_id,operation,duration_sec,peak_vram_gb,system_ram_gb,prompt_tokens,generated_tokens")

app = Flask(__name__)

# Laptop
# MODELS_CONFIG = {
#     "llama3.2-1b": "meta-llama/Llama-3.2-1B-Instruct",
#     "qwen2.5-1.5b": "Qwen/Qwen2.5-1.5B-Instruct",
#     "deepseek-1.3b": "deepseek-ai/deepseek-coder-1.3b-instruct",
#     "gemma2-2b": "google/gemma-2-2b-it"
# }

# Desktop 1
# MODELS_CONFIG = {
#     "qwen-coder": "Qwen/Qwen2.5-Coder-7B-Instruct",
#     "deepseek-r1": "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
#     "llama3.1": "meta-llama/Llama-3.1-8B-Instruct",
#     "gemma2": "google/gemma-2-9b-it"
# }

# Desktop 2
MODELS_CONFIG = {
    "qwen-3": "Qwen/Qwen3-14B",
    "deepseek-r1": "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B",
    "qwen-2.5": "Qwen/Qwen2.5-Coder-14B-Instruct",
    # "deepseek-lite": "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"
    # "starcoder2": "bigcode/starcoder2-15b-instruct-v0.1"
    # "gemma2": "google/gemma-2-9b-it"
}


@contextmanager
def monitor_execution(model_id, operation_name):
    # 1. Reset stats
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
        torch.cuda.empty_cache()
        torch.cuda.synchronize()

    start_time = time.perf_counter()

    stats = {"prompt_tokens": 0, "generated_tokens": 0}

    try:
        yield stats
    finally:
        if torch.cuda.is_available():
            torch.cuda.synchronize()

        end_time = time.perf_counter()
        duration = end_time - start_time

        peak_vram_gb = 0.0
        if torch.cuda.is_available():
            peak_vram_gb = torch.cuda.max_memory_allocated() / (1024 ** 3)

        process = psutil.Process(os.getpid())
        ram_usage_gb = process.memory_info().rss / (1024 ** 3)
        total_tokens = stats['prompt_tokens'] + stats['generated_tokens']
        tps = total_tokens / duration if duration > 0 else 0

        log_msg = (f"{model_id},{operation_name},{duration:.4f},{peak_vram_gb:.4f},"
                   f"{ram_usage_gb:.4f},{stats['prompt_tokens']},{stats['generated_tokens']}")
        metrics_logger.info(log_msg)

        print(
            f"[METRICS] {model_id} | {operation_name} | {duration:.2f}s | "
            f"VRAM: {peak_vram_gb:.2f}GB | RAM: {ram_usage_gb:.2f}GB | "
            f"Tokens: {stats['prompt_tokens']} in / {stats['generated_tokens']} out | "
            f"Speed: {tps:.2f} tok/s"
        )


class ModelEngine:
    def __init__(self):
        self.current_model_id = None
        self.model = None
        self.tokenizer = None
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu")
        self.lock = threading.Lock()

        # RAM Cache: stores {model_id: {'model': obj, 'tokenizer': obj}}
        self.ram_cache = {}

    def _clean_gpu_memory(self):
        """Helper to force VRAM cleanup"""
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.synchronize()
            torch.cuda.empty_cache()
            torch.cuda.ipc_collect()
            torch.cuda.synchronize()

    def _offload_current_model(self):
        """
        Moves the current model from VRAM to System RAM (CPU).
        Does NOT delete the object.
        """
        if self.model and self.current_model_id:
            print(
                f"[OFFLOAD] Moving {self.current_model_id} from GPU to System RAM...")

            try:
                # Attempt to move model to CPU to save it in RAM
                self.model.to("cpu")

                # Store in cache
                self.ram_cache[self.current_model_id] = {
                    "model": self.model,
                    "tokenizer": self.tokenizer
                }
                print(
                    f"[OFFLOAD] {self.current_model_id} stored in RAM cache.")

            except Exception as e:
                # Fallback for 4-bit models or configs that don't support .to('cpu')
                print(
                    f"[WARNING] Failed to move {self.current_model_id} to CPU (likely quantization limitation): {e}")
                print(
                    f"[CLEANUP] Deleting {self.current_model_id} completely instead.")
                del self.model
                del self.tokenizer

            # Remove references from active slots
            self.model = None
            self.tokenizer = None
            self.current_model_id = None

            # Clear VRAM now that the model is on CPU (or deleted)
            self._clean_gpu_memory()
            print("[OFFLOAD] VRAM cleared.")

    def completely_free_all(self):
        """
        Frees the current model AND clears the entire RAM cache.
        """
        print("[FREE] Explicit free requested. Clearing Cache and VRAM...")

        # 1. Unload current if active
        if self.model:
            del self.model
            del self.tokenizer
            self.model = None
            self.tokenizer = None
            self.current_model_id = None

        # 2. Clear RAM cache
        if self.ram_cache:
            print(
                f"[FREE] Removing {len(self.ram_cache)} models from RAM cache.")
            self.ram_cache.clear()

        # 3. Final GC
        self._clean_gpu_memory()
        print("[FREE] System state reset.")

    def load_model(self, model_key):
        if model_key not in MODELS_CONFIG:
            raise ValueError(f"Model {model_key} not supported.")

        if self.current_model_id == model_key:
            return

        print(f"[LOAD] Request to switch to {model_key}...")

        # Offload current model to RAM (Context Switch)
        self._offload_current_model()

        # Check if the requested model is already in RAM cache
        if model_key in self.ram_cache:
            print(f"[CACHE] Found {model_key} in RAM cache. Moving to GPU...")
            cached_data = self.ram_cache[model_key]

            try:
                self.model = cached_data["model"]
                self.tokenizer = cached_data["tokenizer"]

                # Move back to GPU
                self.model.to(self.device)
                self.current_model_id = model_key
                print(f"[LOAD] {model_key} restored from RAM.")
                return
            except Exception as e:
                print(
                    f"[ERROR] Failed to restore from RAM: {e}. Reloading from disk.")
                del self.ram_cache[model_key]
                self._clean_gpu_memory()

        # If not in cache or failed to restore, load from disk
        model_repo = MODELS_CONFIG[model_key]
        try:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.bfloat16
            )

            self.tokenizer = AutoTokenizer.from_pretrained(model_repo)

            self.model = AutoModelForCausalLM.from_pretrained(
                model_repo,
                device_map="auto",
                quantization_config=bnb_config,
                trust_remote_code=True
            )
            self.model.eval()
            self.current_model_id = model_key
            print(f"[LOAD] {model_key} loaded from disk.")

        except Exception as e:
            print(f"[FATAL] Failed loading {model_key}: {e}")
            self._clean_gpu_memory()
            raise e

    def get_generation_strategy(self, model_id, max_new_tokens=2048):
        # Default strategy
        config = {
            "max_new_tokens": max_new_tokens,
            "do_sample": True,
            "temperature": 0.4,
            "top_p": 0.9,
            "pad_token_id": self.tokenizer.eos_token_id
        }
        return config

    def compute_perplexity(self, text, model_id):
        with self.lock:
            self.load_model(model_id)
            with monitor_execution(model_id, "score") as metrics:
                inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=4096).to(
                    self.model.device)
                input_ids = inputs["input_ids"]
                attention_mask = inputs["attention_mask"]
                valid_tokens = attention_mask[:, 1:].sum(dim=-1)
                if valid_tokens.item() == 0:
                    return {"perplexity": -1, "mean_logbits": 0.0}

                metrics['prompt_tokens'] = input_ids.shape[1]
                metrics['generated_tokens'] = 0

                with torch.no_grad():
                    outputs = self.model(
                        input_ids, attention_mask=attention_mask)
                    logits = outputs.logits

                shift_logits = logits[:, :-1, :]
                shift_labels = input_ids[:, 1:]

                log_probs = torch.nn.functional.log_softmax(
                    shift_logits, dim=-1)
                target_log_probs = log_probs.gather(
                    dim=-1, index=shift_labels.unsqueeze(-1)).squeeze(-1)
                target_log_probs = target_log_probs * \
                    attention_mask[:, 1:].to(log_probs.dtype)
                negative_log_likelihood = - \
                    target_log_probs.sum(dim=-1) / \
                    attention_mask[:, 1:].sum(dim=-1)
                perplexity = torch.exp(negative_log_likelihood)

                return {
                    "perplexity": perplexity.item(),
                    "mean_logbits": torch.mean(target_log_probs).item() if target_log_probs.numel() > 0 else 0.0
                }

    def generate(self, model_key, prompt):
        with self.lock:
            self.load_model(model_key)
            with monitor_execution(model_key, "generate") as metrics:
                messages = [{"role": "user", "content": prompt}]
                text_input = self.tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )

                inputs = self.tokenizer(
                    text_input,
                    return_tensors="pt",
                    truncation=True,
                    max_length=15000
                ).to(self.device)

                input_token_len = inputs.input_ids.shape[1]
                metrics['prompt_tokens'] = input_token_len

                strategy = self.get_generation_strategy(model_key)

                gen_params = {k: v for k, v in strategy.items()
                              if v is not None}
                if not gen_params.get("do_sample", True):
                    gen_params.pop("temperature", None)
                    gen_params.pop("top_p", None)
                    gen_params.pop("top_k", None)

                with torch.no_grad():
                    outputs = self.model.generate(**inputs, **gen_params)

                metrics['generated_tokens'] = outputs[0].shape[0] - \
                    input_token_len

                response = self.tokenizer.decode(
                    outputs[0][inputs.input_ids.shape[1]:],
                    skip_special_tokens=True
                )
                return response


engine = ModelEngine()

MAX_RAM_CACHE_SIZE = MODELS_CONFIG.__len__()


def download_and_preload_all_models():
    """
    Downloads models to disk AND loads them into System RAM.
    Models are loaded to GPU one-by-one and then offloaded to RAM.
    """
    print("\n" + "="*60)
    print("[INIT] Starting PRELOAD sequence (Disk -> GPU -> RAM)...")
    print(f"[INIT] Target RAM Cache Size: {MAX_RAM_CACHE_SIZE} models")
    print("="*60)

    for name, repo_id in MODELS_CONFIG.items():
        print(f"[DOWNLOAD] Verifying files for {name} ({repo_id})...")
        snapshot_download(repo_id)

    print("\n" + "-"*60)
    print("[PRELOAD] Files ready. Starting RAM population...")
    print("-"*60)

    for i, name in enumerate(MODELS_CONFIG.keys()):
        print(f"[PRELOAD] Processing {name} ({i+1}/{len(MODELS_CONFIG)})...")
        try:
            engine.load_model(name)

            process = psutil.Process(os.getpid())
            ram_gb = process.memory_info().rss / (1024 ** 3)
            print(f"[STATUS] System RAM Usage: {ram_gb:.2f} GB")

        except Exception as e:
            print(f"[ERROR] Could not preload {name}: {e}")

    print("="*60)
    print("[INIT] Preload complete.")
    print(f"[INIT] Models in RAM Cache: {list(engine.ram_cache.keys())}")
    print(f"[INIT] Active on GPU: {engine.current_model_id}")
    print("="*60 + "\n")


if os.environ.get("RUN_PRELOAD") == "true":
    download_and_preload_all_models()


@app.route('/', methods=['GET'])
def health_check():
    gpu_status = "ok" if torch.cuda.is_available() else "cpu-only"
    # Show cached models in status
    cached = list(engine.ram_cache.keys())
    return jsonify({
        "status": "ready",
        "gpu": gpu_status,
        "current_model": engine.current_model_id,
        "ram_cached_models": cached
    })


@app.route('/models', methods=['GET'])
def list_models():
    return jsonify({"available_models": list(MODELS_CONFIG.keys())})


@app.route('/score', methods=['POST'])
def score_text():
    data = request.json
    model_id = data.get('model_id', 'llama3.1')
    text = data.get('text')
    try:
        stats = engine.compute_perplexity(text, model_id)
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    model_id = data.get('model_id', 'qwen-coder')
    prompt = data.get('prompt')
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400
    try:
        response_text = engine.generate(model_id, prompt)
        return jsonify({"model": model_id, "response": response_text})
    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/free', methods=['POST'])
def free_model():
    """Frees active VRAM and clears RAM cache"""
    try:
        engine.completely_free_all()
        return jsonify({"status": "All models freed (RAM + VRAM)"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8900)
