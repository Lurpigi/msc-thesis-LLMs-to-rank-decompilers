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
    os.path.join(os.getenv("LOG_DIR"), 'llm_metrics.csv'))
file_handler.setFormatter(logging.Formatter('%(asctime)s,%(message)s'))
metrics_logger.addHandler(file_handler)
if os.stat(os.path.join(os.getenv("LOG_DIR"), 'llm_metrics.csv')).st_size == 0:
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
MODELS_CONFIG = {
    "qwen-coder": "Qwen/Qwen2.5-Coder-7B-Instruct",
    "deepseek-r1": "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
    "llama3.1": "meta-llama/Llama-3.1-8B-Instruct",
    "gemma2": "google/gemma-2-9b-it"
}

# Desktop 2
# MODELS_CONFIG = {
#     "qwen-3": "Qwen/Qwen3-14B",
#     "deepseek-r1": "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B",
#     "llama-4": "meta-llama/meta-llama/Llama-4-Scout-17B-16E-Instruct",
#     "phi-4": "microsoft/phi-4"
# }


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

    def _unload_model(self):
        if self.model:
            print(f"[CLEANUP] Unloading {self.current_model_id}...")
            del self.model
            del self.tokenizer
            self.model = None
            self.tokenizer = None

            # Forced GC flow
            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.synchronize()
                torch.cuda.empty_cache()
                torch.cuda.ipc_collect()
                torch.cuda.synchronize()

            self.current_model_id = None
            print("[CLEANUP] VRAM cleared.")

    def load_model(self, model_key):
        if model_key not in MODELS_CONFIG:
            raise ValueError(f"Model {model_key} not supported.")

        if self.current_model_id == model_key:
            return

        print(f"[LOAD] Switching to {model_key}...")

        self._unload_model()

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
            print(f"[LOAD] {model_key} ready.")

        except Exception as e:
            print(f"[FATAL] Failed loading {model_key}: {e}")
            self._unload_model()
            raise e

    def get_generation_strategy(self, model_id, max_new_tokens=2048):
        # Default
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
                    self.model.device)  # model.config.max_position_embeddings
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

                # Preprocessing
                messages = [{"role": "user", "content": prompt}]
                text_input = self.tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )

                inputs = self.tokenizer(
                    text_input,
                    return_tensors="pt",
                    truncation=True,
                    max_length=15000  # Safety cap
                ).to(self.device)

                input_token_len = inputs.input_ids.shape[1]
                metrics['prompt_tokens'] = input_token_len

                strategy = self.get_generation_strategy(model_key)

                gen_params = {k: v for k, v in strategy.items()
                              if v is not None}
                # Remove sampling params if do_sample is False
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


def download_all_models():
    """Pre-download all models to local cache to avoid delays during requests"""
    print("\n" + "="*50)
    print("[INIT] Downloading all models to local cache...")
    print("="*50)

    for name, repo_id in MODELS_CONFIG.items():
        print(f"[DOWNLOAD] Checking/Downloading {name} ({repo_id})...")
        # Download only if not present
        snapshot_download(repo_id)
        AutoTokenizer.from_pretrained(repo_id)

    print("="*50)
    print("[INIT] All models are ready in the local cache.")
    print("="*50 + "\n")


@app.route('/', methods=['GET'])
def health_check():
    gpu_status = "ok" if torch.cuda.is_available() else "cpu-only"
    return jsonify({"status": "ready", "gpu": gpu_status, "current_model": engine.current_model_id})


@app.route('/models', methods=['GET'])
def list_models():
    return jsonify({"available_models": list(MODELS_CONFIG.keys())})


@app.route('/score', methods=['POST'])
def score_text():
    data = request.json
    model_id = data.get('model_id', 'llama3.2-1b')
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
    try:
        engine._unload_model()
        return jsonify({"status": "model freed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


class FlaskAppTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_generate(self):

        def test_model(model_key):
            payload = {
                "model_id": model_key,
                "prompt": "Scrivi una funzione C per sommare due numeri."
            }
            print(f"\n[TEST] Trying to generate with {model_key}...")
            response = self.client.post('/generate', json=payload)
            data = response.get_json()

            if response.status_code != 200:
                print(f"[FAIL] Error received: {data.get('error')}")

            self.assertEqual(response.status_code, 200)
            self.assertIn("response", data)
            print(data["response"][:200] + "...")
            print(
                f"[SUCCESS] Response from {model_key} received successfully.")

        for model_key in MODELS_CONFIG.keys():
            test_model(model_key)

    def test_score(self):
        sample_text = "void sum(int a, int b) { return a + b; }"
        for model_key in MODELS_CONFIG.keys():
            payload = {
                "model_id": model_key,
                "text": sample_text
            }
            print(f"\n[TEST] Trying to score with {model_key}...")
            response = self.client.post('/score', json=payload)
            data = response.get_json()

            if response.status_code != 200:
                print(f"[FAIL] Error received: {data.get('error')}")

            self.assertEqual(response.status_code, 200)
            self.assertIn("perplexity", data)
            print(
                f"[SUCCESS] Perplexity from {model_key}: {data['perplexity']}, Mean Logbits: {data['mean_logbits']}")


if __name__ == '__main__':
    # unittest.main()  # TESTING
    app.run(host='0.0.0.0', port=8900)
