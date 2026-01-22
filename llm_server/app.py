import logging
from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch
import gc

import unittest
import threading

from huggingface_hub import snapshot_download

app = Flask(__name__)

# Laptop
# MODELS_CONFIG = {
#     "llama3.2-1b": "meta-llama/Llama-3.2-1B-Instruct",
#     "qwen2.5-1.5b": "Qwen/Qwen2.5-1.5B-Instruct",
#     "deepseek-1.3b": "deepseek-ai/deepseek-coder-1.3b-instruct",
#     "gemma2-2b": "google/gemma-2-2b-it"
# }

# Desktop
MODELS_CONFIG = {
    "qwen-coder": "Qwen/Qwen2.5-Coder-7B-Instruct",
    # too old -> "deepseek-v2": "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct",
    "deepseek-r1": "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
    "llama3.1": "meta-llama/Llama-3.1-8B-Instruct",
    "gemma2": "google/gemma-2-9b-it"
}

current_model_id = None
model = None
tokenizer = None
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model_lock = threading.Lock()


def download_all_models():
    """Pre-download all models to local cache to avoid delays during requests"""
    print("\n" + "="*50)
    print("[INIT] Downloading all models to local cache...")
    print("="*50)

    for name, repo_id in MODELS_CONFIG.items():
        print(f"[DOWNLOAD] Checking/Downloading {name} ({repo_id})...")
        # Download only if not present
        snapshot_download(repo_id)
        # Also initialize the tokenizer to have it ready
        AutoTokenizer.from_pretrained(repo_id)

    print("="*50)
    print("[INIT] All models are ready in the local cache.")
    print("="*50 + "\n")


def unload_current_model():
    global model, tokenizer, current_model_id
    if model is not None:
        model = None

    if tokenizer is not None:
        tokenizer = None

    gc.collect()

    if torch.cuda.is_available():
        torch.cuda.synchronize()

        torch.cuda.empty_cache()
        torch.cuda.ipc_collect()

        torch.cuda.synchronize()

    gc.collect()

    current_model_id = None
    print("[CLEANUP] GPU memory cleared.")


def load_model(model_key):
    global current_model_id, model, tokenizer

    if model_key not in MODELS_CONFIG:
        raise ValueError(
            f"Model {model_key} not in supported list: {list(MODELS_CONFIG.keys())}")

    if current_model_id == model_key:
        return

    print(f"[INFO] Switching model from {current_model_id} to {model_key}...")

    # free memory
    if model is not None:
        unload_current_model()

    model_id = MODELS_CONFIG[model_key]

    try:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16
        )

        tokenizer = AutoTokenizer.from_pretrained(
            model_id, trust_remote_code=True)

        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map="auto",
            quantization_config=bnb_config,
            trust_remote_code=True
        )

        model.eval()
        current_model_id = model_key
        print(f"[INFO] {model_key} loaded on {device}")

    except Exception as e:
        print(f"Failed to load model {model_key}: {str(e)}")
        unload_current_model()
        raise e


def get_generation_strategy(model_id, tokenizer):
    """
    Returns a dictionary of generation parameters optimized for the specific model.
    """
    # Default
    config = {
        "max_new_tokens": 2048,
        "do_sample": True,
        "temperature": 0.7,
        "top_p": 0.9,
        # "pad_token_id": tokenizer.eos_token_id
    }

    model_id_lower = model_id.lower()

    if "llama-3.1" in model_id_lower:
        terminators = [
            tokenizer.eos_token_id,
            tokenizer.convert_tokens_to_ids("<|eot_id|>")
        ]
        config.update({
            "temperature": 0.6,
            "terminators": terminators,
            "repetition_penalty": 1.05  # Mild penalty for stability
        })

    elif "qwen2.5" in model_id_lower:
        # Optimized for Coding: Low Entropy
        config.update({
            "temperature": 0.2,  # Low temp for syntax precision
            "top_p": 0.8,
            "top_k": 20,
            "repetition_penalty": 1.1
        })

    elif "deepseek" in model_id_lower:
        config.update({
            "do_sample": False,
            "eos_token_id": tokenizer.eos_token_id
        })

    elif "gemma-2" in model_id_lower:
        # Optimized for Soft-Capped Logits
        config.update({
            "temperature": 1.0,  # Default per Google
            "top_p": 0.95,
            "top_k": 50,
        })

    return config


def preprocess_messages(model_id, messages):
    """
    Middleware to adapt message structure to model constraints.
    """
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]

    processed_messages = [msg.copy() for msg in messages]

    # FIX GEMMA
    if "gemma-2" in model_id.lower():
        if processed_messages and processed_messages[0].get('role') == 'system':
            system_msg = processed_messages.pop(0)
            system_content = system_msg['content']

            if processed_messages and processed_messages[0].get('role') == 'user':
                processed_messages[0]['content'] = f"{system_content}\n\n{processed_messages[0]['content']}"
            else:
                processed_messages.insert(
                    0, {"role": "user", "content": system_content})

    return processed_messages


def compute_perplexity(inputs):

    input_ids = inputs["input_ids"]
    attention_mask = inputs["attention_mask"]

    with torch.no_grad():
        outputs = model(input_ids, attention_mask=attention_mask)
        logits = outputs.logits

    shift_logits = logits[:, :-1, :]
    shift_labels = input_ids[:, 1:]

    log_probs = torch.nn.functional.log_softmax(shift_logits, dim=-1)
    target_log_probs = log_probs.gather(
        dim=-1, index=shift_labels.unsqueeze(-1)).squeeze(-1)
    target_log_probs = target_log_probs * \
        attention_mask[:, 1:].to(log_probs.dtype)
    negative_log_likelihood = - \
        target_log_probs.sum(dim=-1) / attention_mask[:, 1:].sum(dim=-1)
    perplexity = torch.exp(negative_log_likelihood)

    return {
        "perplexity": perplexity.item(),
        "mean_logbits": torch.mean(target_log_probs).item() if target_log_probs.numel() > 0 else 0.0
    }


@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200


@app.route('/models', methods=['GET'])
def list_models():
    return jsonify({"available_models": list(MODELS_CONFIG.keys())})


@app.route('/score', methods=['POST'])
def score_text():
    data = request.json
    model_id = data.get('model_id', 'llama3.2-1b')  # Default
    text = data.get('text')
    with model_lock:
        try:
            load_model(model_id)
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=4096).to(
                model.device)  # model.config.max_position_embeddings
            stats = compute_perplexity(inputs)
            return jsonify(stats)
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    user_prompt = data.get('prompt')
    model_id = data.get('model_id', 'llama3.2-1b')  # Default
    if not user_prompt:
        return jsonify({"error": "Missing 'prompt' field"}), 400
    with model_lock:
        try:
            load_model(model_id)

            if not model or not tokenizer:
                return jsonify({"error": "Model not loaded"}), 503

            final_messages = preprocess_messages(model_id, user_prompt)

            # print(f"[DEBUG] Final messages for {model_id}: {final_messages}")

            # add_generation_prompt=True adds the final token (e.g., <|start_header_id|>assistant) to signal the model to start generating.
            prompt = tokenizer.apply_chat_template(
                final_messages,
                tokenize=False,
                add_generation_prompt=True,
                truncation=True,
                max_length=4096  # model.config.max_position_embeddings
            )

            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

            strategy = get_generation_strategy(model_id, tokenizer)

            gen_params = {k: v for k, v in strategy.items() if v is not None}
            # Remove sampling params if do_sample is False
            if not gen_params.get("do_sample", True):
                gen_params.pop("temperature", None)
                gen_params.pop("top_p", None)
                gen_params.pop("top_k", None)

            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    **gen_params
                )

            # slice outputs to exclude the input prompt tokens
            response_text = tokenizer.decode(
                outputs[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)

            return jsonify({
                "model": model_id,
                "response": response_text,
            })

        except Exception as e:
            print(f"Generation failed: {str(e)}")
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


if __name__ == '__main__':
    download_all_models()

    # unittest.main()  # TESTING
    app.run(host='0.0.0.0', port=8900)
