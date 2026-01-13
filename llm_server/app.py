from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch
import gc

from huggingface_hub import snapshot_download

app = Flask(__name__)

MODELS_CONFIG = {
    "llama3.2-1b": "meta-llama/Llama-3.2-1B-Instruct",
    "qwen2.5-1.5b": "Qwen/Qwen2.5-1.5B-Instruct",
    "phi3.5-mini": "microsoft/Phi-3.5-mini-instruct",
    "gemma2-2b": "google/gemma-2-2b-it"
}

current_model_id = None
model = None
tokenizer = None
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


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

def load_model(model_key):
    global current_model_id, model, tokenizer
    
    if model_key not in MODELS_CONFIG:
        raise ValueError(f"Model {model_key} not in supported list: {list(MODELS_CONFIG.keys())}")
    
    if current_model_id == model_key:
        return

    print(f"[INFO] Switching model from {current_model_id} to {model_key}...")
    
    # free memory
    if model is not None:
        del model
        del tokenizer
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            gc.collect()

    repo_id = MODELS_CONFIG[model_key]
    tokenizer = AutoTokenizer.from_pretrained(repo_id)

    # Load model with quantization if on GPU
    q_config = None
    if device.type == "cuda":
        q_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True
        )

    model = AutoModelForCausalLM.from_pretrained(
        repo_id,
        quantization_config=q_config,
        device_map="auto" if device.type == "cuda" else "cpu",
        dtype=torch.float16 if device.type == "cuda" else torch.float32,
        trust_remote_code=True,
        use_cache=False,
    )
    
    current_model_id = model_key
    print(f"[INFO] {model_key} loaded on {device}")


def compute_perplexity(inputs):

    input_ids = inputs["input_ids"]
    attention_mask = inputs["attention_mask"]

    with torch.no_grad():
        outputs = model(input_ids, attention_mask=attention_mask)
        logits = outputs.logits

    shift_logits = logits[:, :-1, :] 
    shift_labels = input_ids[:, 1:] 

    log_probs = torch.nn.functional.log_softmax(shift_logits, dim=-1)
    target_log_probs = log_probs.gather(dim=-1, index=shift_labels.unsqueeze(-1)).squeeze(-1)
    target_log_probs = target_log_probs * attention_mask[:, 1:].to(log_probs.dtype)
    negative_log_likelihood = -target_log_probs.sum(dim=-1) / attention_mask[:, 1:].sum(dim=-1)
    perplexity = torch.exp(negative_log_likelihood)

    return {
        "perplexity": perplexity.item(),
        "mean_logbits": torch.mean(target_log_probs).item() if target_log_probs.numel() > 0 else 0.0
    }

#healtcheck docker
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

@app.route('/score', methods=['POST'])
def score_text():
    data = request.json
    model_id = data.get('model_id', 'llama3.2-1b') # Default
    text = data.get('text')
    
    try:
        load_model(model_id)
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=4096).to(model.device) #model.config.max_position_embeddings
        stats = compute_perplexity(inputs)
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    user_prompt = data.get('prompt')
    model_id = data.get('model_id', 'llama3.2-1b') # Default
    if not user_prompt:
        return jsonify({"error": "Missing 'prompt' field"}), 400

    try:
        load_model(model_id)
        messages = [{"role": "user", "content": user_prompt}]
        inputs = tokenizer.apply_chat_template(messages, add_generation_prompt=True, tokenize=True, return_dict=True, return_tensors="pt").to(model.device)
        
        outputs = model.generate(**inputs, max_new_tokens=512, pad_token_id=tokenizer.eos_token_id, do_sample=False)
        full_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
        return jsonify({"model": model_id, "generated_text": full_text})
    except Exception as e:
        print(f"[ERROR] Generate failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    download_all_models()
    app.run(host='0.0.0.0', port=8900)
