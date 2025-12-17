from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch
import math

app = Flask(__name__)

model_name = "meta-llama/Llama-3.2-1B-Instruct"
#model_name = "Qwen/Qwen2.5-1.5B-Instruct"
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Load model with appropriate device configuration
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[INFO] Loading model on {device}...")

if device.type == "cuda":
    # GPU CONFIGURATION (4-bit for speed)
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_quant_type="nf4",
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=quantization_config,
        device_map="auto",
        torch_dtype=torch.float16,
    )
else:
    # CPU CONFIGURATION (No 4-bit, float32 for compatibility)
    print("[WARN] GPU not found. Running in CPU mode (slow).")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        device_map="cpu",
        torch_dtype=torch.float32 
    )

print(f"[INFO] Model loaded on {device}")

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
    text = data.get('text')
    
    if not text:
        return jsonify({"error": "Missing 'text' field"}), 400
    
    inputs = tokenizer(
        text, 
        return_tensors="pt", 
        truncation=True, 
        max_length=4096  #model.config.max_position_embeddings
    ).to(model.device)
    
    stats = compute_perplexity(inputs)
    return jsonify(stats)

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    user_prompt = data.get('prompt')
    if not user_prompt:
        return jsonify({"error": "Missing 'prompt' field"}), 400

    messages = [{"role": "user", "content": user_prompt}]
    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    ppl = compute_perplexity(inputs)
    
    try:
        outputs = model.generate(
            **inputs,
            return_dict_in_generate=True,
            output_scores=True,
            max_new_tokens=512,
            pad_token_id=tokenizer.eos_token_id,
        )

        full_text = tokenizer.decode(outputs.sequences[0], skip_special_tokens=True)
        input_text = tokenizer.decode(inputs["input_ids"][0], skip_special_tokens=True)
        generated_text = full_text[len(input_text):].strip()
        print(f"[INFO] Generated text: {generated_text}")

        # compute probabilities and logbits of generated tokens
        scores = outputs.scores
        token_probs = []
        logbits = []
        tokens = []
        for i, score_tensor in enumerate(scores):
            probs = torch.softmax(score_tensor[0], dim=-1)
            gen_index = inputs['input_ids'].shape[1] + i
            token_id = int(outputs.sequences[0, gen_index])
            p = probs[token_id].item()
            token_probs.append(p)
            logbits.append(math.log2(p) if p > 0 else float('-inf'))
            tokens.append(tokenizer.decode([token_id]))
        if logbits:
            mean_logbits = sum(logbits) / len(logbits)
            perplexity_tokens = 2 ** (-mean_logbits)
        else:
            mean_logbits = 0
            perplexity_tokens = 0

        response = {
            "model": model_name,
            "input_prompt": user_prompt,
            "input_perplexity": ppl["perplexity"],
            "input_mean_logbits": ppl["mean_logbits"],
            "generated_text": generated_text,
            "generated_tokens": tokens,
            "generated_token_probabilities": token_probs,
            "generated_logbits": logbits,
            "generated_mean_logbits": mean_logbits,
            "generated_perplexity": perplexity_tokens
        }

        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8900)
