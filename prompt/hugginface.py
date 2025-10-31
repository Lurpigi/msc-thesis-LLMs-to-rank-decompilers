from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import math

app = Flask(__name__)

# Load model and tokenizer
model_name = "openai/gpt-oss-safeguard-20b"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = model.to(device)


@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    user_prompt = data.get('prompt')
    if not user_prompt:
        return jsonify({"error": "Missing 'prompt' field"}), 400

    messages = [
        {"role": "user", "content": user_prompt},
    ]
    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    try:
        # Generate output with logits

        outputs = model.generate(
            **inputs,
            return_dict_in_generate=True,
            output_scores=True,
            max_new_tokens=5000,
        )

        # Decode generated text
        full_text = tokenizer.decode(
            outputs.sequences[0], skip_special_tokens=True)
        input_text = tokenizer.decode(
            inputs["input_ids"][0], skip_special_tokens=True)
        generated_text = full_text[len(input_text):].strip()

        print(f"[INFO] Generated text: {generated_text}")
        # print(f"[DEBUG] {tokenizer.decode(outputs[0][inputs['input_ids'].shape[-1]:])}")

        # Process scores (logits) - outputs.scores è una tupla di tensori
        scores = outputs.scores  # Tuple di tensori, uno per ogni token generato

        token_probs = []
        logbits = []
        tokens = []

        # For each generated token, compute probability and log-bits
        for i, score_tensor in enumerate(scores):
            # score_tensor shape: (1, vocab_size)
            probs = torch.softmax(score_tensor[0], dim=-1)

            # Index of the token actually generated (offset by input length)
            gen_index = inputs['input_ids'].shape[1] + i
            token_id = int(outputs.sequences[0, gen_index])

            # Probability of the generated token
            p = probs[token_id].item()
            token_probs.append(p)
            logbits.append(math.log2(p) if p > 0 else float('-inf'))

            # Add decoded token to list
            tokens.append(tokenizer.decode([token_id]))
        if logbits:
            mean_logbits = sum(logbits) / len(logbits)
            perplexity = 2 ** (-mean_logbits)
        else:
            mean_logbits = 0
            perplexity = 0

        response = {
            "model": model_name,
            "input_prompt": user_prompt,
            "generated_text": generated_text,
            "tokens": tokens,
            "token_probabilities": token_probs,
            "logbits": logbits,
            "mean_logbits": mean_logbits,
            "perplexity": perplexity
        }

        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8900)
