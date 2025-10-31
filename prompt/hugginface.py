from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import math

app = Flask(__name__)

# Load model and tokenizer
model_name = "meta-llama/Llama-3.2-3B-Instruct"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)
model.eval()

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    user_prompt = data.get('prompt')
    if not user_prompt:
        return jsonify({"error": "Missing 'prompt' field"}), 400

    # Tokenize input
    inputs = tokenizer(user_prompt, return_tensors="pt")
    try:
        # Generate output with logits
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                return_dict_in_generate=True,
                output_scores=True,  # Usa output_scores invece di output_logits
                max_new_tokens=50,
                pad_token_id=tokenizer.eos_token_id  # Usa eos_token come pad_token
            )

        # Decode generated text
        generated_tokens = outputs.sequences[0][inputs['input_ids'].shape[1]:]
        generated_text = tokenizer.decode(generated_tokens, skip_special_tokens=True)


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
