#!/usr/bin/env python3

import requests
import sys
import os
import json
from pathlib import Path


FLASK_URL = "http://localhost:8900/generate"

PROMPT_FILE = Path("./prompt/llm_prompt.txt")
OUTPUT_DIR = Path("./prompt/res")


def main():

    if not PROMPT_FILE.exists():
        print("Error: llm_prompt.txt file not found.")
        sys.exit(1)

    with PROMPT_FILE.open("r", encoding="utf-8") as f:
        prompt_text = f.read()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Generating with response...")

    payload = {
        "prompt": prompt_text
    }

    try:
        response = requests.post(FLASK_URL, json=payload, timeout=600)
        response.raise_for_status()

        data = response.json()

        model = data.get("model", "unknown_model")
        input_prompt = data.get("input_prompt", "")
        input_perplexity = data.get("input_perplexity", None)
        input_mean_logbits = data.get("input_mean_logbits", None)
        generated_text = data.get("generated_text", "")
        generated_tokens = data.get("generated_tokens", [])
        generated_token_probabilities = data.get("generated_token_probabilities", [])
        generated_logbits = data.get("generated_logbits", [])
        generated_mean_logbits = data.get("generated_mean_logbits", None)
        generated_perplexity = data.get("generated_perplexity", None)

        # Save all results in JSON
        filename = f"{OUTPUT_DIR}/flask_response.json"
        with open(filename, "w", encoding="utf-8") as out_file:
            json.dump({
            "model": model,
            "input_prompt": input_prompt,
            "input_perplexity": input_perplexity,
            "input_mean_logbits": input_mean_logbits,
            "generated_text": generated_text,
            "generated_tokens": generated_tokens,
            "generated_token_probabilities": generated_token_probabilities,
            "generated_logbits": generated_logbits,
            "generated_mean_logbits": generated_mean_logbits,
            "generated_perplexity": generated_perplexity
            }, out_file, indent=2, ensure_ascii=False)

        print(f"saved on in {filename}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
