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

        generated_text = data.get("generated_text", "")
        input_prompt = data.get("input_prompt", "")
        perplexity = data.get("perplexity", None)
        logbits = data.get("logbits", [])
        token_probs = data.get("token_probabilities", [])
        model = data.get("model", "unknown_model")

        # Salva i risultati in JSON per mantenere tutte le info
        filename = f"{OUTPUT_DIR}/flask_response.json"
        with open(filename, "w", encoding="utf-8") as out_file:
            json.dump({
                "model": model,
                "input_prompt": input_prompt,
                "generated_text": generated_text,
                "perplexity": perplexity,
                "mean_logbits": sum(logbits) / len(logbits) if logbits else None,
                "token_probabilities": token_probs
            }, out_file, indent=2, ensure_ascii=False)

        print(f"saved on in {filename}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
