#!/usr/bin/env python3

import requests
import sys
import os
from pathlib import Path

MODELS = {
    "d": [  #Desktop
        "llama3.2:3b",
        "gpt-oss:20b",
        "deepseek-r1:14b",
        "gemma3:12b"
    ],
    "l": [  #Laptop
        "llama3.2:3b"
    ]
}

with open("/etc/resolv.conf") as f:
    for line in f:
        if line.startswith("nameserver"):
            OLLAMA_HOST = line.split()[1].strip()
            break
    else:
        OLLAMA_HOST = "localhost"

OLLAMA_URL = f"http://{OLLAMA_HOST}:11434/api/generate"

PROMPT_FILE = Path("./prompt/llm_prompt.txt")
OUTPUT_DIR = Path("./prompt/res")

def main():
    if len(sys.argv) < 2 or sys.argv[1].lower() not in MODELS:
        print("Usage: python3 script.py [d|l]")
        sys.exit(1)

    pc_type = sys.argv[1].lower()
    models_to_use = MODELS[pc_type]

    # Read prompt
    if not PROMPT_FILE.exists():
        print("Error: llm_prompt.txt file not found.")
        sys.exit(1)

    with PROMPT_FILE.open("r", encoding="utf-8") as f:
        prompt_text = f.read()

    # Create output folder if it does not exist
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for model in models_to_use:
        print(f"→ Generating with {model} on {'Laptop' if pc_type == 'l' else 'Desktop'}...")

        payload = {
            "model": model,
            "prompt": prompt_text,
            "stream": False
        }

        try:
            response = requests.post(OLLAMA_URL, json=payload)
            response.raise_for_status()
            result = response.json().get("response", "")

            filename = f"{OUTPUT_DIR}/ollama_{model.replace(':', '_')}_{pc_type}.txt"
            with open(filename, "w", encoding="utf-8") as out_file:
                out_file.write(result)

            print(f"Result saved in {filename}")

        except requests.exceptions.RequestException as e:
            print(f"Error with model {model}: {e}")

if __name__ == "__main__":
    main()
