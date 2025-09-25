#!/usr/bin/env python3
import os
import re
import sys
import requests
from pathlib import Path
from typing import Dict, List

# Config
FILES = ["apt", "whoami", "gedit"]
DECOMPILERS: Dict[str, str] = {
    "angr": "angr-9.2.169",
    "binary-ninja": "binary-ninja-5.1.8005",
    "boomerang": "boomerang-0.5.2",
    "dewolf": "dewolf-2025-01-01",
    "ghidra": "ghidra-11.3.1",
    "hex-rays": "hex-rays-9.2.0.250908",
    "recstudio": "recstudio-4.1",
    "reko": "reko-0.11.6.0",
    "relyze": "relyze-4.0.0",
    "retdec": "retdec-5.0",
    "snowman": "snowman-0.1.2-21",
}

ACTIVE_DECOMPILERS: List[str] = ["ghidra", "binary-ninja", "hex-rays"]

MODELS = {
    "d": [  # Desktop
        # "llama3.2:3b",
        "gpt-oss:20b",
        "deepseek-r1:14b",
        "gemma3:12b"
    ],
    "l": [  # Laptop
        "llama3.2:3b"
    ]
}

OLLAMA_HOST = "localhost"
OLLAMA_URL = f"http://{OLLAMA_HOST}:11434/api/generate"

INPUT_DIR = Path("./dogbolt/src")
OUTPUT_DIR = Path("./prompt/res")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def remove_comments(code: str) -> str:
    """Removes comments // and /* */ from the code"""
    # Remove /* ... */ multiline
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    # Remove // until end of line
    code = re.sub(r"//.*", "", code)
    return code


def strip_small_functions(code: str, min_lines: int = 5) -> str:
    """Removes functions with fewer than min_lines from the decompiled code"""
    result = []
    i = 0
    while i < len(code):
        match = re.search(
            r"([a-zA-Z_][\w\s\*]+?\([^)]*\))\s*\{", code[i:], re.M)
        if not match:
            result.append(code[i:])
            break
        start = i + match.start()
        header = match.group(1).strip()

        # cerca fine funzione con bilanciamento delle graffe
        depth, end = 0, start
        for j, ch in enumerate(code[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        func_body = code[start:end+1]

        # conta solo righe di codice non vuote e non solo graffe
        lines = [
            l for l in func_body.strip().splitlines()
            if l.strip() and l.strip() not in ("{", "}")
        ]
        if len(lines) >= min_lines:
            result.append(func_body)

        i = end + 1
    return "\n\n".join(result)


def build_prompt(file: str, file_map: Dict[str, str]) -> str:
    """Creates a prompt with the entire file cleaned of short functions"""
    sections = [
        "You are an expert in reverse engineering and C/C++ code analysis.\n"
        "You will be given multiple decompilation outputs of the same program, "
        "each produced by a different decompiler.\n\n"
        "Your task is to choose the best decompiler based only on the structural readability of the code "
        "(control flow clarity, function organization, expression predictability, "
        "structural economy).\n\n"
        "ANSWER WITH ONLY THE NUMBER OF THE DECOMPILER.\n\n"
    ]
    for idx, dec in enumerate(ACTIVE_DECOMPILERS, start=1):
        sections.append(
            f"---\nDecompiler N. {idx}: {dec}\nCode:\n```\n{file_map.get(dec, '')}\n```"
        )
    return "\n".join(sections)


def run_llm(models: List[str], prompt: str, file: str) -> Dict[str, str]:
    """Sends the prompt to all models and returns their responses"""
    responses = {}
    for model in models:
        try:
            print(f"Querying model {model} for file {file}...")
            response = requests.post(
                OLLAMA_URL,
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=300,
            )
            response.raise_for_status()
            result = response.json().get("response", "").strip()
            print(f"Model {model} response for {file}: {result}")
            responses[model] = result if result in {"1", "2", "3"} else "0"
        except Exception as e:
            print(f"[ERROR] {model}: {e}")
            responses[model] = "0"
    return responses


def main():
    if len(sys.argv) < 2 or sys.argv[1].lower() not in MODELS:
        print("Usage: python3 script.py [d|l]")
        sys.exit(1)

    pc_type = sys.argv[1].lower()
    models_to_use = MODELS[pc_type]

    # Results dictionary {file: choice}
    results = {f: {} for f in FILES}

    for f in FILES:
        file_map: Dict[str, str] = {}
        for dec in ACTIVE_DECOMPILERS:
            path = INPUT_DIR / f"{DECOMPILERS[dec]}" / f"{f}.decompiled.c"
            if not path.exists():
                print(f"[WARN] Missing {path}")
                continue
            code = path.read_text(encoding="utf-8", errors="replace")
            code = remove_comments(code)
            cleaned = strip_small_functions(code, min_lines=5)
            file_map[dec] = cleaned

        if not file_map:
            continue

        prompt = build_prompt(f, file_map)
        model_responses = run_llm(models_to_use, prompt, f)
        results[f] = model_responses

    # --- Markdown table ---
    header = ["model_llm"] + FILES
    sep = ["---"] * len(header)

    print("\n=== FINAL TABLE (Markdown) ===\n")
    print("| " + " | ".join(header) + " |")
    print("| " + " | ".join(sep) + " |")

    table_lines = []
    table_lines.append("| " + " | ".join(header) + " |")
    table_lines.append("| " + " | ".join(sep) + " |")

    for model in models_to_use:
        row = [model]
        for f in FILES:
            choice = results.get(f, {}).get(model, "0")
            if choice in {"1", "2", "3"}:
                row.append(ACTIVE_DECOMPILERS[int(choice)-1])
            else:
                row.append("")
        line = "| " + " | ".join(row) + " |"
        print(line)
        table_lines.append(line)

    out_file = OUTPUT_DIR / "final_table.md"
    out_file.write_text("\n".join(table_lines), encoding="utf-8")


if __name__ == "__main__":
    main()
