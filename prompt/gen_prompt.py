#!/usr/bin/env python3

import os
from pathlib import Path
from typing import Dict, List


DECOMPILERS: Dict[str, str] = {
    "angr": "angr-9.2.169",
    "binary-ninja": "binary-ninja-5.1.8005",
    "boomerang": "boomerang-0.5.2",
    "dewolf": "dewolf-2025-01-01",
    "ghidra": "ghidra-11.3.1",
    "hex-rays": "hex-rays-9.1.0.250226",
    "recstudio": "recstudio-4.1",
    "reko": "reko-0.11.6.0",
    "relyze": "relyze-4.0.0",
    "retdec": "retdec-5.0",
    "snowman": "snowman-0.1.2-21",
}


ACTIVE_DECOMPILERS: List[str] = [
    "binary-ninja",
    "ghidra",
]


INPUT_DIR = Path("./dogbolt/src")
OUTPUT_DIR = Path("./prompt")


def read_decompiled_files(decompiler_list: List[str]) -> Dict[str, str]:
    results = {}
    for name in decompiler_list:
        dir_path = INPUT_DIR / DECOMPILERS[name]
        if not dir_path.exists():
            print(f"[WARN] No directory found: {dir_path}")
            continue

        found_file = None
        candidate = dir_path / "decompiled.c"
        if candidate.exists():
            found_file = candidate


        if not found_file:
            print(f"[WARN] No decompiled file found for {name}")
            continue

        try:
            content = found_file.read_text(encoding="utf-8", errors="replace")
            results[name] = content.strip()
        except Exception as e:
            print(f"[ERROR] in {found_file}: {e}")

    return results


def build_llm_prompt(decompiled_map: Dict[str, str]) -> str:
    sections = [
        "You are an expert in reverse engineering and C/C++ code analysis.\n"
        "I will provide you with the decompilation results of the same binary "
        "performed using different decompilers.\n"
        "Your tasks are:\n"
        "1. Rank the outputs from the most 'human-readable' to the least, explaining your choices.\n"
        "2. Explain which style, naming, and structural factors influenced the ranking.\n"
        "3. Estimate the complexity of each output.\n"
        "4. Estimate the perplexity (measure of predictability) for each output.\n"
        "5. Provide a comparative analysis.\n"
    ]
    for idx, (name, content) in enumerate(decompiled_map.items(), start=1):
        sections.append(f"---\nDecompiler N. {idx}: {name}\nCode:\n```\n{content}\n```")

    sections.append(
        "---\n"
        "Provide the answer in an ordered format with:\n"
        "- Final ranking (from best to worst)\n"
        "- Motivations\n"
        "- Complexity of each code\n"
        "- Perplexity of each code\n"
    )
    return "\n".join(sections)


if __name__ == "__main__":
    decompiled_map = read_decompiled_files(ACTIVE_DECOMPILERS)
    if not decompiled_map:
        print("[ERROR] No decompiled files read. Check the configuration.")
        exit(1)

    prompt = build_llm_prompt(decompiled_map)
    output_file = OUTPUT_DIR / "llm_prompt.txt"
    output_file.write_text(prompt, encoding="utf-8")

    print(f"[INFO] Prompt LLM generated in: {output_file}")
