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
    "hex-rays": "hex-rays-9.2.0.250908",
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
        "You will be given multiple decompilation outputs of the same binary, "
        "each produced by a different decompiler.\n\n"
        "Your task is to evaluate **only the structural readability of the code**, "
        "not variable naming or stylistic details.\n"
        "For consistency, apply the following evaluation criteria:\n"
        "1. **Control Flow Clarity** : Are conditionals (if, switch, loops) expressed "
        "in a form close to standard C, or are they obfuscated with labels and gotos?\n"
        "   - Example (clear): `switch(x) { case 1: ... }`\n"
        "   - Example (unclear): `goto label_4014ba;`\n"
        "2. **Function Organization** : Are functions structured with clear entry/exit "
        "points, or fragmented into inline tailcalls and redundant wrappers?\n"
        "3. **Expression Predictability** : Are operations expressed as standard C "
        "expressions (`a + b`, `a / b`), or through low-level macros/register artifacts?\n"
        "   - Example (clear): `result = memory + func_name;`\n"
        "   - Example (unclear): `rax_6 = FCMP_O(x87_r6_2, askdo_input_3);`\n"
        "4. **Structural Economy** : Does the code minimize unnecessary temporaries "
        "and boilerplate, or is it bloated with intermediate variables from register spills?\n"
        "   - Example (efficient): `double d = sin(x);`\n"
        "   - Example (bloated): `var_50 = func_name / 57.2957; var_50 = sin(var_50);`\n\n"
        "For each decompiler output, you must:\n"
        "1. Rank all outputs from most human-readable to least.\n"
        "2. Explain which structural factors influenced your ranking.\n"
        "3. Estimate the **perplexity** (1–10, lower = more predictable control flow).\n"
        "4. Provide a comparative analysis, explicitly contrasting the structural differences.\n\n"
        "Remember: **do not evaluate variable naming, comments, or cosmetic style. "
        "Focus only on structural readability.**\n"
    ]
    for idx, (name, content) in enumerate(decompiled_map.items(), start=1):
        sections.append(f"---\nDecompiler N. {idx}: {name}\nCode:\n```\n{content}\n```")

    sections.append(
        "---\n"
        "Provide the answer in this ordered format:\n"
        "- Final ranking (best to worst)\n"
        "- Motivations\n"
        "- Perplexity of each code\n"
        "- Comparative analysis\n"
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
