#!/usr/bin/env python3
import os
import re
import sys
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Set

# Config
FILES = ["cat", "chmod", "sleep"]
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
    "d": ["gpt-oss:20b", "deepseek-r1:14b", "gemma3:12b"],
    "l": ["llama3.2:3b"]
}

OLLAMA_HOST = "localhost"
OLLAMA_URL = f"http://{OLLAMA_HOST}:11434/api/generate"

INPUT_DIR = Path("./dogbolt/src")
OUTPUT_DIR = Path("./prompt/res")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def remove_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r"//.*", "", code)
    return code

def extract_functions(code: str) -> Dict[str, str]:
    """
    Extract complete functions from decompiled code, returning a dict
    {function_name: full_code_block}.
    This does not try to filter by length here.
    """
    funcs: Dict[str, str] = {}
    # Rudimentary pattern: "type name(args) { … }"
    # This can fail on complex cases, but it's a starting point.
    pattern = re.compile(r"([a-zA-Z_][\w]*)\s*\([^)]*\)\s*(?:__[a-zA-Z_]\w*\s*)*\{", re.M)
    for m in pattern.finditer(code):
        name = m.group(1)
        start = m.start()
        # Find the opening brace position
        brace_pos = code.find("{", m.end() - 1)
        if brace_pos < 0:
            continue
        depth = 0
        end = brace_pos
        for i, ch in enumerate(code[brace_pos:], start=brace_pos):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        func_body = code[start:end + 1]
        funcs[name] = func_body
    return funcs


def intersect_function_names(mappings: List[Dict[str, str]]) -> Set[str]:
    """
    Given dicts of functions for each decompiler, return the intersection
    of function names that appear in all of them.
    """
    name_sets = [set(m.keys()) for m in mappings]
    if not name_sets:
        return set()
    common = name_sets[0].intersection(*name_sets[1:])
    return common


def build_prompt_for_function(func_name: str, func_map: Dict[str, str]) -> str:
    """Build the prompt for a single function, comparing decompilation outputs."""
    lines = [
        "You are an expert in reverse engineering and C/C++ code analysis.",
        "You will be given multiple decompilation outputs of the **same function** from different decompilers.",
        "Your task is to choose the best decompiler for that function, based on clarity of control flow, structure, and expression readability.",
        "Answer with ONLY the number of the decompiler (1, 2, or 3).",
        "",
    ]
    for idx, dec in enumerate(ACTIVE_DECOMPILERS, start=1):
        code = func_map.get(dec, "")
        lines.append(f"---\nDecompiler N. {idx}: {dec}\nCode:\n```\n{code}\n```")
    return "\n".join(lines)


def estimate_perplexity(prompt: str) -> float:
    """
    TODO: Implement a real perplexity estimation. For now, return a dummy value based on length.
    """
    n = len(prompt.split())
    if n == 0:
        return float("inf")
    # Use a fake formula: perplexity = exp(log n)
    import math
    return math.exp(math.log(n))


def run_llm(models: List[str], prompt: str) -> Dict[str, Tuple[str, float]]:
    """
    Send the prompt to each model, return dict {model: (response, perplexity)}.
    """
    out: Dict[str, Tuple[str, float]] = {}
    for model in models:
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=300,
            )
            resp.raise_for_status()
            result = resp.json().get("response", "").strip()
            # TODO PERPLEXITY
            perp = estimate_perplexity(prompt)
            if result not in {"1", "2", "3"}:
                result = "0"
            out[model] = (result, perp)
        except Exception as e:
            print(f"[ERROR] model {model}: {e}", file=sys.stderr)
            out[model] = ("0", float("inf"))
    return out


def main():
    if len(sys.argv) < 2 or sys.argv[1].lower() not in MODELS:
        print("Usage: python3 script.py [d|l]")
        sys.exit(1)
    pc_type = sys.argv[1].lower()
    models_to_use = MODELS[pc_type]

    # Read decompiled outputs for each file and each decompiler
    decomp_maps: Dict[str, Dict[str, Dict[str, str]]] = {}
    # structure: decomp_maps[file][decompiler] = code (cleaned)
    for opt in range(1, 4):
        for f in FILES:
            decomp_maps[f"{f}_O{opt}"] = {}
            for dec in ACTIVE_DECOMPILERS:
                path = INPUT_DIR / f"{DECOMPILERS[dec]}" / f"{f}_O{opt}.decompiled.c"
                if not path.exists():
                    print(f"[WARN] Missing {path}")
                    continue
                code = path.read_text(encoding="utf-8", errors="replace")
                code = remove_comments(code)
                decomp_maps[f"{f}_O{opt}"][dec] = code

    # For each file, extract functions for each decompiler
    func_maps_per_file: Dict[str, Dict[str, Dict[str, str]]] = {}
    # structure: func_maps_per_file[file][decompiler][func_name] = function code
    for opt in range(1, 4):
        for f in FILES:
            func_maps_per_file[f"{f}_O{opt}"] = {}
            for dec, code in decomp_maps[f"{f}_O{opt}"].items():
                func_maps_per_file[f"{f}_O{opt}"][dec] = extract_functions(code)

    # Now for each file, determine the set of functions common to all decompilers
    common_funcs_per_file: Dict[str, Set[str]] = {}
    for opt in range(1, 4):
        for f in FILES:
            full_f = f"{f}_O{opt}"
            maps = list(func_maps_per_file[full_f].values())
            common = intersect_function_names(maps)
            common_funcs_per_file[full_f] = common
            print(f"[INFO] File {full_f}: functions common across decompilers: {common}")

    # Send an LLM request for each common function in each file
    # --- COLLECT RESULTS INTO TABLES BY OPT LEVEL ---
    results_by_opt = {1: {}, 2: {}, 3: {}}  # {opt: {model: {file_func: "decompiler - perplexity"}}}

    for opt in range(1, 4):
        for f in FILES:
            for func in common_funcs_per_file.get(f"{f}_O{opt}", ()):
                func_map = {dec: func_maps_per_file[f"{f}_O{opt}"][dec].get(func, "") for dec in ACTIVE_DECOMPILERS}
                prompt = build_prompt_for_function(func, func_map)
                responses = run_llm(models_to_use, prompt)
                print(f"[INFO] Responses for {f}_O{opt}::{func}: {responses}")

                # store results in memory
                file_func = f"{f}_{func}"
                for model, (choice, perp) in responses.items():
                    results_by_opt[opt].setdefault(model, {})
                    if choice in {"1", "2", "3"}:
                        dec = ACTIVE_DECOMPILERS[int(choice) - 1]
                        cell = f"{dec} - {perp:.1f}"
                    else:
                        cell = "X"
                    results_by_opt[opt][model][file_func] = cell

    # --- WRITE MARKDOWN TABLES ---
    for opt in range(1, 4):
        opt_results = results_by_opt[opt]
        if not opt_results:
            continue

        all_file_funcs = sorted({
            ff
            for model_data in opt_results.values()
            for ff in model_data.keys()
        })

        out_fn = OUTPUT_DIR / f"final_table_O{opt}.md"
        with open(out_fn, "w", encoding="utf-8") as fo:
            fo.write(f"# Results - Optimization O{opt}\n\n")
            header = ["model_llm"] + all_file_funcs
            fo.write("| " + " | ".join(header) + " |\n")
            fo.write("| " + " | ".join(["---"] * len(header)) + " |\n")

            for model in models_to_use:
                row = [model]
                for ff in all_file_funcs:
                    val = opt_results.get(model, {}).get(ff, "X")
                    row.append(val)
                fo.write("| " + " | ".join(row) + " |\n")

        print(f"[INFO] Saved table for O{opt} -> {out_fn}")

if __name__ == "__main__":
    main()
