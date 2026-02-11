
import json
import os
import itertools
import random
from utils.llm import get_llm_analysis, free_llm_model, get_code_metrics
from utils.com import get_ast, get_func_name, get_source_code, get_models
from utils.const import OUTPUT_DIR


SRC_PATH = os.path.abspath('src')


class binary_item:

    source_func: str
    binary_name: str
    funcs: dict

    def __init__(self, binary_name):
        self.source_func = get_source_code(binary_name)
        self.binary_name = binary_name
        self.funcs = {}

    def set_func(self, code, decompiler_name):
        self.name = get_func_name(self.binary_name)
        search_str = f"{self.name}("

        start_idx = -1
        brace_idx = -1
        search_pos = 0
        while True:
            start_idx = code.find(search_str, search_pos)
            if start_idx == -1:
                raise ValueError(
                    f"Function definition for '{self.name}' not found")

            curr_idx = start_idx + len(self.name)
            paren_count = 0
            args_closed = False

            while curr_idx < len(code):
                if code[curr_idx] == '(':
                    paren_count += 1
                elif code[curr_idx] == ')':
                    paren_count -= 1
                    if paren_count == 0:
                        args_closed = True
                        curr_idx += 1
                        break
                curr_idx += 1

            if not args_closed:
                raise ValueError("Unmatched parentheses in function arguments")
            while curr_idx < len(code) and code[curr_idx].isspace():
                curr_idx += 1

            if curr_idx < len(code) and code[curr_idx] == '{':
                brace_idx = curr_idx
                break
            else:
                search_pos = curr_idx
        brace_count = 1
        end_idx = brace_idx + 1
        while end_idx < len(code) and brace_count > 0:
            if code[end_idx] == "{":
                brace_count += 1
            elif code[end_idx] == "}":
                brace_count -= 1
            end_idx += 1

        if brace_count != 0:
            raise ValueError("Unmatched braces in function code")

        # print(f"[INFO] Extracted function {self.name} from decompiler {decompiler_name}")
        # print(f"[DEBUG] Function code:\n{code[start_idx:end_idx]}")
        self.funcs[decompiler_name] = code[start_idx:end_idx]

    def get_ast(self, decompiler_name):
        func = self.funcs.get(decompiler_name, "")
        if func == "":
            raise ValueError(
                f"Function not set for decompiler {decompiler_name}")
        return get_ast(func)

    def get_func_name(self):
        return self.name

    def get_binary_name(self):
        return self.binary_name

    def get_source_ast(self):
        return get_ast(self.source_func)

    def get_source_func(self):
        return self.source_func

    def get_func_decomp(self, decompiler_name):
        return self.funcs[decompiler_name]

    def get_decompilers(self):
        return list(self.funcs.keys())


def run_judge_with_bias_check(content_base, content_pr, model_id, source_content=None, is_ast=False):
    analysis = get_llm_analysis(
        content_base, content_pr, model_id=model_id, source=source_content, is_ast=is_ast
    )
    winner = analysis.get("winner", "Error")
    if winner in ("TIE", "Error"):
        return analysis

    print("checking bias...")

    analysis_swap = get_llm_analysis(
        content_pr, content_base, model_id=model_id, source=source_content, is_ast=is_ast
    )
    winner_swap = analysis_swap.get("winner", "Error")

    if winner_swap not in ("A", "B"):
        return {
            "winner": "TIE",
            "motivation": "Could not detect potential bias in LLM response (Position Bias); declaring TIE."
        }

    if winner != winner_swap:
        return analysis
    else:
        return {
            "winner": "TIE",
            "motivation": "Detected potential bias in LLM response (Position Bias); declaring TIE."
        }


def main():
    output_file = os.path.join(OUTPUT_DIR, "dogbolt_report.json")
    results = {model_id: [] for model_id in MODELS_TO_BENCHMARK}

    #  { filename_task: { decompiler_name: full_path } }
    tasks_map = {}
    num_decompilers = 0
    for d_dir in os.listdir(SRC_PATH):
        d_path = os.path.join(SRC_PATH, d_dir)
        if not os.path.isdir(d_path):
            continue

        num_decompilers += 1

        for fname in os.listdir(d_path):
            if not fname.endswith(".c"):
                continue

            if fname not in tasks_map:
                tasks_map[fname] = {}

            tasks_map[fname][d_dir] = os.path.join(d_path, fname)

    valid_tasks = [t for t, decomps in tasks_map.items() if len(
        decomps) >= num_decompilers]

    print(
        f"Found {len(tasks_map)} tasks. Processing {len(valid_tasks)} common tasks...")
    items_binary = []
    for task_filename in valid_tasks:

        binary_name = task_filename.replace(".c", "")

        try:
            items_binary.append(binary_item(binary_name))
            for d_key, d_path in tasks_map[task_filename].items():
                with open(d_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                decomp_name_parts = d_key.split('-')[:-1]
                decomp_name = "-".join(decomp_name_parts)
                # print(f"Setting function for binary {binary_name} decompiler {decomp_name}...")
                items_binary[-1].set_func(code, decomp_name)
        except Exception as e:
            print(f"Error for {binary_name}: {e}")
            continue

    SAMPLE_SIZE = 25

    if len(items_binary) > SAMPLE_SIZE:
        print(
            f"Sampling {SAMPLE_SIZE} items from {len(items_binary)} total...")
        random.seed(0)
        items_binary = random.sample(items_binary, SAMPLE_SIZE)

    print(
        f"Starting pairwise comparison for {len(items_binary)} valid items...")
    decompilers = items_binary[0].get_decompilers()
    pairs = list(itertools.combinations(decompilers, 2))
    print(f"Comparing {len(pairs)} decompiler pairs: {pairs}")
    for model in MODELS_TO_BENCHMARK:
        print(f"Benchmarking model: {model}...")
        if os.path.exists(os.path.join(OUTPUT_DIR, "_"+model+".json")):
            print(
                f"Output for model {model} already exists. Skipping benchmarking.")
            res = json.load(
                open(os.path.join(OUTPUT_DIR, "_"+model+".json"), "r"))
            results[model] = res
            continue
        for item in items_binary:
            print(f"Processing binary: {item.get_binary_name()}...")
            try:
                source_ast = item.get_source_ast()
                if not source_ast:
                    raise ValueError("Source AST is empty")
            except Exception as e:
                print(f"Error getting source AST ({e})")
                return

            for d1, d2 in pairs:
                try:
                    ast_1 = item.get_ast(d1)
                    ast_2 = item.get_ast(d2)

                    if not ast_1 or not ast_2:
                        raise ValueError("One of the ASTs is empty")

                    # print("source code:", item.get_source_func())
                    # print("decompiler A code:", item.get_func_decomp(d1))
                    # print("decompiler B code:", item.get_func_decomp(d2))

                    perp_source = get_code_metrics(
                        item.get_source_func(), model_id=model)['perplexity']
                    perp_1 = get_code_metrics(
                        item.get_func_decomp(d1), model_id=model)['perplexity']
                    perp_2 = get_code_metrics(
                        item.get_func_decomp(d2), model_id=model)['perplexity']

                    perp_ast_source = get_code_metrics(
                        source_ast, model_id=model)['perplexity']
                    perp_ast_1 = get_code_metrics(
                        ast_1, model_id=model)['perplexity']
                    perp_ast_2 = get_code_metrics(
                        ast_2, model_id=model)['perplexity']

                    print(
                        f"Perplexities - Source: {perp_source}, {d1}: {perp_1}, {d2}: {perp_2}")

                    print(
                        f"Getting AST analysis with source context for {item.get_func_name()}...")
                    analysis_ast_s = run_judge_with_bias_check(
                        content_base=ast_1,
                        content_pr=ast_2,
                        model_id=model,
                        source_content=source_ast,
                        is_ast=True
                    )

                    print(
                        f"Getting Quality analysis with source context for {item.get_func_name()}...")
                    analysis_s = run_judge_with_bias_check(
                        content_base=item.get_func_decomp(d1),
                        content_pr=item.get_func_decomp(d2),
                        model_id=model,
                        source_content=item.get_source_func(),
                        is_ast=False
                    )

                    print(
                        f"Getting Blind AST analysis for {item.get_func_name()}...")
                    analysis_ast = run_judge_with_bias_check(
                        content_base=ast_1,
                        content_pr=ast_2,
                        model_id=model,
                        source_content=None,
                        is_ast=True
                    )

                    print(
                        f"Getting Blind Quality analysis for {item.get_func_name()}...")
                    analysis = run_judge_with_bias_check(
                        content_base=item.get_func_decomp(d1),
                        content_pr=item.get_func_decomp(d2),
                        model_id=model,
                        source_content=None,
                        is_ast=False
                    )

                    entry = {
                        "binary": item.get_binary_name(),
                        "function": item.get_func_name(),
                        "decompiler_A": d1,
                        "decompiler_B": d2,
                        "winner_s": analysis_s.get("winner", "Error"),
                        "motivation_s": analysis_s.get("motivation", ""),
                        "winner": analysis.get("winner", "Error"),
                        "motivation": analysis.get("motivation", ""),
                        "winner_ast": analysis_ast.get("winner", "Error"),
                        "motivation_ast": analysis_ast.get("motivation", ""),
                        "winner_ast_s": analysis_ast_s.get("winner", "Error"),
                        "motivation_ast_s": analysis_ast_s.get("motivation", ""),
                        "code_A": item.get_func_decomp(d1),
                        "code_B": item.get_func_decomp(d2),
                        "source_code": item.get_source_func(),
                        "ast_A": ast_1,
                        "ast_B": ast_2,
                        "ast_Source": source_ast,
                        "perplexity_source": perp_source,
                        "perplexity_A": perp_1,
                        "perplexity_B": perp_2,
                        "perplexity_ast_source": perp_ast_source,
                        "perplexity_ast_A": perp_ast_1,
                        "perplexity_ast_B": perp_ast_2,
                    }

                    results[model].append(entry)
                    print(
                        f"[{item.get_binary_name()}] {d1} vs {d2} -> Winner AST: {entry['winner_ast']}")
                    print(
                        f"[{item.get_binary_name()}] {d1} vs {d2} -> Winner Code: {entry['winner']}")

                except Exception as e:
                    print(
                        f"Error comparing {d1} vs {d2} on {item.get_binary_name()}: {e}")
        print(f"Completed benchmarking for model: {model}.")
        with open(os.path.join(OUTPUT_DIR, "_"+model+".json"), "w", encoding='utf-8') as f:
            json.dump(results[model], f, indent=2)
    print(f"Saving {len(results)} comparisons to {output_file}...")
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    free_llm_model()


if __name__ == "__main__":
    MODELS_TO_BENCHMARK = get_models()
    main()
