
import json
import os
import re

import requests
import itertools
import tree_sitter_c
from tree_sitter import Language, Parser
import datasets


DATASET_PATH = os.path.abspath('Dataset/compiled_ds')
LLM_API_URL = os.environ.get("LLM_API_URL", "http://localhost:8900")
OUTPUT_DIR = os.path.abspath('outputs')
MODELS_TO_BENCHMARK = []
DATASET_CACHE = {}

def get_models():
    """
    Returns the list of models to benchmark from the LLM server.
    """
    try:
        resp = requests.get(f"{LLM_API_URL}/models", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("available_models", [])
            print(f"[INFO] Models available for benchmarking: {models}")
            return models
        else:
            print(
                f"[WARN] Could not fetch models from LLM server: {resp.status_code}")
            return []
    except Exception as e:
        print(f"[ERR] Failed to get models: {e}")
        return []

def get_ast(code):
    C_LANGUAGE = Language(tree_sitter_c.language())
    parser = Parser(C_LANGUAGE)

    tree = parser.parse(code.encode('utf8'))
    structure = []

    def traverse(node):
        # Block
        if node.type == 'compound_statement':
            structure.append("{")
            for child in node.children:
                traverse(child)
            structure.append("}")
            return

        # If-Else
        if node.type == 'if_statement':
            structure.append("if()")
            for child in node.children_by_field_name('consequence'):
                traverse(child)

            else_node = node.child_by_field_name('alternative')
            if else_node:
                structure.append("else")
                traverse(else_node)
            return

        # loops
        if node.type == 'while_statement':
            structure.append("while()")
            for child in node.children_by_field_name('body'):
                traverse(child)
            return

        if node.type == 'for_statement':
            structure.append("for()")
            for child in node.children_by_field_name('body'):
                traverse(child)
            return

        if node.type == 'do_statement':
            structure.append("do_while()")
            for child in node.children_by_field_name('body'):
                traverse(child)
            return

        # switch-case
        if node.type == 'switch_statement':
            structure.append("switch(){")
            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    traverse(child)
            structure.append("}")
            return

        if node.type == 'case_statement':
            structure.append("case:")
            for child in node.children:
                if child.type not in ['case', ':'] and child.type != 'number_literal':
                    traverse(child)
            return

        if node.type == 'goto_statement':
            structure.append("goto")
            return

        # if node.type == 'labeled_statement':
        #     structure.append("label:")         # also std::_Lockit:: so for now ignore

        # call
        if node.type == 'call_expression':
            structure.append("call(")
            args = node.child_by_field_name('arguments')
            if args:
                # capture any nested calls or logic
                for child in args.children:
                    if child.type not in ['(', ')', ',']:  # cleanup
                        traverse(child)
            structure.append(")")
            return

        # Ternary
        if node.type == 'conditional_expression':
            structure.append("(?")
            traverse(node.child_by_field_name('condition'))
            structure.append(":")
            traverse(node.child_by_field_name('consequence'))
            structure.append(":")
            traverse(node.child_by_field_name('alternative'))
            structure.append(")")
            return

        # Fallback
        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    return "".join(structure)


def get_llm_analysis(base_code, pr_code, model_id, source=None):
    """Call the LLM to get analysis"""

    prompt = get_ast_prompt(base_code, pr_code, source)

    try:
        resp = requests.post(LLM_API_URL+"/generate", json={
                             "prompt": prompt, "model_id": model_id})

        if resp.status_code == 200:
            result = resp.json()

            generated_text = result.get("response", "")
            try:
                match = re.search(
                    r'\{\s*"(?:winner|motivation)"\s*:.*\}', generated_text, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
                return {"winner": "Unknown", "motivation": generated_text}
            except:
                return {"winner": "Error", "motivation": generated_text}
        else:
            return {"error": f"API Error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def load_dataset(path=DATASET_PATH):
    if not DATASET_CACHE:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Dataset not found at {path}")

        ds = datasets.load_from_disk(path)
        for row in ds:
            path_str = row.get('path', '')
            key = os.path.basename(path_str)
            DATASET_CACHE[key] = row
    return DATASET_CACHE

def get_func_name(bin):
    try:
        ds = load_dataset()
    except Exception as e:
        raise RuntimeError(f"Error loading dataset: {e}")

    for _, row in enumerate(ds):
        if bin in row.get('path'):
            return row.get('file')
    raise ValueError(f"Function name for binary '{bin}' not found in dataset.")

def get_source_code(bin):

    try:
        ds = load_dataset()
    except Exception as e:
        raise RuntimeError(f"Error loading dataset: {e}")

    for _, row in enumerate(ds):
        if bin in row.get('path'):
            return row.get('func')
    raise ValueError(f"Source code for binary '{bin}' not found in dataset.")

####################################

def get_ast_prompt(base_ast, pr_ast, source_ast):
    return (
        "You are an expert compiler engineer and static analysis specialist.\n"
        "Your task is to evaluate which of two decompiled Control Flow AST skeletons "
        "better preserves the structural intent of the original Source Code.\n\n"

        "### CONTEXT\n"
        "You will be provided with three AST skeletons representing the control flow of a C function.\n"
        "These skeletons contain ONLY control structures (if, while, switch, goto, etc.) "
        "and function calls, stripped of variables and expressions.\n"
        "1. **SOURCE (Ground Truth)**: The original, human-written structure.\n"
        "2. **A (Decompiler A)**: decompiler A output.\n"
        "3. **B (Decompiler B)**: decompiler B output.\n\n"

        "### EVALUATION CRITERIA\n"
        "Compare A and B against the SOURCE. Choose the winner based on:\n"
        "1. **Loop Recovery**: Does it correctly identify `for/while` loops instead of `if + goto`?\n"
        "2. **Nesting Depth**: Does it respect the original nesting level without excessive flattening or unnecessary nesting?\n"
        "3. **Branching Logic**: Does it maintain `if-else` chains similar to the source, or does it fragment them?\n"
        "4. **Ghost Instructions**: Penalize the presence of phantom `label:` and `goto` that do not exist in the SOURCE.\n\n"

        "### DATA\n"
        f"--- SOURCE AST (Target) ---\n{source_ast}\n\n"
        f"--- A AST ---\n{base_ast}\n\n"
        f"--- B AST ---\n{pr_ast}\n\n"

        "### OUTPUT FORMAT\n"
        "Analyze the structures step-by-step internally, then output your final decision ONLY in valid JSON format:\n"
        "{\n"
        '  "winner": "A" | "B" | "TIE"\n'
        '  "motivation": "Brief comparison of why you chose the winner.",\n'
        "}"
    )

SRC_PATH = os.path.abspath('src')

class binary_item:
    source_func = ""
    funcs = {}
    binary_name = ""
    def __init__(self, binary_name):
        self.source_func = get_source_code(binary_name)
        self.binary_name = binary_name

    def set_func(self, code, decompiler_name):
        name = get_func_name(self.binary_name)
        start_str = f"{name}("
        start_idx = code.find(start_str)
        if start_idx == -1:
            raise ValueError("Function start not found")
        # find the opening brace {
        brace_idx = code.find("{", start_idx)
        if brace_idx == -1:
            raise ValueError("Function opening brace not found")
        # find the matching closing brace }
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
        self.funcs[decompiler_name] = code[start_idx:end_idx]

    def get_ast(self, decompiler_name):
        func = self.funcs.get(decompiler_name, "")
        if func == "":
            raise ValueError(f"Function not set for decompiler {decompiler_name}")
        return get_ast(func)
    
    def get_source_ast(self):
        return get_ast(self.source_func)
    
    def get_func_decomp(self, decompiler_name):
        return self.funcs[decompiler_name]
    
    def get_decompilers(self):
        return list(self.funcs.keys())

def main():
    output_file = os.path.join(OUTPUT_DIR, "dogbolt_report.json")
    results = {model_id: [] for model_id in MODELS_TO_BENCHMARK}

    try:
        load_dataset(DATASET_PATH)
    except Exception as e:
        print(f"Critical Error: {e}")
        return

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

    
    valid_tasks = [t for t, decomps in tasks_map.items() if len(decomps) >= num_decompilers]
    
    print(f"Found {len(tasks_map)} tasks. Processing {len(valid_tasks)} common tasks...")
    items_binary = []
    for task_filename in valid_tasks:
        
        binary_name = task_filename.replace(".c", "")
            
        try:
            items_binary.append(binary_item(binary_name))
            for d_key, d_path in tasks_map[task_filename].items():
                with open(d_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                decomp_name = d_key.split('-')[:-1]
                items_binary[-1].set_func(code, decomp_name)
        except Exception as e:
            print(f"Error for {binary_name}: {e}")
            continue

    print(f"Starting pairwise comparison for {len(items_binary)} valid items...")

    decompilers = items_binary[0].get_decompilers()
    pairs = list(itertools.combinations(decompilers, 2))

    for model in MODELS_TO_BENCHMARK:
        for item in items_binary:
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

                    analysis = get_llm_analysis(
                        base_code=ast_1,
                        pr_code=ast_2,
                        model_id=model,
                        source=source_ast
                    )

                    for row in DATASET_CACHE.values():
                        if item.binary_name in row.get('path', ''):
                            func_name = row.get('file', 'unknown')
                            break
                   
                    entry = {
                        "binary": item.binary_name,
                        "function": func_name,
                        "decompiler_A": d1,
                        "decompiler_B": d2,
                        "winner": analysis.get("winner", "Error"),
                        "motivation": analysis.get("motivation", ""),
                        "ast_A": ast_1,
                        "ast_B": ast_2,
                        "ast_Source": source_ast
                    }
                    
                    results[model].append(entry)
                    print(f"[{item.binary_name}] {d1} vs {d2} -> Winner: {entry['winner']}")

                except Exception as e:
                    print(f"Error comparing {d1} vs {d2} on {item.binary_name}: {e}")

    print(f"Saving {len(results)} comparisons to {output_file}...")
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    MODELS_TO_BENCHMARK = get_models()
    main()