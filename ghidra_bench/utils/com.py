import subprocess
import sys
import requests
import lizard
import os
import datasets
import tree_sitter_c
from tree_sitter import Language, Parser
from .const import LLM_API_URL, DATASET_PATH


def run_command(cmd, cwd=None, env=None, input_text=None):
    verbose = 0
    # subprocess.check_call(cmd, shell=True, cwd=cwd, env=env)
    if verbose:
        print(f"[CMD] Executing: {cmd}")
    sys.stdout.flush()

    process = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        env=env,
        input=input_text,
        stdout=subprocess.PIPE,    # Capture stdout and stderr as text
        stderr=subprocess.STDOUT,  # Merge stderr into stdout
        text=True                  # Decode bytes to string
    )

    if verbose:
        if process.stdout:
            print(process.stdout)

    if process.returncode != 0:
        print(f"[FATAL] Command failed with return code {process.returncode}")
        if not verbose and process.stdout:
            print(process.stdout)
        raise subprocess.CalledProcessError(process.returncode, cmd)


def get_ast(code, indent_step=2):
    C_LANGUAGE = Language(tree_sitter_c.language())
    parser = Parser(C_LANGUAGE)
    tree = parser.parse(code.encode('utf8'))
    structure = []
    depth = 0
    def append_indent():
        if indent_step > 0:
            structure.append("\n" + " " * (depth * indent_step))
        else:
            structure.append(" ")

    def traverse(node):
        nonlocal depth

        # Block
        if node.type == 'compound_statement':
            structure.append("{")
            if indent_step > 0:
                depth += 1
            
            for child in node.children:
                if child.type in ['{', '}']: 
                    continue
                
                append_indent()
                traverse(child)

            if indent_step > 0:
                depth -= 1
                append_indent()
            else:
                structure.append(" ")
            
            structure.append("}")
            return
            
        if node.type == 'expression_statement':
            for child in node.children:
                traverse(child)
            # structure.append(";") 
            return
            
        if node.type == 'return_statement':
            structure.append("return")
            for child in node.children:
                if child.type != 'return':
                    #structure.append(" ")
                    traverse(child)
            return

        if node.type == 'if_statement':
            structure.append("if(")
            traverse(node.child_by_field_name('condition'))
            structure.append(")")
            
            traverse(node.child_by_field_name('consequence'))
            
            else_node = node.child_by_field_name('alternative')
            if else_node:
                structure.append("else")
                traverse(else_node)
            return

        if node.type == 'while_statement':
            structure.append("while(")
            traverse(node.child_by_field_name('condition'))
            structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'for_statement':
            structure.append("for(")
            for child in node.children_by_field_name('initializer'): traverse(child)
            structure.append(";")
            for child in node.children_by_field_name('condition'): traverse(child)
            structure.append(";")
            for child in node.children_by_field_name('update'): traverse(child)
            structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'do_statement':
            structure.append("do")
            traverse(node.child_by_field_name('body'))
            structure.append("while(")
            traverse(node.child_by_field_name('condition'))
            structure.append(")")
            return

        if node.type == 'switch_statement':
            structure.append("switch(")
            traverse(node.child_by_field_name('condition'))
            structure.append("){")
            
            if indent_step > 0:
                depth += 1
            
            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    if child.type in ['{', '}']: continue
                    append_indent()
                    traverse(child)
            
            if indent_step > 0:
                depth -= 1
                append_indent()
                
            structure.append("}")
            return

        if node.type == 'case_statement':
            structure.append("case ")
            value = node.child_by_field_name('value')
            if value:
                traverse(value)
            structure.append(":")
            
            if indent_step > 0:
                depth += 1
                
            for child in node.children:
                if child.type not in ['case', ':', 'number_literal'] and child != value:
                    append_indent()
                    traverse(child)
            
            if indent_step > 0:
                depth -= 1
            return

        if node.type == 'goto_statement':
            structure.append("goto label")
            return

        if node.type == 'call_expression':
            structure.append("call(")
            args = node.child_by_field_name('arguments')
            if args:
                first = True
                for child in args.children:
                    if child.type not in ['(', ')', ',']:
                        if not first: structure.append(", ")
                        traverse(child)
                        first = False
            structure.append(")")
            return

        if node.type == 'conditional_expression':
            structure.append("(")
            traverse(node.child_by_field_name('condition'))
            structure.append("? ")
            traverse(node.child_by_field_name('consequence'))
            structure.append(": ")
            traverse(node.child_by_field_name('alternative'))
            structure.append(")")
            return

        # Fallback 
        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    
    return "".join(structure).strip()

def get_func_name(bin, dataset_path=DATASET_PATH):
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"Error: Dataset path '{dataset_path}' does not exist.")

    try:
        ds = datasets.load_from_disk(dataset_path)
    except Exception as e:
        raise RuntimeError(f"Error loading dataset: {e}")

    for _, row in enumerate(ds):
        if bin in row.get('path'):
            return row.get('file')
    raise ValueError(f"Function name for binary '{bin}' not found in dataset.")


def get_source_code(bin, dataset_path=DATASET_PATH):
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"Error: Dataset path '{dataset_path}' does not exist.")

    try:
        ds = datasets.load_from_disk(dataset_path)
    except Exception as e:
        raise RuntimeError(f"Error loading dataset: {e}")

    for _, row in enumerate(ds):
        if bin in row.get('path'):
            return row.get('func')
    raise ValueError(f"Source code for binary '{bin}' not found in dataset.")


# just reference
def get_dataset_info():

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Error: Dataset path '{DATASET_PATH}' does not exist.")

    try:
        ds = datasets.load_from_disk(DATASET_PATH)
    except Exception as e:
        raise RuntimeError(f"Error loading dataset: {e}")

    print(f"Found {len(ds)} items.\n")

    (func, path, source) = ([], [], [])
    for _, row in enumerate(ds):
        func.append(row.get('file'))
        path.append(row.get('path'))
        source.append(row.get('func'))

    return (func, path, source)


def get_cc(code):
    """
    Calculates the Cyclomatic Complexity
    """
    try:
        analysis = lizard.analyze_file.analyze_source_code(
            "dummy_file.c", code)
        if analysis.function_list:
            return analysis.function_list[0].cyclomatic_complexity
    except Exception as e:
        print(f"[WARN] Lizard complexity check failed: {e}")
    return 0


def fetch_decompiler_prs():
    """
    Fetches open PR numbers from Ghidra repo with label "Feature: Decompiler"
    """
    url = "https://api.github.com/search/issues"
    query = 'repo:NationalSecurityAgency/ghidra is:pr is:open label:"Feature: Decompiler"'

    params = {
        'q': query,
        'sort': 'updated',
        'order': 'desc',
        'per_page': 100
    }

    try:
        print(f"[GITHUB] Fetching open PRs with label 'Feature: Decompiler'...")
        response = requests.get(url, params=params)

        if response.status_code == 200:
            data = response.json()
            items = data.get('items', [])
            pr_numbers = [str(item['number']) for item in items]
            print(f"[GITHUB] Found {len(pr_numbers)} PRs: {pr_numbers}")
            # pr_numbers  # 5554, '8834']  # pr_numbers
            return ['8752', '8635', '8629', '8628', '8587', '8312', '8161', '7253', '6722', '6718']
            # return ['3299', '8597']
        elif response.status_code == 403:
            print("[WARN] GitHub API rate limit exceeded or access denied.")
            return []
        else:
            print(f"[ERR] GitHub API returned status {response.status_code}")
            return []

    except Exception as e:
        print(f"[ERR] Failed to fetch PRs: {e}")
        return []


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
