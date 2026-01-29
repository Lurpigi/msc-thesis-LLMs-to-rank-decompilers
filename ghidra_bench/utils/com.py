import subprocess
import sys
import requests
import lizard
import tree_sitter_c
from tree_sitter import Language, Parser
from .const import LLM_API_URL


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
            return pr_numbers[::-1]  # 5554, '8834']  # pr_numbers
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
