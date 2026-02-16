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
    verbose = 1
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
        print(
            f"[FATAL] Command failed with return code {process.returncode}")
        if not verbose and process.stdout:
            print(process.stdout)
        raise subprocess.CalledProcessError(process.returncode, cmd)
    if "ValueError:" in process.stdout:
        print(
            f"[FATAL] Command output indicates a ValueError: {process.stdout}")
        raise ValueError("Command output indicates a ValueError")


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

    def clean_ast_output(ast_str):
        lines = ast_str.splitlines()

        cleaned_lines = []
        for line in lines:
            stripped_right = line.rstrip()
            if line.strip():
                cleaned_lines.append(stripped_right)
        return "\n".join(cleaned_lines)

    def traverse(node):
        nonlocal depth

        if node is None:
            return

        if node.type == 'labeled_statement' and b'::' in node.text:
            for child in node.children:
                if child.type != ':':
                    traverse(child)
            return

        if node.type == 'function_definition':
            traverse(node.child_by_field_name('type'))
            structure.append(" ")
            traverse(node.child_by_field_name('declarator'))
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'function_declarator':
            traverse(node.child_by_field_name('declarator'))
            structure.append("(")
            params = node.child_by_field_name('parameters')
            if params:
                first = True
                for child in params.children:
                    if child.type not in ['(', ')', ',']:
                        if not first:
                            structure.append(", ")
                        traverse(child)
                        first = False
            structure.append(")")
            return

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
            structure.append(";")
            return

        if node.type == 'return_statement':
            structure.append("return")
            has_value = False
            for child in node.children:
                if child.type != 'return' and child.type != ';':
                    has_value = True
                    break

            if has_value:
                structure.append(" ")
                for child in node.children:
                    if child.type != 'return' and child.type != ';':
                        traverse(child)

            structure.append(";")
            return

        if node.type == 'if_statement':
            structure.append("if")
            traverse(node.child_by_field_name('condition'))
            # structure.append(")")
            traverse(node.child_by_field_name('consequence'))
            else_node = node.child_by_field_name('alternative')
            if else_node:
                if else_node.type == 'if_statement':
                    structure.append("else ")
                    traverse(else_node)
                else:
                    structure.append("else")
                    traverse(else_node)
            return

        # loops

        if node.type == 'while_statement':
            structure.append("while")
            traverse(node.child_by_field_name('condition'))
            # structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'do_statement':
            structure.append("do")
            traverse(node.child_by_field_name('body'))
            structure.append("while")
            traverse(node.child_by_field_name('condition'))
            structure.append(";")
            return

        if node.type == 'for_statement':
            structure.append("for(")
            init = node.child_by_field_name('initializer')
            if init:
                traverse(init)
                if init.type != 'declaration':
                    structure.append("; ")
            else:
                structure.append(";")
            structure.append(" ")

            cond = node.child_by_field_name('condition')
            if cond:
                traverse(cond)
            structure.append("; ")
            upd = node.child_by_field_name('update')
            if upd:
                traverse(upd)

            structure.append(")")
            traverse(node.child_by_field_name('body'))
            return

        if node.type == 'switch_statement':
            structure.append("switch")
            traverse(node.child_by_field_name('condition'))
            structure.append("{")
            if indent_step > 0:
                depth += 1

            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    if child.type in ['{', '}']:
                        continue
                    append_indent()
                    traverse(child)

            if indent_step > 0:
                depth -= 1
                append_indent()
            structure.append("}")
            return

        if node.type == 'case_statement':
            structure.append("case ")
            val = node.child_by_field_name('value')
            if val:
                traverse(val)
            else:
                structure.append("def")
            structure.append(":")
            if indent_step > 0:
                depth += 1
            for child in node.children:
                if child.type not in ['case', 'default', ':', 'number_literal'] and child != val:
                    append_indent()
                    traverse(child)
            if indent_step > 0:
                depth -= 1
            return

        if node.type == 'break_statement':
            structure.append("break;")
            return

        if node.type == 'continue_statement':
            structure.append("continue;")
            return

        if node.type == 'goto_statement':
            structure.append("goto lbl;")
            return

        if node.type == 'labeled_statement':
            if b'::' in node.children[0].text:
                for child in node.children:
                    if child.type != ':':
                        traverse(child)
                return

            structure.append("lbl:")
            append_indent()

            label_node = node.children[0]

            for child in node.children:
                if child.id == label_node.id:
                    continue
                if child.type == ':':
                    continue

                traverse(child)
            return

        if node.type == 'unary_expression' or node.type == 'pointer_expression':
            if node.child_count > 0:
                op_node = node.children[0]
                op = op_node.text.decode('utf8')
                if op in ['*', '&', '!', '-', '~']:
                    structure.append(op)
                else:
                    structure.append("op")
            traverse(node.child_by_field_name('argument'))
            return

        if node.type == 'pointer_declarator':
            structure.append("*")
            traverse(node.child_by_field_name('declarator'))
            return

        if node.type == 'abstract_pointer_declarator':
            structure.append("*")
            for child in node.children:
                if child.type != '*':
                    traverse(child)
            return

        if node.type == 'field_expression':
            traverse(node.child_by_field_name('argument'))
            operator = "."
            for child in node.children:
                if child.type == '->':
                    operator = "->"
                    break
                elif child.type == '.':
                    operator = "."
                    break

            structure.append(operator)
            traverse(node.child_by_field_name('field'))
            return

        # expressions

        if node.type == 'binary_expression':
            traverse(node.child_by_field_name('left'))
            op = node.children[1].text.decode('utf8')
            structure.append(f" {op} ")
            traverse(node.child_by_field_name('right'))
            return

        if node.type == 'update_expression':
            # for child in node.children:
            #     print(f"Update expression child: {child.type} - {child.text}")
            op = node.children[0].type
            # print(f"Update expression operator: {op}")
            if op in ['++', '--']:
                structure.append(node.children[0].text.decode('utf8'))
                traverse(node.children[1])
            else:
                traverse(node.children[0])
                structure.append(node.children[1].text.decode('utf8'))
            return

        if node.type == 'assignment_expression':
            traverse(node.child_by_field_name('left'))
            structure.append(" = ")
            traverse(node.child_by_field_name('right'))
            return

        if node.type == 'cast_expression':
            structure.append("(type)")
            traverse(node.child_by_field_name('value'))
            return

        if node.type == 'call_expression':
            structure.append("call(")
            args = node.child_by_field_name('arguments')
            if args:
                first = True
                for child in args.children:
                    if child.type not in ['(', ')', ',']:
                        if not first:
                            structure.append(", ")
                        traverse(child)
                        first = False
            structure.append(")")
            return

        if node.type == 'conditional_expression':
            structure.append("(")
            traverse(node.child_by_field_name('condition'))
            structure.append(" ? ")
            traverse(node.child_by_field_name('consequence'))
            structure.append(" : ")
            traverse(node.child_by_field_name('alternative'))
            structure.append(")")
            return

        if node.type == 'parenthesized_expression':
            structure.append("(")
            for child in node.children:
                if child.type not in ['(', ')']:
                    traverse(child)
            structure.append(")")
            return

        if node.type == 'declaration':
            structure.append("type ")
            first = True
            for child in node.children:
                if child.type in [
                    'primitive_type', 'type_identifier', 'struct_specifier',
                    'enum_specifier', 'union_specifier', 'storage_class_specifier',
                    'type_qualifier', 'sizeless_type', 'sized_type_specifier',
                    'class_specifier', 'attribute_specifier', 'ms_declspec_modifier',
                    ';', ','
                ]:
                    continue
                if not first:
                    structure.append(", ")

                traverse(child)
                first = False

            structure.append(";")
            return

        if node.type == 'parameter_declaration':
            traverse(node.child_by_field_name('type'))

            decl = node.child_by_field_name('declarator')
            if decl:
                structure.append(" ")
                traverse(decl)
            return

        if node.type == 'init_declarator':
            traverse(node.child_by_field_name('declarator'))
            structure.append(" = ")
            traverse(node.child_by_field_name('value'))
            return

        if node.type == 'number_literal':
            n = node.text.decode('utf8')
            # print(f"Number literal: {n}")
            structure.append(n)
            return

        if node.type in ['string_literal', 'char_literal', 'concatenated_string']:
            structure.append("str")
            return

        if node.type in ['true', 'false', 'null']:
            structure.append("bool" if node.type != 'null' else "null")
            return

        if node.type in ['primitive_type', 'type_identifier']:
            structure.append("type")
            return

        if node.type == 'pointer_declarator':
            structure.append("*")
            traverse(node.child_by_field_name('declarator'))
            return

        if node.type == 'subscript_expression':
            traverse(node.child_by_field_name('argument'))
            structure.append("[")
            traverse(node.child_by_field_name('index'))
            structure.append("]")
            return

        if node.type == 'array_declarator':
            traverse(node.child_by_field_name('declarator'))
            structure.append("[")
            size = node.child_by_field_name('size')
            if size:
                traverse(size)
            structure.append("]")
            return

        # Leaf nodes
        if node.child_count == 0:
            if node.type in ['identifier', 'field_identifier']:
                structure.append("id")
                return
            if len(node.type) == 1 and node.type in ";,(){}[]":
                return

        for child in node.children:
            traverse(child)

    traverse(tree.root_node)

    return clean_ast_output("".join(structure))


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
            return ['8628', '8587', '8161', '7253', '6722']
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
