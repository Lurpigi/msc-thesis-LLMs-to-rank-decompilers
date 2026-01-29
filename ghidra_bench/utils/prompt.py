
def get_quality_prompt(base_code, pr_code):
    return (
        "You are a Senior Reverse Engineering Analyst and C Code Auditor.\n"
        "Your goal is to compare two decompiled versions of the same function and determine "
        "which one is more human, structurally sound, readable, and idiomatic.\n\n"

        "### INSTRUCTIONS\n"
        "1. **Ignore Semantics**: Do not judge variable names (e.g., `iVar1` vs `index`) or whitespace styles.\n"
        "2. **Focus on Structure**: Evaluate strictly the Control Flow Graph (CFG) recovery and C expression logic.\n"
        "3. **Compare**: Version A is the 'BASE' (current), Version B is the 'PR' (proposed).\n\n"

        "### EVALUATION CRITERIA\n"
        "Compare BASE and PR based on these factors:\n"
        "- **Control Flow Reconstruction**: Does the code use high-level loops (`while`, `for`) and structured `switch` cases? "
        "Heavily penalize `goto`, arbitrary `label:` jumps, and spaghetti logic.\n"
        "- **Expression Logic**: Are pointers and arithmetic clean (e.g., `arr[i]`) or raw/messy (e.g., `*(int *)(p + 4)`)? "
        "Prefer standard C idioms over raw byte manipulation.\n"
        "- **Dead Code/Redundancy**: Penalize unnecessary temporary variables, redundant casts, or dead assignments.\n"
        "- **Conditionals**: Are `if/else` chains logical, or artificially flattened/nested?\n\n"

        "### INPUT DATA\n"
        "--- VERSION A (BASE) ---\n"
        f"```c\n{base_code}\n```\n\n"
        "--- VERSION B (PR) ---\n"
        f"```c\n{pr_code}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Analyze the code step-by-step internally. Then, provide the final verdict ONLY in this JSON format:\n"
        "{\n"
        '  "winner": "BASE" | "PR" | "TIE"\n'
        '  "analysis": "Concise justification focusing on structural differences (e.g., \'PR successfully recovered the for-loop structure that BASE missed\').",\n'
        "}"
    )


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
        "2. **BASE (Decompiler A)**: Current decompiler output.\n"
        "3. **PR (Decompiler B)**: Proposed improved decompiler output.\n\n"

        "### EVALUATION CRITERIA\n"
        "Compare BASE and PR against the SOURCE. Choose the winner based on:\n"
        "1. **Loop Recovery**: Does it correctly identify `for/while` loops instead of `if + goto`?\n"
        "2. **Nesting Depth**: Does it respect the original nesting level without excessive flattening or unnecessary nesting?\n"
        "3. **Branching Logic**: Does it maintain `if-else` chains similar to the source, or does it fragment them?\n"
        "4. **Ghost Instructions**: Penalize the presence of phantom `label:` and `goto` that do not exist in the SOURCE.\n\n"

        "### DATA\n"
        f"--- SOURCE AST (Target) ---\n{source_ast}\n\n"
        f"--- BASE AST ---\n{base_ast}\n\n"
        f"--- PR AST ---\n{pr_ast}\n\n"

        "### OUTPUT FORMAT\n"
        "Analyze the structures step-by-step internally, then output your final decision ONLY in valid JSON format:\n"
        "{\n"
        '  "winner": "BASE" | "PR" | "TIE"\n'
        '  "analysis": "Brief comparison of why you chose the winner.",\n'
        "}"
    )
