def get_quality_prompt_s(source_code, code_a, code_b):
    return (
        "You are a Senior Compiler Engineer evaluating decompilation Structural Fidelity.\n"
        "Your goal is to select the candidate that best approximates the **Control Flow Graph (CFG)** and **Data Structures** of the Source Code.\n"
        "**CRITICAL RULE**: IGNORE variable names. Focus ONLY on whether the *structure* matches the source logic.\n\n"

        "### THE ONLY HIERARCHY: HUMAN INTENT RECOVERY\n"
        "Your sole criterion is: **Which candidate successfully recovers the logic patterns written by the original human developer?**\n"
        "- **The Source is the Human Standard**: If the Source uses a `switch`, the Human-Like candidate uses a `switch`. If the Source uses `for`, the Human-Like candidate uses `for`.\n"
        "- **Decompiler Noise**: Any deviation from the Source structure (e.g., turning a `switch` into `if-else` cascades, or a `for` loop into `goto` labels) is considered a 'Decompiler Artifact' and must be penalized.\n"
        "- **Exception**: If the Source itself uses `goto` (e.g., for error cleanup), preserving it is CORRECT and HUMAN. Do not penalize fidelity to the source.\n\n"

        "### COMPARISON GUIDE\n"
        "1. **Control Flow Isomorphism**: `switch` vs `switch` > `switch` vs `if-else`.\n"
        "2. **Loop Abstraction**: `for(;;)` vs `for(;;)` > `for(;;)` vs `while` + `goto`.\n"
        "3. **Data Access**: `obj->field` vs `obj->field` > `obj->field` vs `*(obj + offset)`.\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: Pick a winner.\n"
        "- **Tie-Breaker**: Choose the one that is easier to read and maintain.\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH (SOURCE CODE) ---\n"
        f"```c\n{source_code}\n```\n\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Think deeply about structural equivalence. Output ONLY valid JSON:\n"
        "{\n"
        '  "diff_analysis": "Briefly describe the structural difference.",\n'
        '  "motivation": "One sentence explanation focusing on structural fidelity to the human source.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_ast_prompt_s(ast_a, ast_b, source_ast):
    return (
        "You are a Senior Decompilation Architect. Your task is to compare two AST candidates against a Ground Truth (Source AST).\n"
        "Your goal: Determine which candidate better preserves the **architectural intent** of the Source.\n\n"

        "### THE ONLY HIERARCHY: STRUCTURAL ISOMORPHISM\n"
        "The Winner is the one that mirrors the **topological shape** of the Source AST.\n"
        "1. **Match the Abstraction**: If Source has `switch`, Winner has `switch`. If Source has `for`, Winner has `for`.\n"
        "2. **Reject Degradation**: If a candidate transforms a high-level structure (Source) into a lower-level one (e.g., `if-else` chain, `while` + `break`, `goto`), it is a failure of the decompiler.\n"
        "3. **Complexity Matching**: If Source is flat, Winner is flat. If Source is nested, Winner is nested. Penalize hallucinatory wrapper blocks `{ { } }`.\n\n"

        "### DIFFERENTIAL ANALYSIS STRATEGY\n"
        "1. **Triangulate**: Compare Source vs A vs B.\n"
        "2. **Locate Divergence**: Find where A and B disagree on the structure.\n"
        "3. **Select Fidelity**: The one closest to Source wins. If Source uses `goto` (ugly), the one that keeps `goto` wins (accurate).\n\n"

        "### INPUT DATA\n"
        f"--- GROUND TRUTH (SOURCE AST) ---\n{source_ast}\n\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "diff_analysis": "Identify the specific structure where A and B diverge relative to the Source.",\n'
        '  "motivation": "Explain why the winner is structurally closer to the Source intent.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_quality_prompt(code_a, code_b):
    return (
        "You are a Lead C Code Auditor performing a blind review.\n"
        "Your goal is to select the candidate that follows **Human Engineering Practices** over Machine Generation artifacts.\n"
        "**CRITICAL RULE**: IGNORE variable names. Focus ONLY on logic flow, data access, and readability.\n\n"

        "### THE ONLY HIERARCHY: HUMAN READABILITY & STANDARDS\n"
        "Ask yourself: *Which version would I accept in a Code Review from a junior human developer?*\n\n"
        "1. **High-Level Abstractions (Winner)**:\n"
        "   - Uses `for` loops for iteration.\n"
        "   - Uses `switch` for multi-branching.\n"
        "   - Uses struct arrows `->` for member access.\n"
        "   - Uses standard boolean logic (`&&`, `||`).\n\n"
        "2. **Low-Level Artifacts (Loser)**:\n"
        "   - Uses `goto` to simulate loops (backward jumps).\n"
        "   - Uses infinite loops (`while(1)`) combined with conditional breaks.\n"
        "   - Uses raw pointer arithmetic (`*(p+4)`) instead of struct fields.\n"
        "   - Uses deep, unnecessary nesting (Arrow Code).\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: Pick a winner.\n"
        "- **The Goto Nuance**: `goto` is ONLY acceptable for forward-jumping error cleanup (standard C pattern). Any other use (loops, spaghetti) is a fail.\n"
        "- **Tie-Breaker**: Choose the one that is easier to read and maintain.\n\n"

        "### INPUT DATA\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "diff_analysis": "Briefly describe the structural difference.",\n'
        '  "motivation": "One sentence explanation focusing on why the winner is more human-like.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )

def get_ast_prompt(ast_a, ast_b):
    return (
        "You are a Lead Static Analysis Expert evaluating decompiled Control Flow Skeletons (AST).\n"
        "Your goal: Select the candidate that represents the most **idiomatic and human-like structural design**.\n\n"

        "### THE ONLY HIERARCHY: IDIOMATIC CONTROL FLOW\n"
        "We prioritize structures that map to high-level human thinking over raw assembly graphs.\n\n"
        "1. **Semantic Structure (Winner)**:\n"
        "   - `for` loops, `do-while` loops, `switch` statements.\n"
        "   - Clean nesting that reflects logical scope.\n\n"
        "2. **Graph Artifacts (Loser)**:\n"
        "   - `goto` cycles (spaghetti).\n"
        "   - `if-else` cascades (where `switch` applies).\n"
        "   - Artificial wrapper blocks `{ { ... } }`.\n\n"

        "### DIFFERENTIAL ANALYSIS\n"
        "1. **Scan**: Ignore the 90% identical parts.\n"
        "2. **Isolate Delta**: Look ONLY at where the nodes differ.\n"
        "3. **Judge**: Does the difference make the code more like a Human (Abstract) or more like a Machine (Concrete)?\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: Pick a winner.\n"
        "- **Tie-Breaker**: If logic is identical, choose the representation with less artificial nesting/depth.\n\n"

        "### INPUT DATA\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "diff_analysis": "Briefly describe the structural difference.",\n'
        '  "motivation": "Why the winner is more human-like.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )