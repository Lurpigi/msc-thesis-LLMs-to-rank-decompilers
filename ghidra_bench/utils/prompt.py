def get_quality_prompt_s(diff_text, source_code):
    return (
        "You are a Senior Compiler Engineer evaluating decompilation fidelity.\n"
        "Your goal: Determine if the changes in the Diff move the code **closer to the Source Code structure** or further away.\n\n"

        "### HOW TO READ THE DIFF\n"
        "- Lines `-` = **Candidate A**.\n"
        "- Lines `+` = **Candidate B**.\n\n"

        "### EVALUATION CRITERIA\n"
        "1. **Structural Isomorphism**: Which version (A or B) matches the control flow structures of the Source Code?\n"
        "   - Source `switch` -> Winner must have `switch`.\n"
        "   - Source `for` -> Winner must have `for`.\n"
        "2. **Correction vs Regression**: Does the `+` line fix a logic error present in `-`, or does it introduce noise?\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH (SOURCE CODE) ---\n"
        f"```c\n{source_code}\n```\n\n"
        "--- STRUCTURAL DIFF (A vs B) ---\n"
        f"```diff\n{diff_text}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Briefly describe which version aligns with Source structure.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_ast_prompt_s(diff_text, source_ast):
    return (
        "You are a Decompilation Architect comparing AST changes against a Ground Truth.\n"
        "Your goal: Determine which version in the Diff (A or B) mirrors the **Source AST topology**.\n\n"

        "### HOW TO READ THE DIFF\n"
        "- Lines `-` = **Candidate A**.\n"
        "- Lines `+` = **Candidate B**.\n\n"

        "### CRITERIA\n"
        "1. **Topology Match**: Does the `+` code restore a node type (e.g. `SwitchStatement`) present in the Source but missing in `-`?\n"
        "2. **Complexity**: Does the `+` code match the nesting depth of the Source?\n\n"

        "### INPUT DATA\n"
        f"--- GROUND TRUTH (SOURCE AST) ---\n{source_ast}\n\n"
        f"--- AST DIFF (A vs B) ---\n{diff_text}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Briefly describe which version aligns with Source structure.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_quality_prompt(diff_text):
    return (
        "You are a Lead C Code Auditor performing a blind review of a patch (Diff).\n"
        "Your goal is to decide which version in the diff (the original '-' lines or the new '+' lines) represents better **Human Engineering Practices**.\n"
        "**CRITICAL RULE**: Focus ONLY on the logic flow and readability changes shown in the diff.\n\n"

        "### HOW TO READ THE DIFF\n"
        "- Lines `-` = **Candidate A**.\n"
        "- Lines `+` = **Candidate B**.\n\n"

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
        "**Judge**: Does the difference make the code more like a Human (Abstract) or more like a Machine (Concrete)?\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: Pick a winner.\n"
        "- **Tie-Breaker**: If logic is identical, choose the representation with less artificial nesting/depth.\n\n"


        "### INPUT DATA (UNIFIED DIFF)\n"
        f"```diff\n{diff_text}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Why the winner is more human-like.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_ast_prompt(diff_text):
    return (
        "You are a Static Analysis Expert evaluating changes in Control Flow Skeletons (AST).\n"
        "Your goal: Decide if the structural changes in the Diff improve the **Idiomatic Design**.\n\n"

        "### HOW TO READ THE DIFF\n"
        "- Lines `-` = **Candidate A**.\n"
        "- Lines `+` = **Candidate B**.\n\n"

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
        "**Judge**: Does the difference make the code more like a Human (Abstract) or more like a Machine (Concrete)?\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: Pick a winner.\n"
        "- **Tie-Breaker**: If logic is identical, choose the representation with less artificial nesting/depth.\n\n"

        "### INPUT DATA (AST DIFF)\n"
        f"```diff\n{diff_text}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Why the winner is more human-like.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )
