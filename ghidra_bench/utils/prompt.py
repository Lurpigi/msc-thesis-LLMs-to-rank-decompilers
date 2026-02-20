def get_quality_prompt_s(diff_text, source_code):
    return (
        "You are a Senior Compiler Engineer evaluating decompilation fidelity.\n"
        "Your goal: Determine if the changes in the Diff move the code **closer to the Source Code structure** or further away.\n\n"

        "### HOW TO READ THE COMPARISON\n"
        "- Lines starting with `%` belong ONLY to **Candidate A**.\n"
        "- Lines starting with `&` belong ONLY to **Candidate B**.\n"
        "- Lines starting with a space belong to BOTH (shared context).\n\n"

        "### EVALUATION CRITERIA\n"
        "1. **Structural Isomorphism**: Which version (A or B) matches the control flow structures of the Source Code?\n"
        "   - Source `switch` -> Winner must have `switch`.\n"
        "   - Source `for` -> Winner must have `for`.\n"

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

        "### HOW TO READ THE COMPARISON\n"
        "- Lines starting with `%` belong ONLY to **Candidate A**.\n"
        "- Lines starting with `&` belong ONLY to **Candidate B**.\n"
        "- Lines starting with a space belong to BOTH (shared context).\n\n"

        "### EVALUATION CRITERIA\n"
        "1. **Topology Match**: Which version (A or B) preserves the Source AST node types and structure?\n"
        "2. **Complexity**: Does the one version of code match better the nesting depth of the Source?\n\n"

        "### INPUT DATA\n"
        f"--- GROUND TRUTH (SOURCE AST) ---\n{source_ast}\n\n"
        f"--- AST DIFF (A vs B) ---\n"
        f"```diff\n{diff_text}\n```\n"

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
        "Your goal is to decide which version in the diff (the version A '-' lines or the version B '+' lines) represents better **Human Engineering Practices**.\n"
        "**CRITICAL RULE**: Focus ONLY on the logic flow and readability changes shown in the diff.\n\n"

        "### HOW TO READ THE COMPARISON\n"
        "- Lines starting with `%` belong ONLY to **Candidate A**.\n"
        "- Lines starting with `&` belong ONLY to **Candidate B**.\n"
        "- Lines starting with a space belong to BOTH (shared context).\n\n"

        "### THE ONLY HIERARCHY: HUMAN ENGINEERING & READABILITY\n"
        "We prioritize code that looks like it was authored by an experienced human programmer over raw, algorithmic output.\n\n"
        "1. **Human-like Traits (Winner)**:\n"
        "   - Natural, idiomatic choices (e.g., using a clean `for` loop instead of a clunky `while` with manual increments).\n"
        "   - Simplified, elegant conditionals and optimized operations.\n"
        "   - Clean visual structure that prioritizes readability and clear developer intent.\n\n"
        "2. **Machine-like Artifacts (Loser)**:\n"
        "   - Over-complicated, mechanical translations of simple logic.\n"
        "   - Redundant operations, unnecessary casts, or awkward block structures.\n"
        "   - Literal, step-by-step logic that a human would naturally abstract away.\n\n"

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

        "### HOW TO READ THE COMPARISON\n"
        "- Lines starting with `%` belong ONLY to **Candidate A**.\n"
        "- Lines starting with `&` belong ONLY to **Candidate B**.\n"
        "- Lines starting with a space belong to BOTH (shared context).\n\n"

        "### THE ONLY HIERARCHY: HUMAN ENGINEERING & READABILITY\n"
        "We prioritize code that looks like it was authored by an experienced human programmer over raw, algorithmic output.\n\n"
        "1. **Human-like Traits (Winner)**:\n"
        "   - Natural, idiomatic choices (e.g., using a clean `for` loop instead of a clunky `while` with manual increments).\n"
        "   - Simplified, elegant conditionals and optimized operations.\n"
        "   - Clean visual structure that prioritizes readability and clear developer intent.\n\n"
        "2. **Machine-like Artifacts (Loser)**:\n"
        "   - Over-complicated, mechanical translations of simple logic.\n"
        "   - Redundant operations, unnecessary casts, or awkward block structures.\n"
        "   - Literal, step-by-step logic that a human would naturally abstract away.\n\n"

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

#########################################################


def Cget_quality_prompt_s(code_a, code_b, source_code):
    return (
        "You are a Senior Compiler Engineer evaluating decompilation fidelity.\n"
        "Your goal: Determine which candidate version (A or B) is **closer to the Source Code structure**.\n\n"

        "### EVALUATION CRITERIA\n"
        "1. **Structural Isomorphism**: Which version matches the control flow structures of the Source Code?\n"
        "   - Source `switch` -> Winner should have `switch`.\n"
        "   - Source `for` -> Winner should have `for`.\n"
        "2. **Logical Fidelity**: Which version correctly represents the logic of the source without introducing assembly-level artifacts (like unnecessary gotos)?\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH (SOURCE CODE) ---\n"
        f"```c\n{source_code}\n```\n\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Briefly describe which candidate aligns better with the Source structure.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def Cget_ast_prompt_s(ast_a, ast_b, source_ast):
    return (
        "You are a Decompilation Architect comparing AST topologies against a Ground Truth.\n"
        "Your goal: Determine which candidate (A or B) mirrors the **Source AST topology**.\n\n"

        "### EVALUATION CRITERIA\n"
        "1. **Topology Match**: Does one Candidate restore a node type (e.g. `SwitchStatement`) present in the Source but missing in the other?\n"
        "2. **Complexity**: Does the candidate match the nesting depth and statement hierarchy of the Source?\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH (SOURCE AST) ---\n"
        f"{source_ast}\n\n"
        "--- CANDIDATE A AST ---\n"
        f"{ast_a}\n\n"
        "--- CANDIDATE B AST ---\n"
        f"{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Identify specific node types or nesting levels that match the Ground Truth.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def Cget_quality_prompt(code_a, code_b):
    return (
        "You are a Lead C Code Auditor performing a blind review of two decompilation candidates.\n"
        "Your goal: Decide which version represents better **Human Engineering Practices**.\n\n"

        "### THE HIERARCHY OF IDIOMATIC CONTROL FLOW\n"
        "Prioritize structures that map to high-level human thinking over raw machine output:\n"
        "1. **Semantic Structure (Preferred)**: `for` loops, `do-while`, `switch` statements, and clean scoping.\n"
        "2. **Graph Artifacts (Avoid)**: `goto` spaghetti, deep `if-else` cascades where `switch` applies, or artificial `{ { ... } }` wrapper blocks.\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: Pick a winner.\n"
        "- **Tie-Breaker**: If logic is identical, choose the version with less artificial nesting depth.\n\n"

        "### INPUT DATA\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Describe why the winner is more human-readable/idiomatic.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def Cget_ast_prompt(ast_a, ast_b):
    return (
        "You are a Static Analysis Expert evaluating Control Flow Skeletons (AST).\n"
        "Your goal: Decide which structural representation (A or B) is more **Idiomatic**.\n\n"

        "### CRITERIA\n"
        "We prioritize high-level human abstractions over raw assembly-derived graphs:\n"
        "- **Winner**: Natural loops (`for`/`while`), `switch` cases, and logical nesting.\n"
        "- **Loser**: Conditional jumps to labels (`goto`), excessive `if-else` cascades, and redundant wrapper blocks.\n\n"

        "### INPUT DATA\n"
        "--- CANDIDATE A AST ---\n"
        f"{ast_a}\n\n"
        "--- CANDIDATE B AST ---\n"
        f"{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Explain the structural advantages of the winner.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )
