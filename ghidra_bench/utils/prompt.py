def get_quality_prompt(source_code, code_a, code_b):
    return (
        "You are a Lead Compiler Engineer evaluating decompilation quality.\n"
        "Your goal is to select the candidate that best approximates the original Source Code.\n"
        "**CRITICAL GOAL**: You represent a human developer. If exact semantic reconstruction fails in both, "
        "you MUST prefer the candidate with the most 'human-like' structure (standard loops, clean logic) "
        "over spaghetti code, even if it has minor inaccuracies.\n\n"

        "### EVALUATION HIERARCHY (In order of priority)\n"
        "1. **Semantic Equivalence**: Does it do the exact same thing? (Critical)\n"
        "2. **Idiomatic C**: Does it look like code written by a human? (e.g., `for(i=0..)` vs `while` with gotos). (High Priority)\n"
        "3. **Variable/Type Recovery**: Are types correct? (Medium Priority)\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You CANNOT return null. One candidate is always 'less bad' than the other.\n"
        "- **The 'Human' Tie-Breaker**: If Candidate A is semantically perfect but uses `goto` everywhere, and Candidate B has a minor bug but perfect clean structure, **CHOOSE B**. We prefer readable code that needs a small fix over unreadable correct code.\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH ---\n"
        f"```c\n{source_code}\n```\n\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Think deeply about the control flow and logic. Then, output ONLY the following JSON structure without markdown formatting if possible:\n"
        "{\n"
        '  "motivation": "One sentence explanation focusing on why the winner is more human-readable or accurate.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_ast_prompt(ast_a, ast_b, source_ast):
    return (
        "You are a Static Analysis Expert comparing Control Flow Skeletons (AST).\n"
        "Your goal: Identify which AST is topologically closer to the Source, prioritizing structural shapes (loops/nesting) over node labels.\n\n"

        "### CRITERIA\n"
        "1. **Topological Shape**: Does the nesting depth and sequence of blocks match the Source?\n"
        "2. **Loop Fidelity**: `ForLoop` vs `WhileLoop`. If Source has a `ForLoop`, the candidate with `ForLoop` wins.\n"
        "3. **Complexity Penalty**: Penalize candidates that add unnecessary `Goto`, `Label`, or extra nesting levels.\n\n"

        "### FORCED DECISION\n"
        "- You MUST pick a winner. If both are bad, pick the one with the correct Loop Types.\n"
        "- If Loop Types match in both, pick the one with the correct Nesting Depth.\n\n"

        "### INPUT DATA\n"
        f"--- SOURCE AST ---\n{source_ast}\n\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Concise reason (e.g., \'A recovered the for-loop while B used while-goto\').",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )
