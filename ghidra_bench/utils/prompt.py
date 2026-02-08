def get_quality_prompt_s(source_code, code_a, code_b):
    return (
        "You are a Lead Compiler Engineer evaluating decompilation quality.\n"
        "Your goal is to select the candidate that best approximates the original Source Code as that implies that it is more human-readable and structurally sound.\n"
        "**CRITICAL GOAL**: You represent a human developer. If exact semantic reconstruction fails in both, "
        "you MUST prefer the candidate with the most 'human-like' structure (standard loops, clean logic) "
        "over spaghetti code, even if it has minor inaccuracies; the one more human, structurally sound, readable, and idiomatic..\n\n"

        "### EVALUATION HIERARCHY (In order of priority)\n"
        "1. **Idiomatic C**: Does it look like code written by a human? (e.g., `for(i=0..)` vs `while` with gotos). (Critical)\n"
        "2. **Semantic Equivalence**: Does it do the exact same thing? (High Priority)\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You CANNOT return null. One candidate is always 'less bad' than the other.\n"
        "- **The 'Human' Tie-Breaker**: If Candidate A is semantically perfect but uses `goto` everywhere, and Candidate B has a minor bug but perfect clean structure, **CHOOSE B**. We prefer readable code that needs a small fix over unreadable correct code.\n\n"
        "- **Ignore Semantics**: Do not judge variable names (e.g., `iVar1` vs `index`) or whitespace styles.\n"
        "- **Focus on Structure**: Evaluate strictly the Control Flow Graph (CFG) recovery and C expression logic.\n"

        "### EVALUATION CRITERIA\n"
        "Compare based on these factors:\n"
        "- **Control Flow Reconstruction**: Does the code use high-level loops (`while`, `for`) and structured `switch` cases? "
        "Heavily penalize `goto`, arbitrary `label:` jumps, and spaghetti logic.\n"
        "- **Expression Logic**: Are pointers and arithmetic clean (e.g., `arr[i]`) or raw/messy (e.g., `*(int *)(p + 4)`)? "
        "Prefer standard C idioms over raw byte manipulation.\n"
        "- **Dead Code/Redundancy**: Penalize unnecessary temporary variables, redundant casts, or dead assignments.\n"
        "- **Conditionals**: Are `if/else` chains logical, or artificially flattened/nested?\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH (SOURCE CODE) ---\n"
        f"```c\n{source_code}\n```\n\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Think deeply about the control flow and logic internally. Then, output ONLY the following JSON structure without markdown formatting if possible:\n"
        "{\n"
        '  "motivation": "One sentence explanation focusing on why the winner is more human-readable or accurate.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_ast_prompt_s(ast_a, ast_b, source_ast):
    return (
        "You are a Senior Static Analysis Expert evaluating the 'Human-ness' of Control Flow Skeletons (AST).\n"
        "Your goal is to select the AST candidate that best recovers the *intended structural logic* of the Source, "
        "prioritizing high-level abstractions over raw machine-like flows as it indicates a more human-readable and structurally sound design.\n\n"

        "### CONTEXT\n"
        "The inputs are stripped ASTs (e.g., `if(id && id){while(id){ type id = num op}}`). Variables are abstract.\n"
        "**CRITICAL GOAL**: You must identify which structure looks like it was written by a human developer "
        "versus a decompiler's state-machine artifact.\n\n"

        "### EVALUATION HIERARCHY (In order of priority)\n"
        "1. **High-Level Abstraction Recovery (Idiomatic Structure)**:\n"
        "   - **Loops**: If Source has a `for` loop, a candidate with `for` is superior to one using `while` or `goto`.\n"
        "   - **Branching**: If Source has a `switch`, a candidate with `switch` is superior to cascading `if-else` chains.\n"
        "2. **Spaghetti Reduction (The 'Goto' Penalty)**:\n"
        "   - Humans rarely write `goto`. Decompilers love them.\n"
        "   - Heavily penalize `goto`, `label`, or `break` used to simulate loops. The candidate with FEWER `goto` nodes is more 'human'.\n"
        "3. **Nesting Plausibility**:\n"
        "   - Humans prefer flat logic. Penalize artificial nesting (e.g., `if(){ if(){ ... } }` where the Source implies a single logical AND).\n"
        "   - If Source is flat, the Candidate with the matching flat depth wins.\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You CANNOT return null.\n"
        "- **The 'Structure' Tie-Breaker**: If Candidate A follows the Source's topology exactly (e.g., has the `switch`), but adds one extra wrapper block `{}`, and Candidate B completely loses the `switch` (turning it into `if-else`), **CHOOSE A**. Structural type correctness (`switch` vs `if`) outweighs minor block noise.\n"
        "- **Syntactic Sugar**: Prefer `for()` over `while()` if the Source used `for()`. Prefer `switch` over `if-else-if`.\n\n"

        "### INPUT DATA\n"
        f"--- GROUND TRUTH (SOURCE AST) ---\n{source_ast}\n\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Analyze the topological shapes. Then, output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Concise explanation (e.g., \'A recovered the switch-case structure and avoided gotos, while B degraded to if-else spaghetti\').",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_quality_prompt(code_a, code_b):
    return (
        "You are a Lead C Code Auditor performing a blind review of two decompiled functions.\n"
        "Your goal is to select the candidate that is more **idiomatic, readable, and structurally sound**.\n"
        "Since you do not have the original source code, you must judge purely on **Software Engineering Standards** and **Human-Likeness**.\n\n"

        "### CORE PHILOSOPHY: The 'Human' Turing Test\n"
        "Ask yourself: *Which version looks like it was written by a competent human developer, and which looks like a machine-generated state machine?*\n"
        "- **Human Code**: Uses high-level abstractions (`for`, `switch`, structs, arrays), logical variable scopes, and clear control flow.\n"
        "- **Machine Code**: Uses `goto`, explicit `label:` jumps, raw pointer arithmetic (`*(p+4)`), infinite loops with breaks, or cascaded `if-else` chains instead of `switch`.\n\n"

        "### EVALUATION CRITERIA (In order of priority)\n"
        "1. **Control Flow Hygiene** (Critical):\n"
        "   - **Winner**: Uses `for(int i=0...` loops and structured `switch` cases.\n"
        "   - **Loser**: Uses `while(true)` combined with `if (...) break`, or spaghetti `goto` logic.\n"
        "2. **Expression Logic**:\n"
        "   - **Winner**: Uses idiomatic access like `arr[i]` or `ptr->field`.\n"
        "   - **Loser**: Uses raw byte manipulation like `*(int*)((char*)ptr + 8)`.\n"
        "3. **Readability & Logic**:\n"
        "   - Penalize deeply nested `if` chains that could be flattened (early returns).\n"
        "   - Penalize redundant variables or dead code.\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You CANNOT return null. You MUST pick the one that is 'less painful' to read.\n"
        "- **Tie-Breaker**: If both are similar, pick the one with fewer `goto` statements and fewer casts.\n\n"

        "### INPUT DATA\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Analyze the code structure internally. Then, output ONLY the following JSON structure:\n"
        "{\n"
        '  "motivation": "One sentence explanation focusing on why the winner is more human-readable (e.g., \'A used a clean for-loop while B used goto spaghetti\').",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )

def get_ast_prompt(ast_a, ast_b):
    return (
        "You are a Static Analysis Expert evaluating the 'Human-ness' of Control Flow Skeletons (AST).\n"
        "Your goal is to select the AST candidate that represents the most **logical and high-level structural design**.\n"
        "You do not have the source AST. You must judge based on which structure represents **Idiomatic Programming Patterns** and **Human-Likeness**.\n\n"

        "### CONTEXT\n"
        "The inputs are stripped ASTs (e.g., `if(id && id){while(id){ type id = num op}}`). Variables are abstract.\n"
        "**CRITICAL GOAL**: Distinguish between High-Level Logic (Human) and Control Flow Graph artifacts (Decompiler).\n\n"

        "### EVALUATION HIERARCHY\n"
        "1. **High-Level Abstraction Preference**:\n"
        "   - **Loops**: A `for` loop is intrinsically superior to a `while` loop, which is superior to a `goto` cycle. Humans prefer `for` for iteration.\n"
        "   - **Branching**: A `switch` structure is superior to a long chain of `if-else-if`. It indicates the decompiler successfully recognized the jump table pattern.\n"
        "2. **Spaghetti Reduction (The 'Goto' Penalty)**:\n"
        "   - Any presence of `goto` or `label` is a strong negative signal.\n"
        "   - The candidate with FEWER `goto` nodes is almost always the winner.\n"
        "3. **Nesting & Complexity**:\n"
        "   - **Compactness**: `if(A && B)` (one block) is better than `if(A){ if(B) ... }` (nested blocks).\n"
        "   - **Artificial Scope**: Penalize excessive wrapper blocks `{ { ... } }` that serve no logical purpose.\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You must pick a winner.\n"
        "- **The Cleanliness Rule**: If both use the same structures, choose the one with less nesting depth and fewer `goto`s.\n\n"

        "### INPUT DATA\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Analyze the topological shapes. Then, output ONLY valid JSON:\n"
        "{\n"
        '  "motivation": "Concise explanation (e.g., \'A recovered high-level loop structures, whereas B relied on low-level jumps\').",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )