def get_quality_prompt_s(source_code, code_a, code_b):
    return (
        "You are a Senior Compiler Engineer evaluating decompilation Structural Fidelity.\n"
        "Your goal is to select the candidate that best approximates the **Control Flow Graph (CFG)** and **Data Structures** of the Source Code.\n"
        "**CRITICAL RULE**: IGNORE variable names (e.g., `iVar1` vs `file_ptr`). Focus ONLY on whether the *structure* (loops, switches, logic) matches the source.\n\n"

        "### STRUCTURAL FIDELITY CHECKS (Logic over Text)\n"
        "1. **Control Flow Isomorphism**:\n"
        "   - *Source*: `switch(x) { case 1: ... }`\n"
        "   - *Winner*: `switch(v1) { case 1: ... }` (Matches structure).\n"
        "   - *Loser*: `if (v1 == 1) ... else if ...` (Broken structure).\n"
        "2. **Loop Recovery**:\n"
        "   - *Source*: `for (int i=0; i<10; i++)`\n"
        "   - *Winner*: `for (v1=0; v1<10; v1++)` (Matches logic).\n"
        "   - *Loser*: `v1=0; label: if(v1>=10) goto end; ... goto label;` (Degraded to goto).\n"
        "3. **Abstraction Level (Macros/Sizeof)**:\n"
        "   - *Source*: `malloc(sizeof(Node))`\n"
        "   - *Winner*: `malloc(sizeof(StructA))` (Preserves type awareness).\n"
        "   - *Loser*: `malloc(24)` (Collapses types to magic numbers).\n"
        "4. **Pointer Logic vs Struct Access**:\n"
        "   - *Source*: `obj->next = null`\n"
        "   - *Winner*: `v1->field1 = 0` (Preserves pointer dereferencing logic).\n"
        "   - *Loser*: `*(v1 + 8) = 0` (Degrades to offset arithmetic).\n\n"

        "### EVALUATION HIERARCHY\n"
        "1. **CFG Recovery**: Does the candidate use the same control structures (`while`, `for`, `switch`) as the source?\n"
        "2. **Expression Fidelity**: Are complex conditions (`A && B`) preserved or split into nested `if`s (`if(A){ if(B)... }`)?\n"
        "3. **Dead Code**: Does the candidate introduce logical noise (dead branches) not present in source?\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You must pick a winner.\n"
        "- **The 'Structure' Tie-Breaker**: If Candidate A has perfect names but `goto` spaghetti, and Candidate B has ugly names (`uVar1`) but perfect `for/switch` structure matching the source, **CHOOSE B**. Structure > Naming.\n"
        "- **Ignore Semantics**: Do not judge variable names or whitespace styles.\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH (SOURCE CODE) ---\n"
        f"```c\n{source_code}\n```\n\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Think deeply about the structural equivalence internally. Then, output ONLY the following JSON structure:\n"
        "{\n"
        '  "motivation": "One sentence explanation focusing on structural fidelity (e.g., \'A correctly recovered the switch statement and sizeof macro, whereas B degraded to if-else chains and magic numbers\').",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_ast_prompt_s(ast_a, ast_b, source_ast):
    return (
        "You are a Senior Decompilation Architect. Your task is to compare two AST candidates against a Ground Truth (Source AST).\n"
        "Your goal: Determine which candidate better preserves the **architectural intent** and **structural patterns** of the Source.\n\n"

        "### DIFFERENTIAL ANALYSIS STRATEGY\n"
        "1. **Triangulate**: Compare Source vs A vs B.\n"
        "2. **Find the Divergence**: Locate the specific block where A and B disagree with each other.\n"
        "3. **Match with Source**: Check which candidate's divergence aligns closer to the Source's structure.\n\n"

        "### EVALUATION CRITERIA (In order of priority)\n"
        "1. **Structural Isomorphism (The 'Pattern Match' Rule)**:\n"
        "   - If Source uses `switch` -> The candidate with `switch` wins (even if the other looks cleaner).\n"
        "   - If Source uses `for` -> The candidate with `for` wins against `while`.\n"
        "   - **Crucial**: You are judging fidelity to the *type* of control flow (Loop vs Jump vs Branch).\n"
        "2. **Complexity Handling**:\n"
        "   - If Source is flat but Candidate A adds fake nesting `{ { } }`, Candidate B (flat) wins.\n"
        "   - If Source has `goto` (e.g., error handling) and Candidate A keeps `goto` while B tries to turn it into a confused `do-while`, **A wins**. Accuracy > Prettiness.\n"
        "3. **Noise Reduction**:\n"
        "   - If both match the structure, pick the one with fewer artificial wrapper blocks or empty statements.\n\n"

        "### FORCED DECISION RULES\n"
        "- **Accuracy First**: Even if the Source code is ugly (e.g., uses `goto`), the candidate that correctly faithfully reproduces that ugliness is the winner over a candidate that hallucinates a 'clean' structure that doesn't exist.\n"
        "- **Tie-Breaker**: If both are structurally equidistant from Source, pick the one with less nesting depth.\n\n"

        "### INPUT DATA\n"
        f"--- GROUND TRUTH (SOURCE AST) ---\n{source_ast}\n\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "diff_analysis": "Identify the specific structure where A and B diverge (e.g., \'Source has a switch. A recovered it, B used if-else\').",\n'
        '  "motivation": "Explain why the winner is structurally closer to the Source intent.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )


def get_quality_prompt(code_a, code_b):
    return (
        "You are a Lead C Control Flow Architect performing a blind review of two decompiled functions.\n"
        "Your goal is to select the candidate with the superior **Control Flow Graph (CFG)** and **Expression Logic**.\n"
        "**CRITICAL RULE**: IGNORE variable names (e.g., `iVar1`, `uVar3`, `param_1`). Focus ONLY on the code structure, logic flow, and data access patterns.\n\n"

        "### CORE PHILOSOPHY: Structural Human-Likeness\n"
        "Ask yourself: *Which version represents the logic like a human developer (High-Level AST), and which looks like a machine state-machine (Low-Level CFG)?*\n"
        "- **Winner (Human-Like)**: Uses `for`, `switch`, `do-while`, explicit struct access (`ptr->field`), and standard boolean logic (`&&`, `||`).\n"
        "- **Loser (Machine-Like)**: Uses `goto`, `label:`, infinite loops with conditional breaks, cascaded `if-else` chains instead of `switch`, or raw pointer arithmetic (`*(ptr + 4)`).\n\n"

        "### SPECIFIC STRUCTURAL RED FLAGS (Focus on Logic, NOT Names)\n"
        "1. **Control Flow Degradation**:\n"
        "   - *Loser*: `if (cond) goto label; ... label:` (Spaghetti logic).\n"
        "   - *Winner*: `while (cond) { ... }` (Structured loop).\n"
        "2. **Obfuscated Loop Conditions**:\n"
        "   - *Loser*: `for(i=x; ptr != (*((_QWORD *) (i + 64))); ...)` (Pointer math in loop condition).\n"
        "   - *Winner*: `while (curr->next != end_obj)` (Clean logical comparison).\n"
        "3. **Data Access Patterns (Structs vs Offsets)**:\n"
        "   - *Loser*: `*(int*)(ptr + 8) = 5;` (Raw memory offset - Low level).\n"
        "   - *Winner*: `ptr->field = 5;` (Struct member access - High level).\n"
        "4. **Expression Inflation**:\n"
        "   - *Loser*: `if ((x & 1) != 0)` (Verbose).\n"
        "   - *Winner*: `if (x % 2)` (Idiomatic).\n\n"

        "### EVALUATION CRITERIA (In order of priority)\n"
        "1. **Control Flow Hygiene** (Critical): Prefer `for`/`switch`. Heavily penalize `goto` and manual jumps.\n"
        "2. **Nesting & Scope**: Penalize deep nesting (`if { if { ... } }`) that can be flattened with early returns (`if (!cond) return;`).\n"
        "3. **Type Logic**: Penalize unnecessary casts on literals (e.g., `(long long)\"string\"`).\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You CANNOT return null.\n"
        "- **Ignore Naming**: Do not penalize `uVar1` vs `counter`. Judge only *how* the variable is used in the control flow.\n"
        "- **Tie-Breaker**: If similar, pick the one with fewer `goto` statements and fewer explicit casts.\n\n"

        "### INPUT DATA\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Analyze the control flow topology internally. Then, output ONLY the following JSON structure:\n"
        "{\n"
        '  "motivation": "One sentence explanation focusing on structural differences (e.g., \'A recovered a clean switch-case structure, while B used an if-else cascade with gotos\').",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )

def get_ast_prompt(ast_a, ast_b):
    return (
        "You are a Lead Static Analysis Expert evaluating two decompiled Control Flow Skeletons (AST).\n"
        "Your goal is to select the candidate that represents the most **idiomatic and human-like structural design**.\n"
        "You do not have the source AST. You must judge based on **Software Engineering Standards** applied to the differences.\n\n"

        "### DIFFERENTIAL ANALYSIS STRATEGY (CRITICAL)\n"
        "1. **Scan**: Look at both ASTs. 90% of the structure might be identical.\n"
        "2. **Isolate the Delta**: Identify ONLY the nodes where A and B differ (e.g., A has a `switch`, B has `if-else`; or A has `goto`, B has `while`).\n"
        "3. **Judge the Delta**: Evaluate ONLY the differing part using the hierarchy below. Ignore the identical parts.\n\n"

        "### EVALUATION HIERARCHY (Apply strictly to the difference)\n"
        "1. **Abstraction Level (The 'High-Level' Rule)**:\n"
        "   - **Winner**: Uses semantic structures (`for`, `switch`, `do-while`).\n"
        "   - **Loser**: Uses mechanical artifacts (`while(true) + break`, `if-else` chains for enums, `goto`).\n"
        "2. **Control Flow Hygiene (The 'Goto' Penalty)**:\n"
        "   - If the difference is that one uses `goto`/`label` and the other uses a structured loop/break, the structured one WINS.\n"
        "   - Exception: If the structured version requires excessive nesting (>4 levels) to avoid a single goto, the goto might be acceptable (but rare).\n"
        "3. **Nesting & Scope**:\n"
        "   - Penalize **Redundant Blocks**: `{ { code } }` vs `{ code }`. The flatter one wins.\n"
        "   - Penalize **Arrow Code**: Deeply nested `if`s are worse than early returns or logical operators (`&&`).\n\n"

        "### FORCED DECISION RULES\n"
        "- **NO NEUTRALITY**: You must pick a winner.\n"
        "- **Tie-Breaker**: If logic is similar, choose the AST with fewer lines and fewer scopes `{}`.\n\n"

        "### INPUT DATA\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output ONLY valid JSON:\n"
        "{\n"
        '  "diff_analysis": "Briefly describe the specific structural difference (e.g., \'A used a for-loop at depth 2, B used a while-loop with manual increment\').",\n'
        '  "motivation": "Why the winner is more human-like based on that difference.",\n'
        '  "winner": "A" | "B"\n'
        "}"
    )