def get_quality_prompt(source_code, code_a, code_b):
    return (
        "You are a Lead Compiler Engineer and C Code Auditor specializing in Decompilation correctness.\n"
        "Your goal is to evaluate two anonymous decompiled versions ('Candidate A' and 'Candidate B') "
        "against the original 'Ground Truth' Source Code.\n\n"

        "### TASK & BIAS WARNING\n"
        "1. **Neutrality**: Candidate A and Candidate B are from different tools. Do not assume one is the 'original' or 'improved' version.\n"
        "2. **Ground Truth is King**: Readability is important, but semantic equivalence to the Source Code is the primary requirement. A readable hallucination is a failure.\n"
        "3. **Chain of Verification**: You must verify the control flow of each candidate against the source before deciding.\n\n"

        "### EVALUATION CRITERIA\n"
        "- **Structural Fidelity**: Does the candidate recover the exact loop types (`for` vs `while`) and conditional nesting of the Source? \n"
        "- **Expression Logic**: Are the arithmetic and pointer operations semantically identical to the Source? Penalize raw casts that obscure the original logic.\n"
        "- **Readability vs. Accuracy**: If both are accurate, prefer the one using standard C idioms. If one is accurate but ugly, and the other is readable but wrong, the accurate one wins.\n"
        "- **Dead Code**: Penalize variables or assignments not present in the Source.\n\n"

        "### INPUT DATA\n"
        "--- GROUND TRUTH (ORIGINAL SOURCE) ---\n"
        f"```c\n{source_code}\n```\n\n"
        "--- CANDIDATE A ---\n"
        f"```c\n{code_a}\n```\n\n"
        "--- CANDIDATE B ---\n"
        f"```c\n{code_b}\n```\n\n"

        "### OUTPUT FORMAT\n"
        "Perform a Chain of Verification analysis internally, then output only strictly valid JSON:\n"
        "{\n"
        '  "verification_analysis": {\n'
        '       "source_structure": "Brief summary of key loops/switch in source",\n'
        '       "candidate_a_discrepancies": "List structural deviations from source found in A",\n'
        '       "candidate_b_discrepancies": "List structural deviations from source found in B"\n'
        '   },\n'
        '  "winner": "A" | "B" | "TIE",\n'
        '  "motivation": "Concise conclusion based on the verification steps."\n'
        "}"
    )

def get_ast_prompt(ast_a, ast_b, source_ast):
    return (
        "You are a Static Analysis Expert specializing in Abstract Syntax Tree comparison.\n"
        "Your task is to determine which of two Control Flow Skeletons better preserves the topological structure of the Original Source.\n\n"

        "### INSTRUCTIONS\n"
        "You are comparing abstract structural representations (AST skeletons) stripped of variable names.\n"
        "1. **Identify the Target**: The 'SOURCE AST' is the ground truth.\n"
        "2. **Verify Candidates**: Compare 'Candidate A' and 'Candidate B' against the Source.\n"
        "3. **Ignore Identifiers**: Focus purely on the shape of the tree (nesting, node types, sequence).\n\n"

        "### CHAIN OF VERIFICATION STEPS\n"
        "Before choosing a winner, perform these checks:\n"
        "1. **Loop Integrity Check**: Count the loops in Source. Do A and B match the count and type (e.g., `for` vs `while`)?\n"
        "2. **Nesting Depth Check**: Check the maximum indentation depth. If Source is deep, a flattened Candidate is incorrect. If Source is flat, a nested Candidate is incorrect.\n"
        "3. **Ghost Instruction Check**: Look for `goto` or `label` nodes in Candidates that do not exist in Source.\n\n"

        "### INPUT DATA\n"
        f"--- SOURCE AST (Ground Truth) ---\n{source_ast}\n\n"
        f"--- CANDIDATE A ---\n{ast_a}\n\n"
        f"--- CANDIDATE B ---\n{ast_b}\n\n"

        "### OUTPUT FORMAT\n"
        "Output strictly valid JSON:\n"
        "{\n"
        '  "verification_analysis": {\n'
        '       "loop_match": "Did A or B miss loops present in Source?",\n'
        '       "nesting_match": "Which candidate matches Source nesting depth better?",\n'
        '       "ghost_nodes": "Did any candidate invent gotos/labels?"\n'
        '   },\n'
        '  "winner": "A" | "B" | "TIE",\n'
        '  "motivation": "Concise conclusion based on the verification steps."\n'
        "}"
    )