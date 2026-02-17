import difflib
import requests
import json
import re
from .com import get_ast, get_func_name, get_source_code
from .prompt import get_ast_prompt_s, get_quality_prompt, get_ast_prompt, get_quality_prompt_s
from .const import LLM_API_FREE, LLM_API_GEN, LLM_API_SCORE, LLM_API_LOSS


def get_code_metrics(code_snippet, model_id):
    """Calls the /score endpoint to obtain raw perplexity of the code)"""
    try:
        resp = requests.post(LLM_API_SCORE, json={
                             "text": code_snippet, "model_id": model_id})
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[WARN] Score API error: {resp.status_code}")
            return {"perplexity": -1, "mean_logbits": 0}
    except Exception as e:
        print(f"[ERR] Failed to get metrics: {e}")
        return {"perplexity": -1, "mean_logbits": 0}

def get_loss_tokens(code_snippet, model_id):
    try:
        resp = requests.post(LLM_API_LOSS, json={
                             "text": code_snippet, "model_id": model_id, "return_tokens": True})
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[WARN] Score API error: {resp.status_code}")
            return {"tokens": [], "losses": []}
    except Exception as e:
        print(f"[ERR] Failed to get token loss data: {e}")
        return {"tokens": [], "losses": []}

def get_diff_text(text_a, text_b, context_lines=3):

    a_lines = text_a.splitlines()
    b_lines = text_b.splitlines()

    diff = difflib.unified_diff(
        a_lines,
        b_lines,
        fromfile='Candidate A',
        tofile='Candidate B',
        n=context_lines,
        lineterm=''
    )

    diff_str = "\n".join(diff)

    return diff_str


def get_llm_analysis(base_code, pr_code, model_id, source=None, is_ast=False):
    """Call the LLM to get analysis"""

    if source is not None and base_code == pr_code:
        return {
            "winner": "NO DIFFERENCE",
            "motivation": "BASE and PR AST are identical; no differences to evaluate."
        }

    diff_content = get_diff_text(base_code, pr_code)

    prompt = (get_ast_prompt(diff_content) if source is None else get_ast_prompt_s(
        diff_content, source)) if is_ast else (get_quality_prompt_s(diff_content, source) if source is not None else get_quality_prompt(diff_content))

    try:
        resp = requests.post(LLM_API_GEN, json={
                             "prompt": prompt, "model_id": model_id})

        if resp.status_code == 200:
            result = resp.json()

            generated_text = result.get("response", "")

            match = re.search(
                r'\{\s*"(?:winner|motivation)"\s*:.*\}', generated_text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            else:
                winner_match = re.search(
                    r'"winner"\s*:\s*"([^"]+)"', generated_text, re.IGNORECASE | re.DOTALL)
                motivation_match = re.search(
                    r'"motivation"\s*:\s*"([^"]+)"', generated_text, re.IGNORECASE | re.DOTALL)
                if winner_match and motivation_match:
                    return {
                        "winner": winner_match.group(1),
                        "motivation": motivation_match.group(1),
                        "raw_response": generated_text
                    }
                return {"winner": "Error", "motivation": generated_text, "raw_response": generated_text}
        else:
            return {"error": f"API Error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def get_or_compute_metric(code, func_name, model_id, binary_name, tag, cache):
    cache_key = (func_name, model_id, binary_name, tag)

    if cache_key in cache:
        # print(f"[CACHE] Using cached {tag} metrics for {func_name}")
        return cache[cache_key]

    print(f"Computing {tag} metrics for {func_name}")
    metrics = get_code_metrics(code, model_id=model_id)
    cache[cache_key] = metrics
    print(f"Finished {tag} metrics for {func_name}")
    return metrics


def run_judge_with_bias_check(content_base, content_pr, model_id, source_content=None, is_ast=False):
    analysis = get_llm_analysis(
        content_base, content_pr, model_id=model_id, source=source_content, is_ast=is_ast
    )
    winner = analysis.get("winner", "Error")
    if winner == "Error":
        return analysis

    print("checking bias...")

    analysis_swap = get_llm_analysis(
        content_pr, content_base, model_id=model_id, source=source_content, is_ast=is_ast
    )
    winner_swap = analysis_swap.get("winner", "Error")

    if winner_swap not in ("A", "B"):
        return {
            "winner": "TIE",
            "motivation": "Could not detect potential bias in LLM response declaring TIE.",
            "raw_response": analysis_swap.get("raw_response", "")
        }

    if winner != winner_swap:
        final_winner = "BASE" if winner == "A" else "PR" if winner == "B" else "Error"
        analysis["winner"] = final_winner
        return analysis
    else:
        return {
            "winner": "TIE",
            "motivation": f"Detected potential bias in LLM response (Position Bias); declaring TIE. the LLM gave {'BASE' if winner == 'A' else 'PR' if winner == 'B' else 'Error'} in both original and swapped prompts.",
            "raw_response1": analysis.get("raw_response", ""),
            "raw_response2": analysis_swap.get("raw_response", "")
        }


def evaluate_with_llm(base_code, pr_code, model_id, test_binary_name, metrics_cache):
    """Creates the prompt, calculates metrics, and calls the Flask server"""
    report = []

    func_name = get_func_name(test_binary_name)
    print(
        f"[EVAL] Starting LLM-based evaluation with model {model_id} for {func_name}")

    source_code = get_source_code(test_binary_name)
    source_ast = get_ast(source_code)
    base_ast = get_ast(base_code)
    pr_ast = get_ast(pr_code)

    base_metrics = get_or_compute_metric(
        base_code, func_name, model_id, test_binary_name, "base", metrics_cache
    )

    source_metrics = get_or_compute_metric(
        source_code, func_name, model_id, test_binary_name, "source", metrics_cache
    )

    base_ast_metrics = get_or_compute_metric(
        base_ast, func_name, model_id, test_binary_name, "base_ast", metrics_cache
    )

    source_ast_metrics = get_or_compute_metric(
        source_ast, func_name, model_id, test_binary_name, "source_ast", metrics_cache
    )

    print(f"Computing metrics for PR - {func_name}")
    pr_metrics = get_code_metrics(pr_code, model_id=model_id)
    pr_ast_metrics = get_code_metrics(pr_ast, model_id=model_id)

    ppl_delta = pr_metrics['perplexity'] - base_metrics['perplexity']
    print(f"Finished quantitative metrics for {func_name}")

    print(f"Getting AST analysis with source context for {func_name}")
    ast_analysis_s = run_judge_with_bias_check(
        base_ast, pr_ast, model_id, source_content=source_ast, is_ast=True
    )
    print(
        f"Winner of AST analysis with source context for {func_name}: {ast_analysis_s.get('winner', 'Error')}")

    print(f"Getting Blind AST analysis for {func_name}")
    ast_analysis = run_judge_with_bias_check(
        base_ast, pr_ast, model_id, source_content=None, is_ast=True
    )
    print(
        f"Winner of Blind AST analysis for {func_name}: {ast_analysis.get('winner', 'Error')}")

    print(f"Getting Blind Quality analysis for {func_name}")
    qualitative_analysis = run_judge_with_bias_check(
        base_code, pr_code, model_id, source_content=None, is_ast=False
    )
    print(
        f"Winner of Blind Quality analysis for {func_name}: {qualitative_analysis.get('winner', 'Error')}")

    print(f"Getting Quality analysis with source context for {func_name}")
    qualitative_analysis_s = run_judge_with_bias_check(
        base_code, pr_code, model_id, source_content=source_code, is_ast=False
    )
    print(
        f"Winner of Quality analysis with source context for {func_name}: {qualitative_analysis_s.get('winner', 'Error')}")

    print(f"Finished AST analysis for {func_name}")

    print(f"starting loss token analysis for {func_name}")
    source_loss = get_loss_tokens(source_code, model_id)
    function_base_loss = get_loss_tokens(base_code, model_id)
    function_pr_loss = get_loss_tokens(pr_code, model_id)
    source_ast_loss = get_loss_tokens(source_ast, model_id)
    base_ast_loss = get_loss_tokens(base_ast, model_id)
    pr_ast_loss = get_loss_tokens(pr_ast, model_id)

    entry = {
        "binary": test_binary_name,
        "function": func_name,
        "source_code": source_code,
        "function_base": base_code,
        "function_pr": pr_code,
        "source_ast": source_ast,
        "base_ast": base_ast,
        "pr_ast": pr_ast,
        "metrics": {
            "source_ppl": source_metrics['perplexity'],
            "base_ppl": base_metrics['perplexity'],
            "pr_ppl": pr_metrics['perplexity'],
            "source_ast_ppl": source_ast_metrics['perplexity'],
            "base_ast_ppl": base_ast_metrics['perplexity'],
            "pr_ast_ppl": pr_ast_metrics['perplexity'],
            "delta_ppl": ppl_delta,
            "source_loss": source_loss,
            "function_base_loss": function_base_loss,
            "function_pr_loss": function_pr_loss,
            "source_ast_loss": source_ast_loss,
            "base_ast_loss": base_ast_loss,
            "pr_ast_loss": pr_ast_loss
        },
        "llm_qualitative": qualitative_analysis,
        "llm_qualitative_source": qualitative_analysis_s,
        "llm_ast": ast_analysis,
        "llm_ast_source": ast_analysis_s
    }

    improvement = "PR" if ppl_delta < 0 else (
        "Base" if ppl_delta > 0 else "No Change")
    print(
        f"   > PPL Summary | Base: {base_metrics['perplexity']:.2f} -> PR: {pr_metrics['perplexity']:.2f} | Delta: {ppl_delta:.2f}")
    print(f"   > Quantitative Winner: {improvement}")

    report.append(entry)
    print(f"[EVAL] Completed evaluation for {func_name}")

    return report


def free_llm_model():
    """Calls the /free endpoint to unload the model from memory"""
    try:
        resp = requests.post(LLM_API_FREE)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[WARN] Free API error: {resp.status_code}")
            return {"status": "error"}
    except Exception as e:
        print(f"[ERR] Failed to free model: {e}")
        return {"status": "error"}
