import requests
import json
import re
from .com import get_ast, get_func_name, get_source_code
from .prompt import get_quality_prompt, get_ast_prompt
from .const import LLM_API_GEN, LLM_API_SCORE


def get_code_metrics(code_snippet, model_id):
    """Calls the /score endpoint to obtain raw perplexity of the code)"""
    try:
        resp = requests.post(LLM_API_SCORE, json={
                             "text": code_snippet, "model_id": model_id}, timeout=300)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[WARN] Score API error: {resp.status_code}")
            return {"perplexity": -1, "mean_logbits": 0}
    except Exception as e:
        print(f"[ERR] Failed to get metrics: {e}")
        return {"perplexity": -1, "mean_logbits": 0}


def get_llm_analysis(base_code, pr_code, model_id, source=None):
    """Call the LLM to get analysis"""

    if source is not None and base_code == pr_code:
        return {
            "winner": "TIE",
            "motivation": "BASE and PR AST are identical; no differences to evaluate."
        }

    prompt = get_quality_prompt(base_code, pr_code) if source is None else get_ast_prompt(
        base_code, pr_code, source)

    try:
        resp = requests.post(LLM_API_GEN, json={
                             "prompt": prompt, "model_id": model_id})

        if resp.status_code == 200:
            result = resp.json()

            generated_text = result.get("response", "")
            try:
                match = re.search(
                    r'\{\s*"(?:winner|motivation)"\s*:.*\}', generated_text, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
                return {"winner": "Unknown", "motivation": generated_text}
            except:
                return {"winner": "Error", "motivation": generated_text}
        else:
            return {"error": f"API Error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def evaluate_with_llm(base_code, pr_code, model_id, test_binary_name, base_metrics_cache):
    """Creates the prompt, calculates metrics, and calls the Flask server"""
    report = []

    print("[EVAL] Starting LLM-based evaluation with model " + model_id)

    func_name = get_func_name(test_binary_name)

    print(f"[EVAL] Evaluating change in {func_name}")

    cache_key = (func_name, model_id, test_binary_name)
    if cache_key in base_metrics_cache:
        base_metrics = base_metrics_cache[cache_key]
        # print(f"[CACHE] Using cached metrics for {func_name}")
    else:
        print(f"Computing base metrics for {func_name}")
        base_metrics = get_code_metrics(base_code, model_id=model_id)
        base_metrics_cache[cache_key] = base_metrics
        print(f"Finished base metrics for {func_name}")

    print(f"Computing metrics for PR - {func_name}")
    pr_metrics = get_code_metrics(pr_code, model_id=model_id)

    print(f"Finished metrics for {func_name}")

    ppl_delta = pr_metrics['perplexity'] - base_metrics['perplexity']

    print(f"Getting qualitative analysis for {func_name}")
    qualitative_analysis = get_llm_analysis(
        base_code, pr_code, model_id=model_id)
    print(f"Finished qualitative analysis for {func_name}")
    print(f"Getting AST analysis for {func_name}")
    ast_analysis = get_llm_analysis(
        get_ast(base_code), get_ast(pr_code), model_id=model_id, source=get_ast(get_source_code(test_binary_name)))
    print(f"Finished AST analysis for {func_name}")
    entry = {
        "binary": test_binary_name,
        "function": func_name,
        "metrics": {
            "base_ppl": base_metrics['perplexity'],
            "pr_ppl": pr_metrics['perplexity'],
            # < 0 means PR improved (lowered) perplexity
            "delta_ppl": ppl_delta,
        },
        "llm_qualitative": qualitative_analysis,
        "llm_ast": ast_analysis
    }

    print(
        f"   > PPL Base: {base_metrics['perplexity']:.2f} | PPL PR: {pr_metrics['perplexity']:.2f} | Delta: {ppl_delta:.2f}")
    print(
        f"   > Better version: {'PR' if ppl_delta < 0 else 'Base' if ppl_delta > 0 else 'No Change'}")

    report.append(entry)
    print(f"[EVAL] Evaluated change in {func_name}")

    return report
