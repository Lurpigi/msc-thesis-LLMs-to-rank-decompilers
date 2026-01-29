import requests
import json
import re
from .com import get_cc, get_ast
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


def evaluate_with_llm(base_data, pr_data, model_id, test_binary_name, base_metrics_cache, MAX_SAMPLES=10):
    """Creates the prompt, calculates metrics, and calls the Flask server"""
    report = []

    print("[EVAL] Starting LLM-based evaluation with model " + model_id)

    all_funcs = list(set(base_data.keys()) & set(pr_data.keys()))

    candidates = []

    print(
        f"[PRE-PROCESS] Analyzing complexity for {len(all_funcs)} functions...")

    for func_name in all_funcs:
        base_code = base_data[func_name]
        pr_code = pr_data[func_name]

        # Fast Skip
        if base_code == pr_code:
            continue

        complexity = get_cc(pr_code)
        # print("--------------------------------")
        # print(pr_code)
        # print(get_ast(pr_code))
        candidates.append((func_name, complexity))

    print(
        f"[PRE-PROCESS] Calculated complexity for all changed functions.")
    candidates.sort(key=lambda x: x[1], reverse=True)

    top_candidates = candidates[:MAX_SAMPLES]

    print(
        f"[PRE-PROCESS] Selected top {len(top_candidates)} functions with highest complexity (Max CCN: {top_candidates[0][1] if top_candidates else 0})")

    print("number of 0 complexity functions: ", len(
        [1 for _, ccn in top_candidates if ccn == 0]))
    print("total functions: ", len(candidates))

    for func_name, ccn_score in top_candidates:

        base_code = base_data[func_name]
        pr_code = pr_data[func_name]

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

        entry = {
            "binary": test_binary_name,
            "function": func_name,
            "metrics": {
                "base_ppl": base_metrics['perplexity'],
                "pr_ppl": pr_metrics['perplexity'],
                # < 0 means PR improved (lowered) perplexity
                "delta_ppl": ppl_delta,
            },
            "llm_analysis": [qualitative_analysis]  # ,ast_analysis
        }

        print(
            f"   > PPL Base: {base_metrics['perplexity']:.2f} | PPL PR: {pr_metrics['perplexity']:.2f} | Delta: {ppl_delta:.2f}")
        print(
            f"   > Better version: {'PR' if ppl_delta < 0 else 'Base' if ppl_delta > 0 else 'No Change'}")

        report.append(entry)
        print(f"[EVAL] Evaluated change in {func_name}")

    return report
