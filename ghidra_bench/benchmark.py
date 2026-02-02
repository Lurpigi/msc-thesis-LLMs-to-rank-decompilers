import os
import json
import subprocess
from utils.const import MAX_SAMPLES, OUTPUT_DIR, MODELS_TO_BENCHMARK, BINARIES_DIR
from utils.ghidra import setup_ghidra_version, extract_decompilation
from utils.llm import evaluate_with_llm, free_llm_model
from utils.com import fetch_decompiler_prs, get_models, get_cc


def already_processed(file, n_pr=None, is_pr=False):
    json_path = os.path.join(
        OUTPUT_DIR, "decomp", f"{file}_pr_{n_pr}.json") if is_pr else os.path.join(OUTPUT_DIR, "decomp", f"{file}_base.json")
    return os.path.exists(json_path)


def main(prs_number=None):
    # pr_number = "8635"#"8718"#"8718"

    print("Prs to process:", prs_number)
    print("[START] Starting main process")

    base_headless = setup_ghidra_version("master")

    test_binary_name = []
    for item in os.listdir(BINARIES_DIR):
        if os.path.isfile(os.path.join(BINARIES_DIR, item)) and not item.startswith('.'):
            if not already_processed(item):
                test_binary_name.append(item)

    if len(test_binary_name) > 0:
        extract_decompilation(base_headless, "base", test_binary_name)
    else:
        print(f"[SKIP] Base already processed. Skipping...")

    final_report = []
    metrics_cache = {}
    for i, pr_number in enumerate(prs_number):
        test_binary_name = []
        print("Timestamp: ", subprocess.getoutput("date"))
        print(f"[PROCESSING] PR #{pr_number}")
        print(f"[PROCESSING] Starting PR #{pr_number}")

        # Check if PR has already been processed
        for item in os.listdir(BINARIES_DIR):
            if os.path.isfile(os.path.join(BINARIES_DIR, item)) and not item.startswith('.'):
                if not already_processed(item, pr_number, True):
                    test_binary_name.append(item)

        if len(test_binary_name) == 0:
            print(f"[SKIP] PR #{pr_number} already processed. Skipping...")
        else:
            try:
                pr_headless = setup_ghidra_version(pr_number, True)
                extract_decompilation(
                    pr_headless, f"pr_{pr_number}", test_binary_name)
            except Exception as e:
                print(f"[ERROR] {e}")
                continue

        pr_report_path = os.path.join(
            OUTPUT_DIR, "reports", f"{pr_number}.json")
        if os.path.exists(pr_report_path):
            print(f"[SKIP] PR #{pr_number} already has a report. Skipping...")
            try:
                with open(pr_report_path, 'r') as f:
                    final_report.append(json.load(f))
            except json.JSONDecodeError:
                print(
                    f"[WARNING] Report for PR #{pr_number} was empty or corrupted. Re-processing might be needed.")
            continue
        results = {model_id: [] for model_id in MODELS_TO_BENCHMARK}
        try:
            bin_cc = []
            for bin in os.listdir(BINARIES_DIR):
                if os.path.isfile(os.path.join(BINARIES_DIR, bin)) and not bin.startswith('.'):
                    base_json_path = os.path.join(
                        OUTPUT_DIR, "decomp", f"{bin}_base.json")
                    pr_json_path = os.path.join(
                        OUTPUT_DIR, "decomp", f"{bin}_pr_{pr_number}.json")

                    if not os.path.exists(base_json_path) or not os.path.exists(pr_json_path):
                        print(
                            f"[SKIP] Base or PR decompilation JSON not found, skipping for {bin} - {pr_number}.")
                        continue

                    with open(base_json_path, 'r') as f:
                        base_data = json.load(f)
                    with open(pr_json_path, 'r') as f:
                        pr_data = json.load(f)

                    for func_name in base_data.keys():
                        if func_name in pr_data:
                            base_code = base_data[func_name]
                            pr_code = pr_data[func_name]
                            if base_code == None or pr_code == None:
                                # should not happen
                                raise ValueError("Decompiled code is None")
                            if base_code != pr_code:
                                bin_cc.append(
                                    (bin, (base_code, pr_code), get_cc(pr_code)))
                                break  # only one func

            print(
                f"[INFO] Total binaries with changes in PR #{pr_number}: {len(bin_cc)}")
            bin_cc.sort(key=lambda x: x[2], reverse=True)

            bin_cc = bin_cc[:MAX_SAMPLES]

            for model_id in MODELS_TO_BENCHMARK:
                for bin, (base_code, pr_code), _ in bin_cc:
                    print(
                        f"[PROCESSING] Evaluating PR #{pr_number} on binary {bin} with model {model_id}...")

                    results[model_id].extend(evaluate_with_llm(
                        base_code, pr_code, model_id, bin, metrics_cache))

        except Exception as e:
            print(f"[FATAL] {e}.")
            return

        # mean results
        mean_delta = sum(entry['metrics']['delta_ppl'] for entry in results[model_id]
                         ) / len(results[model_id]) if results[model_id] else 0
        mean_perplexity_base = sum(entry['metrics']['base_ppl'] for entry in results[model_id]
                                   ) / len(results[model_id]) if results[model_id] else 0
        mean_perplexity_pr = sum(entry['metrics']['pr_ppl'] for entry in results[model_id]
                                 ) / len(results[model_id]) if results[model_id] else 0
        mean_perplexity_source = sum(entry['metrics']['source_ppl'] for entry in results[model_id]
                                    ) / len(results[model_id]) if results[model_id] else 0
        mean_perplexity_base_ast = sum(entry['metrics']['base_ast_ppl'] for entry in results[model_id]
                                       ) / len(results[model_id]) if results[model_id] else 0
        mean_perplexity_source_ast = sum(entry['metrics']['source_ast_ppl'] for entry in results[model_id]
                                         ) / len(results[model_id]) if results[model_id] else 0
        mean_perplexity_pr_ast = sum(entry['metrics']['pr_ast_ppl'] for entry in results[model_id]
                                     ) / len(results[model_id]) if results[model_id] else 0

        print(
            f"[FINAL RESULT] Overall improvement: {'YES' if mean_delta < 0 else 'NO' if mean_delta > 0 else 'NO CHANGE'}")

        print(f"[PROCESSING] Finished model {model_id}")

        rep = {
            "pr": pr_number,
            "mean_delta_perplexity": mean_delta,
            "mean_perplexity_base": mean_perplexity_base,
            "mean_perplexity_pr": mean_perplexity_pr,
            "mean_perplexity_source": mean_perplexity_source,
            "mean_perplexity_base_ast": mean_perplexity_base_ast,
            "mean_perplexity_pr_ast": mean_perplexity_pr_ast,
            "mean_perplexity_source_ast": mean_perplexity_source_ast,
            "results": results
        }
        final_report.append(rep)
        with open(os.path.join(OUTPUT_DIR, "reports", f"{pr_number}.json"), "w") as f:
            json.dump(rep, f, indent=2)

    with open(os.path.join(OUTPUT_DIR, "final_report.json"), "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"[END] Timestamp: {subprocess.getoutput('date')}")
    print("[END] Finished all processing")
    free_llm_model()


if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    MODELS_TO_BENCHMARK = get_models()

    main(fetch_decompiler_prs())  # PR study
