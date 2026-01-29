import os
import json
import subprocess
from utils.const import OUTPUT_DIR, MODELS_TO_BENCHMARK, BINARIES_DIR
from utils.ghidra import setup_ghidra_version, extract_decompilation
from utils.llm import evaluate_with_llm
from utils.com import fetch_decompiler_prs, get_models


def main(prs_number=None):
    # pr_number = "8635"#"8718"#"8718"
    print("[START] Starting main process")

    base_headless = setup_ghidra_version("master")

    test_binary_name = None
    for item in os.listdir(BINARIES_DIR):
        if os.path.isfile(os.path.join(BINARIES_DIR, item)) and not item.startswith('.'):
            test_binary_name = item
            break

    if test_binary_name:
        base_json_path = os.path.join(
            OUTPUT_DIR, "decomp", f"{test_binary_name}_base.json")
        if os.path.exists(base_json_path):
            print(f"[SKIP] Base already processed. Skipping...")
        else:
            extract_decompilation(base_headless, "base")
    else:
        print("[FATAL] No binary found in BINARIES_DIR.")
        return

    final_report = []
    base_metrics_cache = {}
    for i, pr_number in enumerate(prs_number):
        print("Timestamp: ", subprocess.getoutput("date"))
        print(f"[PROCESSING] PR #{pr_number}")
        print(f"[PROCESSING] Starting PR #{pr_number}")

        # Check if PR has already been processed
        pr_json_path = os.path.join(
            OUTPUT_DIR, "decomp", f"{test_binary_name}_pr_{pr_number}.json")
        if os.path.exists(pr_json_path):
            print(f"[SKIP] PR #{pr_number} already processed. Skipping...")
        else:
            continue
        # TODO: enable again
            # try:
            #     pr_headless = setup_ghidra_version(pr_number, is_pr=True)
            #     extract_decompilation(pr_headless, f"pr_{pr_number}")
            # except Exception as e:
            #     print(f"[ERROR] {e}")
            #     # if not i == len(prs_number) - 1: i dont remember why i put this
            #     continue

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
        test_binary_name = None
        results = {model_id: [] for model_id in MODELS_TO_BENCHMARK}
        try:
            for model_id in MODELS_TO_BENCHMARK:
                for item in os.listdir(BINARIES_DIR):
                    if os.path.isfile(os.path.join(BINARIES_DIR, item)) and not item.startswith('.'):
                        test_binary_name = item
                        base_json_path = os.path.join(
                            OUTPUT_DIR, "decomp", f"{test_binary_name}_base.json")
                        pr_json_path = os.path.join(
                            OUTPUT_DIR, "decomp", f"{test_binary_name}_pr_{pr_number}.json")

                        if not os.path.exists(base_json_path) or not os.path.exists(pr_json_path):
                            print(
                                f"[SKIP] Base or PR decompilation JSON not found, skipping for {test_binary_name} - {pr_number}.")
                            continue

                        with open(base_json_path, 'r') as f:
                            base_data = json.load(f)
                        with open(pr_json_path, 'r') as f:
                            pr_data = json.load(f)

                        results[model_id].extend(evaluate_with_llm(
                            base_data, pr_data, model_id, test_binary_name, base_metrics_cache))

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
        print(
            f"[FINAL RESULT] Overall improvement across all prs: {'YES' if mean_delta < 0 else 'NO' if mean_delta > 0 else 'NO CHANGE'}")

        print(f"[PROCESSING] Finished model {model_id}")

        rep = {
            "pr": pr_number,
            "mean_delta_perplexity": mean_delta,
            "mean_perplexity_base": mean_perplexity_base,
            "mean_perplexity_pr": mean_perplexity_pr,
            "results": results
        }
        final_report.append(rep)
        with open(os.path.join(OUTPUT_DIR, "reports", f"{pr_number}.json"), "w") as f:
            json.dump(rep, f, indent=2)

    with open(os.path.join(OUTPUT_DIR, "final_report.json"), "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"[END] Timestamp: {subprocess.getoutput('date')}")
    print("[END] Finished all processing")


if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    MODELS_TO_BENCHMARK = get_models()

    main(fetch_decompiler_prs())
