import os
import random
import subprocess
import requests
import concurrent.futures
import shutil
import json
import sys
import re
import lizard
import random

# CONFIGURATION
GHIDRA_REPO = "https://github.com/NationalSecurityAgency/ghidra"
GHIDRA_REPO_DIR = os.environ.get("GHIDRA_GIT_PATH")  # "/opt/ghidra_src"
GHIDRA_EXTRACTED_DIR = os.environ.get(
    "GHIDRA_EXTRACTED_PATH")  # "/opt/ghidra_exe"
BINARIES_DIR = os.path.abspath("bin")
OUTPUT_DIR = os.path.abspath("outputs")
TARGET_FUNCTIONS = ["main", "test1", "test2", "test3", "test4"]
LLM_API_URL = os.environ.get("LLM_API_URL", "http://localhost:8900")
# LLM_API_GEN = f"{LLM_API_URL}/generate"
LLM_API_SCORE = f"{LLM_API_URL}/score"
MAX_WORKERS = int(os.environ.get("GHIDRA_WORKERS", 4))
GRADLE_INSTALL_ROOT = "/opt/gradle"
MODELS_TO_BENCHMARK = []


def print_time(info=""):
    print(f"{info} - : ", subprocess.getoutput("date"))
    with open(os.path.join(OUTPUT_DIR, "timestamps.log"), "a") as f:
        f.write(f"{info} - : " + subprocess.getoutput("date") + "\n")


def run_command(cmd, cwd=None, env=None, input_text=None):
    verbose = 0
    # subprocess.check_call(cmd, shell=True, cwd=cwd, env=env)
    if verbose:
        print(f"[CMD] Executing: {cmd}")
    sys.stdout.flush()

    process = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        env=env,
        input=input_text,
        stdout=subprocess.PIPE,    # Capture stdout and stderr as text
        stderr=subprocess.STDOUT,  # Merge stderr into stdout
        text=True                  # Decode bytes to string
    )

    if verbose:
        if process.stdout:
            print(process.stdout)

    if process.returncode != 0:
        print(f"[FATAL] Command failed with return code {process.returncode}")
        if not verbose and process.stdout:
            print(process.stdout)
        raise subprocess.CalledProcessError(process.returncode, cmd)


def get_ghidra_properties(repo_dir):
    """Reads application.properties to get Java and Gradle versions."""
    prop_path = os.path.join(repo_dir, "Ghidra", "application.properties")
    props = {
        "java": "17",  # Default fallback
        "gradle": "7.3"  # Default fallback
    }

    if not os.path.exists(prop_path):
        print(f"[WARN] {prop_path} not found. Using defaults.")
        return props

    try:
        with open(prop_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("application.java.min="):
                    props["java"] = line.split("=")[1].strip()
                elif line.startswith("application.gradle.min="):
                    props["gradle"] = line.split("=")[1].strip()
    except Exception as e:
        print(f"[ERR] Failed to read properties: {e}")

    return props


def ensure_gradle(gradle_version):
    """Ensures the specified Gradle version is installed and returns the path to the binary."""
    gradle_dir = os.path.join(GRADLE_INSTALL_ROOT, f"gradle-{gradle_version}")
    gradle_bin = os.path.join(gradle_dir, "bin", "gradle")

    if os.path.exists(gradle_bin):
        return gradle_bin

    print(f"[INFO] Installing Gradle {gradle_version}...")

    os.makedirs(GRADLE_INSTALL_ROOT, exist_ok=True)

    zip_name = f"gradle-{gradle_version}-bin.zip"
    url = f"https://services.gradle.org/distributions/{zip_name}"
    zip_path = os.path.join(GRADLE_INSTALL_ROOT, zip_name)

    run_command(f"wget -q {url} -O {zip_path}")
    run_command(f"unzip -q {zip_path} -d {GRADLE_INSTALL_ROOT}")

    return gradle_bin


def set_java_home(java_version):
    """Sets JAVA_HOME environment variable based on version."""
    java_dir = os.path.join(
        # overkill but its cool
        "/usr", "lib", "jvm", f"java-{java_version}-openjdk-amd64")
    print("[JAVA] Setting JAVA_HOME to", java_dir)
    if not os.path.exists(java_dir):
        try:
            run_command(
                f"apt-get update &&apt-get install -y openjdk-{java_version}-jdk", "/")
        except Exception as e:
            print(f"[ERR] Failed to install OpenJDK {java_version}: {e}")
            raise ValueError("Unsupported Java version")
    # check now if exists
    if not os.path.exists(java_dir):
        raise ValueError("ERROR DOWNLOADING JAVA")
    os.environ["JAVA_HOME"] = java_dir
    os.environ["PATH"] = os.environ["JAVA_HOME"] + \
        "/bin:" + os.environ["PATH"]


def setup_ghidra_version(tag_or_pr, is_pr=False):
    """Clones, checks out and builds Ghidra. Returns the path"""
    print_time(
        f"[SETUP] Setting up Ghidra for {'PR #' + tag_or_pr if is_pr else 'master'}")

    # check image for prebuilt master
    if tag_or_pr == "master" and not is_pr:
        prebuilt_path = os.environ.get("GHIDRA_EXTRACTED_PATH")
        if prebuilt_path and os.path.exists(prebuilt_path):
            print(
                f"[INFO] Using PRE-BUILT Ghidra Master found at {prebuilt_path}")
            # headless_path = os.path.join(prebuilt_path, "support", "analyzeHeadless")

            # if not os.access(headless_path, os.X_OK):
            #     run_command(f"chmod +x {headless_path}")

            # return headless_path
            print_time(f"[SETUP] Finished setting up Ghidra")
            return prebuilt_path

    cwd = GHIDRA_REPO_DIR

    run_command("rm -rf build/dist", cwd=cwd)

    if os.path.exists(GHIDRA_REPO_DIR):
        print(
            f"[INFO] Using pre-built Ghidra template from {GHIDRA_REPO_DIR}...")
    else:
        print("[WARN] Template not found. Falling back to slow git clone...")
        run_command(f"git clone {GHIDRA_REPO} .", cwd=cwd)

    # print("[GIT] Cleaning repository state...")
    # run_command("git reset --hard HEAD && git clean -fd -e build/ -e .gradle/", cwd=cwd)

    if is_pr:
        print(f"[GIT] Checking out PR #{tag_or_pr}...")
        run_command(
            f"git fetch origin pull/{tag_or_pr}/head:pr-{tag_or_pr}", cwd=cwd)
        run_command(f"git checkout pr-{tag_or_pr}", cwd=cwd)
    else:
        run_command(f"git checkout {tag_or_pr}", cwd=cwd)

    if os.path.exists(os.path.join(cwd, "gradlew")):
        print("[JAVA] Using Java 21 for modern Ghidra")
        set_java_home(21)
        gradle_cmd = "./gradlew"
    else:
        props = get_ghidra_properties(cwd)
        req_java = props["java"]
        req_gradle = props["gradle"]
        print(f"[JAVA] Using Java {req_java} for legacy Ghidra")
        set_java_home(req_java)
        gradle_cmd = ensure_gradle(req_gradle)

    print(f"[BUILD] Building Ghidra for {tag_or_pr} (this takes time)...")

    run_command(
        f"{gradle_cmd} -I gradle/support/fetchDependencies.gradle {'init' if gradle_cmd != './gradlew' else ''}", cwd=cwd)
    run_command(f"{gradle_cmd} buildGhidra --build-cache --no-daemon -x test -x integrationTest -x javadoc -x check -x ip -x createJavadocs -x createJsondocs -x zipJavadocs", cwd=cwd)

    dist_dir = os.path.join(cwd, "build", "dist")
    for f in os.listdir(dist_dir):
        if f.endswith(".zip"):
            print(f"[BUILD] Found build artifact: {f}")
            zip_path = os.path.join(dist_dir, f)

            # delete all files in extracted dir
            run_command(f"rm -rf \"{GHIDRA_EXTRACTED_DIR}/*\"", cwd="/")

            run_command(
                f"bsdtar -xf \"{zip_path}\" -s'|^ghidra_[^/]*/||' -C \"{GHIDRA_EXTRACTED_DIR}\"", cwd=dist_dir)

            # inner_folders = [d for d in os.listdir(GHIDRA_EXTRACTED_DIR) if os.path.isdir(
            #     os.path.join(GHIDRA_EXTRACTED_DIR, d))]
            # if not inner_folders:
            #     raise Exception(
            #         "Unzip successful but no folder found inside zip!")

            ghidra_folder = GHIDRA_EXTRACTED_DIR

            # headless = os.path.join(ghidra_folder, "support", "analyzeHeadless")
            # run_command(f"chmod +x {headless}")
            print_time(f"[SETUP] Finished setting up Ghidra")
            return ghidra_folder

    raise Exception("Build failed or artifact not found")


def process_binary_task(binary, ghidra_home, version_tag):
    """
    Function executed by the worker to process a single binary.
    """
    bin_path = os.path.join(BINARIES_DIR, binary)
    script_path = os.path.abspath("scripts")

    unique_proj_dir = os.path.join(
        OUTPUT_DIR, "decomp", f"proj_{version_tag}_{binary}")
    if not os.path.exists(unique_proj_dir):
        os.makedirs(unique_proj_dir)

    env = os.environ.copy()
    env["GHIDRA_BENCH_OUTPUT"] = OUTPUT_DIR
    env["GHIDRA_BENCH_TAG"] = version_tag
    # env["GHIDRA_INSTALL_DIR"] = ghidra_home

    print(
        f"[INFO] [Parallel] Processing {binary} with version {version_tag}...")

    try:
        cmd = (
            f"chmod +x {ghidra_home}/support/pyghidraRun && "
            f"{ghidra_home}/support/pyghidraRun --headless {unique_proj_dir} temp_{binary} "
            f"-deleteProject "
            f"-import {bin_path} -overwrite "
            f"-scriptPath {script_path} -postScript extract.py "
        )
        run_command(cmd, env=env, input_text="n\n")
    except Exception as e:
        try:
            print(f"[INFO] Falling back to analyzeHeadless for {binary}...")
            cmd = (
                f"chmod +x {ghidra_home}/support/analyzeHeadless && "
                f"{ghidra_home}/support/analyzeHeadless {unique_proj_dir} temp_{binary} "
                f"-deleteProject "
                f"-import {bin_path} -overwrite "
                f"-scriptPath {script_path} -postScript extract.py "
            )
            run_command(cmd, env=env, input_text="n\n")
        except Exception as e:
            print(f"[ERR] Failed processing {binary}: {e}")
    finally:
        if os.path.exists(unique_proj_dir):
            shutil.rmtree(unique_proj_dir, ignore_errors=True)
        print(f"[INFO] Finished {binary}")


def extract_decompilation(ghidra_home, version_tag):
    """
    Runs pyghidraRun --headless in parallel on the binaries.
    """

    binaries = [
        f for f in os.listdir(BINARIES_DIR)
        if os.path.isfile(os.path.join(BINARIES_DIR, f)) and not f.startswith('.')
    ]

    if not binaries:
        print("[WARN] No binaries found to process.")
        return

    workers = int(MAX_WORKERS)
    print(f"[INFO] Starting extraction with {workers} parallel workers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_bin = {
            executor.submit(process_binary_task, binary, ghidra_home, version_tag): binary
            for binary in binaries
        }

        for future in concurrent.futures.as_completed(future_to_bin):
            binary = future_to_bin[future]
            try:
                future.result()
            except Exception as exc:
                print(f"[FATAL] {binary} generated an exception: {exc}")


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


def get_llm_qualitative_analysis(base_code, pr_code, model_id):
    """Call the LLM to get a qualitative analysis between two code snippets"""
    prompt_template = (
        "You are an expert in reverse engineering and C/C++ code analysis.\n"
        "You will be given multiple decompilation outputs of the same binary, "
        "each produced by a different decompiler.\n\n"
        "Your task is to evaluate **only the structural readability of the code**, "
        "not variable naming or stylistic details.\n"
        "For consistency, apply the following evaluation criteria:\n"
        "1. **Control Flow Clarity** : Are conditionals (if, switch, loops) expressed "
        "in a form close to standard C, or are they obfuscated with labels and gotos?\n"
        "2. **Function Organization** : Are functions structured with clear entry/exit "
        "points, or fragmented into inline tailcalls and redundant wrappers?\n"
        "3. **Expression Predictability** : Are operations expressed as standard C "
        "expressions, or through low-level macros/register artifacts?\n"
        "4. **Structural Economy** : Does the code minimize unnecessary temporaries "
        "and boilerplate?\n\n"
        "--- DECOMPILER OUTPUT A (Base) ---\n"
        f"{base_code}\n\n"
        "--- DECOMPILER OUTPUT B (PR) ---\n"
        f"{pr_code}\n\n"
        "Provide the answer ONLY in this JSON format:\n"
        "{\n"
        '  "winner": "A or B or Tie",\n'
        '  "motivation": "Short explanation of structural factors"\n'
        "}"
    )

    try:
        api_gen_url = f"{LLM_API_URL}/generate"
        resp = requests.post(api_gen_url, json={
                             "prompt": prompt_template, "model_id": model_id})

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


def get_cyclomatic_complexity(code_snippet):
    """
    Calculates the Cyclomatic Complexity (CCN) of a C function string using lizard.
    Returns 0 if parsing fails.
    """
    try:
        analysis = lizard.analyze_file.analyze_source_code(
            "dummy_file.c", code_snippet)
        if analysis.function_list:
            return analysis.function_list[0].cyclomatic_complexity
    except Exception as e:
        print(f"[WARN] Lizard complexity check failed: {e}")
    return 0


def evaluate_with_llm(base_data, pr_data, model_id, test_binary_name, base_metrics_cache, MAX_SAMPLES=10):
    """Creates the prompt, calculates metrics, and calls the Flask server"""
    report = []

    print_time("[EVAL] Starting LLM-based evaluation with model " + model_id)

    # 1. Identify common functions
    all_funcs = list(set(base_data.keys()) & set(pr_data.keys()))

    candidates = []

    print_time(
        f"[PRE-PROCESS] Analyzing complexity for {len(all_funcs)} functions...")

    for func_name in all_funcs:
        base_code = base_data[func_name]
        pr_code = pr_data[func_name]

        # Fast Skip
        if base_code == pr_code:
            continue

        complexity = get_cyclomatic_complexity(pr_code)
        candidates.append((func_name, complexity))

    print_time(
        f"[PRE-PROCESS] Calculated complexity for all changed functions.")
    candidates.sort(key=lambda x: x[1], reverse=True)

    top_candidates = candidates[:MAX_SAMPLES]

    print_time(
        f"[PRE-PROCESS] Selected top {len(top_candidates)} functions with highest complexity (Max CCN: {top_candidates[0][1] if top_candidates else 0})")

    print("number of 0 complexity functions: ", len(
        [1 for _, ccn in top_candidates if ccn == 0]))
    print("total functions: ", len(candidates))

    # 5. Evaluate the selected functions
    for func_name, ccn_score in top_candidates:

        base_code = base_data[func_name]
        pr_code = pr_data[func_name]

        print(f"[EVAL] Evaluating change in {func_name}")

        cache_key = (func_name, model_id, test_binary_name)
        if cache_key in base_metrics_cache:
            base_metrics = base_metrics_cache[cache_key]
            # print(f"[CACHE] Using cached metrics for {func_name}")
        else:
            print_time(f"Computing base metrics for {func_name}")
            base_metrics = get_code_metrics(base_code, model_id=model_id)
            base_metrics_cache[cache_key] = base_metrics
            print_time(f"Finished base metrics for {func_name}")

        print_time(f"Computing metrics for PR - {func_name}")
        pr_metrics = get_code_metrics(pr_code, model_id=model_id)

        print_time(f"Finished metrics for {func_name}")

        ppl_delta = pr_metrics['perplexity'] - base_metrics['perplexity']

        print_time(f"Getting qualitative analysis for {func_name}")
        qualitative_analysis = get_llm_qualitative_analysis(
            base_code, pr_code, model_id=model_id)
        print_time(f"Finished qualitative analysis for {func_name}")

        entry = {
            "binary": test_binary_name,
            "function": func_name,
            "metrics": {
                "base_ppl": base_metrics['perplexity'],
                "pr_ppl": pr_metrics['perplexity'],
                # < 0 means PR improved (lowered) perplexity
                "delta_ppl": ppl_delta,
            },
            "llm_analysis": qualitative_analysis
        }

        print(
            f"   > PPL Base: {base_metrics['perplexity']:.2f} | PPL PR: {pr_metrics['perplexity']:.2f} | Delta: {ppl_delta:.2f}")
        print(
            f"   > Better version: {'PR' if ppl_delta < 0 else 'Base' if ppl_delta > 0 else 'No Change'}")

        report.append(entry)
        print_time(f"[EVAL] Evaluated change in {func_name}")

    return report


def main(prs_number=None):
    # pr_number = "8635"#"8718"#"8718"
    print_time("[START] Starting main process")

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
        print_time(f"[PROCESSING] Starting PR #{pr_number}")

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

                        # if base_data == pr_data:
                        #     print("[INFO] No changes detected between base and PR decompilations.")
                        #     with open(os.path.join(OUTPUT_DIR, "final_report.json"), "w") as f:
                        #         json.dump({"message": "No changes detected between base and PR decompilations."}, f, indent=2)
                        #     return

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

        print_time(f"[PROCESSING] Finished model {model_id}")

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
    print_time("[END] Finished all processing")


def fetch_decompiler_prs():
    """
    Fetches open PR numbers from Ghidra repo with label "Feature: Decompiler"
    """
    url = "https://api.github.com/search/issues"
    query = 'repo:NationalSecurityAgency/ghidra is:pr is:open label:"Feature: Decompiler"'

    params = {
        'q': query,
        'sort': 'updated',
        'order': 'desc',
        'per_page': 100
    }

    try:
        print(f"[GITHUB] Fetching open PRs with label 'Feature: Decompiler'...")
        response = requests.get(url, params=params)

        if response.status_code == 200:
            data = response.json()
            items = data.get('items', [])
            pr_numbers = [str(item['number']) for item in items]
            print(f"[GITHUB] Found {len(pr_numbers)} PRs: {pr_numbers}")
            return pr_numbers  # 5554, '8834']  # pr_numbers
            # return ['3299', '8597']
        elif response.status_code == 403:
            print("[WARN] GitHub API rate limit exceeded or access denied.")
            return []
        else:
            print(f"[ERR] GitHub API returned status {response.status_code}")
            return []

    except Exception as e:
        print(f"[ERR] Failed to fetch PRs: {e}")
        return []


def get_models():
    """
    Returns the list of models to benchmark from the LLM server.
    """
    try:
        resp = requests.get(f"{LLM_API_URL}/models", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("available_models", [])
            print(f"[INFO] Models available for benchmarking: {models}")
            return models
        else:
            print(
                f"[WARN] Could not fetch models from LLM server: {resp.status_code}")
            return []
    except Exception as e:
        print(f"[ERR] Failed to get models: {e}")
        return []


if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    MODELS_TO_BENCHMARK = get_models()

    main(fetch_decompiler_prs())
