import os
import subprocess
import requests
import concurrent.futures
import shutil
import json
import sys

# CONFIGURATION
GHIDRA_REPO = "https://github.com/NationalSecurityAgency/ghidra"
GHIDRA_REPO_DIR = os.environ.get("GHIDRA_GIT_PATH")  #"/opt/ghidra_src"
GHIDRA_EXTRACTED_DIR = os.environ.get("GHIDRA_EXTRACTED_PATH")  #"/opt/ghidra_exe"
BINARIES_DIR = os.path.abspath("bin")
OUTPUT_DIR = os.path.abspath("outputs")
TARGET_FUNCTIONS = ["main", "test1", "test2", "test3", "test4"]
LLM_API_URL = os.environ.get("LLM_API_URL", "http://localhost:8900")
#LLM_API_GEN = f"{LLM_API_URL}/generate"
LLM_API_SCORE = f"{LLM_API_URL}/score"
MAX_WORKERS = int(os.environ.get("GHIDRA_WORKERS", 4))

def run_command(cmd, cwd=None, env=None, input_text=None):
    #subprocess.check_call(cmd, shell=True, cwd=cwd, env=env)
    if os.environ.get("VERBOSE"):
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
    
    if os.environ.get("VERBOSE"):
        if process.stdout:
            print(process.stdout)
        
    if process.returncode != 0:
        print(f"[FATAL] Command failed with return code {process.returncode}")
        if not os.environ.get("VERBOSE") and process.stdout:
            print(process.stdout)
        raise subprocess.CalledProcessError(process.returncode, cmd)

def setup_ghidra_version(tag_or_pr, is_pr=False):
    """Clones, checks out and builds Ghidra. Returns the path"""
    
    # check image for prebuilt master
    if tag_or_pr == "master" and not is_pr:
        prebuilt_path = os.environ.get("GHIDRA_EXTRACTED_PATH")
        if prebuilt_path and os.path.exists(prebuilt_path):
            print(f"[INFO] Using PRE-BUILT Ghidra Master found at {prebuilt_path}")
            # headless_path = os.path.join(prebuilt_path, "support", "analyzeHeadless")
            
            # if not os.access(headless_path, os.X_OK):
            #     run_command(f"chmod +x {headless_path}")
                
            # return headless_path
            return prebuilt_path
        
    cwd = GHIDRA_REPO_DIR

    if os.path.exists(GHIDRA_REPO_DIR):
        print(f"[INFO] Using pre-built Ghidra template from {GHIDRA_REPO_DIR}...")
    else:
        print("[WARN] Template not found. Falling back to slow git clone...")
        run_command(f"git clone {GHIDRA_REPO} .", cwd=cwd)
    
    # print("[GIT] Cleaning repository state...")
    # run_command("git reset --hard HEAD && git clean -fd -e build/ -e .gradle/", cwd=cwd)
    
    if is_pr:
        run_command(f"git fetch origin pull/{tag_or_pr}/head:pr-{tag_or_pr}", cwd=cwd)
        run_command(f"git checkout pr-{tag_or_pr}", cwd=cwd)
    else:
        run_command(f"git checkout {tag_or_pr}", cwd=cwd)
        
    print(f"[BUILD] Building Ghidra for {tag_or_pr} (this takes time)...")
    gradlew_path = os.path.join(cwd, "gradlew")
    if not os.path.exists(gradlew_path):
        print("[FATAL] gradlew not found! - Ghidra can't be built.")
        raise FileNotFoundError("gradlew not found in Ghidra repo")
        
    #run_command("./gradlew -I gradle/support/fetchDependencies.gradle", cwd=cwd)
    run_command("./gradlew buildGhidra -x test -x integrationTest -x javadoc -x check -x ip -x createJavadocs -x createJsondocs -x zipJavadocs ", cwd=cwd)
    
    dist_dir = os.path.join(cwd, "build", "dist")
    for f in os.listdir(dist_dir):
        if f.endswith(".zip"):
            zip_path = os.path.join(dist_dir, f)

            run_command(f"unzip -o -q {zip_path} -d {GHIDRA_EXTRACTED_DIR}", cwd=dist_dir)
            ghidra_folder = GHIDRA_EXTRACTED_DIR

            # extracted_subfolders = [d for d in os.listdir(ghidra_folder) if os.path.isdir(os.path.join(ghidra_folder, d)) and "ghidra" in d.lower()]
            # if extracted_subfolders:
            #     ghidra_home = os.path.join(ghidra_folder, extracted_subfolders[0])
            # else:
            #     ghidra_home = ghidra_folder

            # headless = os.path.join(ghidra_folder, "support", "analyzeHeadless")
            # run_command(f"chmod +x {headless}")
            print("Timestamp: ", subprocess.getoutput("date"))
            return ghidra_folder
            
    raise Exception("Build failed or artifact not found")

def process_binary_task(binary, ghidra_home, version_tag):
    """
    Function executed by the worker to process a single binary.
    """
    bin_path = os.path.join(BINARIES_DIR, binary)
    script_path = os.path.abspath("scripts")
    
    unique_proj_dir = os.path.join(OUTPUT_DIR, f"proj_{version_tag}_{binary}")
    if not os.path.exists(unique_proj_dir):
        os.makedirs(unique_proj_dir)

    env = os.environ.copy()
    env["GHIDRA_BENCH_OUTPUT"] = OUTPUT_DIR
    env["GHIDRA_BENCH_TAG"] = version_tag
    # env["GHIDRA_INSTALL_DIR"] = ghidra_home

    print(f"[INFO] [Parallel] Processing {binary} with version {version_tag}...")
    
    cmd = (
        f"{ghidra_home}/support/pyghidraRun --headless {unique_proj_dir} temp_{binary} "
        f"-deleteProject " 
        f"-import {bin_path} -overwrite "
        f"-scriptPath {script_path} -postScript extract.py "
    )
    
    try:
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

def get_code_metrics(code_snippet):
    """Calls the /score endpoint to obtain raw perplexity of the code)"""
    try:
        resp = requests.post(LLM_API_SCORE, json={"text": code_snippet})
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[WARN] Score API error: {resp.status_code}")
            return {"perplexity": -1, "mean_logbits": 0}
    except Exception as e:
        print(f"[ERR] Failed to get metrics: {e}")
        return {"perplexity": -1, "mean_logbits": 0}

def evaluate_with_llm(base_data, pr_data):
    """Creates the prompt, calculates metrics, and calls the Flask server"""
    report = []

    print("Timestamp: ", subprocess.getoutput("date"))
    
    for func_name, base_code in base_data.items():
        pr_code = pr_data.get(func_name)
        if not pr_code: continue
        
        # no change
        if base_code.strip() == pr_code.strip():
            #print(f"[SKIP] Function {func_name} is identical.")
            continue

        print(f"[EVAL] Evaluating change in {func_name}...")
        
        base_metrics = get_code_metrics(base_code)
        pr_metrics = get_code_metrics(pr_code)
        
        ppl_delta = pr_metrics['perplexity'] - base_metrics['perplexity']

        entry = {
            "function": func_name,
            "metrics": {
                "base_ppl": base_metrics['perplexity'],
                "pr_ppl": pr_metrics['perplexity'],
                "delta_ppl": ppl_delta, # < 0 means PR improved (lowered) perplexity
            }
        }
        
        print(f"   > PPL Base: {base_metrics['perplexity']:.2f} | PPL PR: {pr_metrics['perplexity']:.2f} | Delta: {ppl_delta:.2f}")
        print(f"   > Better version: {'PR' if ppl_delta < 0 else 'Base' if ppl_delta > 0 else 'No Change'}")
        
        report.append(entry)

    return report

def main(prs_number=None):
    #pr_number = "8635"#"8718"#"8718"
    print(f"[START] Timestamp: {subprocess.getoutput('date')}")
        
    base_headless = setup_ghidra_version("master")
    extract_decompilation(base_headless, "base")
    final_report = []

    for pr_number in prs_number:
        print("Timestamp: ", subprocess.getoutput("date"))
        print(f"[PROCESSING] PR #{pr_number}")
        try:
            pr_headless = setup_ghidra_version(pr_number, is_pr=True)
        except FileNotFoundError as e:
            print(f"[ERROR] {e}")
            continue
        extract_decompilation(pr_headless, "pr_"+pr_number)
        
        test_binary_name = None
        results = []
        try:
            for item in os.listdir(BINARIES_DIR):
                if os.path.isfile(os.path.join(BINARIES_DIR, item)) and not item.startswith('.'):
                    test_binary_name = item
                    base_json_path = os.path.join(OUTPUT_DIR, f"{test_binary_name}_base.json")
                    pr_json_path = os.path.join(OUTPUT_DIR, f"{test_binary_name}_pr_{pr_number}.json")
                    
                    if not os.path.exists(base_json_path) or not os.path.exists(pr_json_path):
                        print("[FATAL] Decompilation output files not found. Check Ghidra headless run.")
                        print(f"Expected Base: {base_json_path}")
                        print(f"Expected PR: {pr_json_path}")
                        return
                    

                    with open(base_json_path, 'r') as f:
                        base_data = json.load(f)
                    with open(pr_json_path, 'r') as f:
                        pr_data = json.load(f)

                    # if base_data == pr_data:
                    #     print("[INFO] No changes detected between base and PR decompilations.")
                    #     with open(os.path.join(OUTPUT_DIR, "final_report.json"), "w") as f:
                    #         json.dump({"message": "No changes detected between base and PR decompilations."}, f, indent=2)
                    #     return

                    results.extend(evaluate_with_llm(base_data, pr_data))


            if not test_binary_name:
                print("[FATAL] No binary found in BINARIES_DIR.")
                return
        except FileNotFoundError:
            print(f"[FATAL] BINARIES_DIR ({BINARIES_DIR}) not found.")
            return
        
        #mean results
        mean_delta = sum(entry['metrics']['delta_ppl'] for entry in results) / len(results) if results else 0
        print(f"[FINAL RESULT] Mean delta perplexity across all functions: {mean_delta:.2f}")
        print(f"[FINAL RESULT] Overall improvement: {'YES' if mean_delta < 0 else 'NO' if mean_delta > 0 else 'NO CHANGE'}")

        print("Timestamp: ", subprocess.getoutput("date"))

        final_report.append({
            "pr_number": pr_number,
            "mean_delta_perplexity": mean_delta,
            "results": results
        })

    with open(os.path.join(OUTPUT_DIR, "final_report.json"), "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"[END] Timestamp: {subprocess.getoutput('date')}")

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
            return pr_numbers
        elif response.status_code == 403:
            print("[WARN] GitHub API rate limit exceeded or access denied.")
            return []
        else:
            print(f"[ERR] GitHub API returned status {response.status_code}")
            return []
            
    except Exception as e:
        print(f"[ERR] Failed to fetch PRs: {e}")
        return []

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)

    main(fetch_decompiler_prs())