import os
import subprocess
import requests
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
LLM_API_GEN = f"{LLM_API_URL}/generate"
LLM_API_SCORE = f"{LLM_API_URL}/score"

def run_command(cmd, cwd=None, env=None):
    #subprocess.check_call(cmd, shell=True, cwd=cwd, env=env)
    print(f"[CMD] Executing: {cmd}")
    sys.stdout.flush()
    
    process = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        env=env,
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
    """Clones, checks out and builds Ghidra. Returns the path to 'support/analyzeHeadless'"""
    
    # check image for prebuilt master
    if tag_or_pr == "master" and not is_pr:
        prebuilt_path = os.environ.get("GHIDRA_EXTRACTED_PATH")
        if prebuilt_path and os.path.exists(prebuilt_path):
            print(f"[INFO] Using PRE-BUILT Ghidra Master found at {prebuilt_path}")
            headless_path = os.path.join(prebuilt_path, "support", "analyzeHeadless")
            
            if not os.access(headless_path, os.X_OK):
                run_command(f"chmod +x {headless_path}")
                
            return headless_path
        
    cwd = GHIDRA_REPO_DIR

    if os.path.exists(GHIDRA_REPO_DIR):
        print(f"[SPEEDUP] Using pre-built Ghidra template from {GHIDRA_REPO_DIR}...")
    else:
        print("[WARN] Template not found. Falling back to slow git clone...")
        run_command(f"git clone {GHIDRA_REPO} .", cwd=cwd)
    
    # MAYBE SHOULD NOT BE NEEDED
    run_command("git reset --hard && git clean -fd -e build/ -e .gradle/", cwd=cwd)
    run_command("git checkout master", cwd=cwd)
    
    if is_pr:
        run_command(f"git fetch origin pull/{tag_or_pr}/head:pr-{tag_or_pr}", cwd=cwd)
        run_command(f"git checkout pr-{tag_or_pr}", cwd=cwd)
    else:
        run_command(f"git checkout {tag_or_pr}", cwd=cwd)
        
    print(f"[BUILD] Building Ghidra for {tag_or_pr} (this takes time)...")
    run_command("./gradlew -I gradle/support/fetchDependencies.gradle", cwd=cwd)
    run_command("./gradlew buildGhidra -x test -x integrationTest -x javadoc -x check", cwd=cwd)
    
    dist_dir = os.path.join(cwd, "build", "dist")
    for f in os.listdir(dist_dir):
        if f.endswith(".zip"):
            zip_path = os.path.join(dist_dir, f)

            run_command(f"unzip -o -q {zip_path} -d {GHIDRA_EXTRACTED_DIR}", cwd=dist_dir)
            ghidra_folder = GHIDRA_EXTRACTED_DIR

            pyghidra_path = os.path.join(ghidra_folder, "Ghidra", "Features", "PyGhidra")
            if os.path.exists(pyghidra_path):
                print(f"[FIX] Removing broken PyGhidra extension at {pyghidra_path}...")
                shutil.rmtree(pyghidra_path)

            headless = os.path.join(ghidra_folder, "support", "analyzeHeadless")
            run_command(f"chmod +x {headless}")
            return headless
            
    raise Exception("Build failed or artifact not found")

def extract_decompilation(headless_path, version_tag):
    """Runs Ghidra Headless on the binaries"""
    script_path = os.path.abspath("scripts") 
    
    env = os.environ.copy()
    env["GHIDRA_BENCH_OUTPUT"] = OUTPUT_DIR
    env["GHIDRA_BENCH_TAG"] = version_tag
    env["GHIDRA_BENCH_TARGETS"] = ",".join(TARGET_FUNCTIONS)

    # Create temporary project
    project_path = os.path.join(OUTPUT_DIR, "temp_proj")
    if not os.path.exists(project_path):
        os.makedirs(project_path)

    for binary in os.listdir(BINARIES_DIR):
        bin_path = os.path.join(BINARIES_DIR, binary)
        if not os.path.isfile(bin_path): continue

        print(f"[EXTRACT] Processing {binary} with version {version_tag}...")
        # Headless command: imports the binary and then runs the script
        cmd = (
            f"{headless_path} {project_path} temp_proj_{version_tag} "
            f"-import {bin_path} -overwrite "
            f"-scriptPath {script_path} -postScript extract.py "
        )
        
        run_command(cmd, env=env)

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
    
    for func_name, base_code in base_data.items():
        pr_code = pr_data.get(func_name)
        if not pr_code: continue
        
        # no change
        # if base_code.strip() == pr_code.strip():
        #     print(f"[SKIP] Function {func_name} is identical.")
        #     continue

        print(f"[EVAL] Evaluating change in {func_name}...")
        
        # Calc (Low PPL = Better/More predictable code)
        base_metrics = get_code_metrics(base_code)
        pr_metrics = get_code_metrics(pr_code)
        
        # Calc Delta PPL (Negative is good -> PR reduced confusion)
        ppl_delta = pr_metrics['perplexity'] - base_metrics['perplexity']

        # 2. Ask LLM for SUBJECTIVE preference
        prompt = (
            "You are an expert in reverse engineering and C/C++ code analysis.\n"
            "You will be given multiple decompilation outputs of the same binary function.\n"
            "Your task is to choose the most human-readable version.\n"
            "Ignore variable names unless they impact structure clarity significantly.\n\n"
            f"Version 1 (Base):\n{base_code}\n\n"
            f"Version 2 (PR):\n{pr_code}\n\n"
            "Answer ONLY with the number of the version you choose (1 or 2)."
        )

        llm_choice = "Error"
        llm_reasoning = ""
        
        try:
            resp = requests.post(LLM_API_GEN, json={"prompt": prompt}).json()
            generated_text = resp.get("generated_text", "").strip()
            llm_reasoning = generated_text
            
            if "1" in generated_text and "2" not in generated_text:
                llm_choice = "Base"
            elif "2" in generated_text and "1" not in generated_text:
                llm_choice = "PR"
            elif "1" in generated_text: # Fallback
                llm_choice = "Base" 
            else:
                llm_choice = "PR" # O Undecided
                
        except Exception as e:
            print(f"Error calling LLM Generate: {e}")

        entry = {
            "function": func_name,
            "metrics": {
                "base_ppl": base_metrics['perplexity'],
                "pr_ppl": pr_metrics['perplexity'],
                "delta_ppl": ppl_delta, # < 0 means PR improved (lowered) perplexity
                "base_logbits": base_metrics['mean_logbits'],
                "pr_logbits": pr_metrics['mean_logbits']
            },
            "llm_eval": {
                "winner": llm_choice,
                "reasoning": llm_reasoning
            }
        }
        
        # Log
        print(f"   > PPL Base: {base_metrics['perplexity']:.2f} | PPL PR: {pr_metrics['perplexity']:.2f} | Delta: {ppl_delta:.2f}")
        print(f"   > LLM Pick: {llm_choice}")
        
        report.append(entry)

    return report

def main():
    pr_number = "8718"#"8635"#"8718" #TODO: get from args/env
    
    base_headless = setup_ghidra_version("master")
    extract_decompilation(base_headless, "base")
    
    pr_headless = setup_ghidra_version(pr_number, is_pr=True)
    extract_decompilation(pr_headless, "pr")
    
    test_binary_name = None
    try:
        for item in os.listdir(BINARIES_DIR):
            if os.path.isfile(os.path.join(BINARIES_DIR, item)) and not item.startswith('.'):
                test_binary_name = item
                break
        if not test_binary_name:
            print("[FATAL] No binary found in BINARIES_DIR.")
            return
    except FileNotFoundError:
        print(f"[FATAL] BINARIES_DIR ({BINARIES_DIR}) not found.")
        return

    base_json_path = os.path.join(OUTPUT_DIR, f"{test_binary_name}_base.json")
    pr_json_path = os.path.join(OUTPUT_DIR, f"{test_binary_name}_pr.json")
    
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

    results = evaluate_with_llm(base_data, pr_data)
    

    with open(os.path.join(OUTPUT_DIR, "final_report.json"), "w") as f:
       json.dump(results, f, indent=2)
    pass

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    main()