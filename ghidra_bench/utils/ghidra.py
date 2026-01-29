import os
from .const import DATASET_PATH, GHIDRA_REPO, GHIDRA_REPO_DIR, GHIDRA_EXTRACTED_DIR, BINARIES_DIR, MAX_WORKERS, GRADLE_INSTALL_ROOT, OUTPUT_DIR
from .com import get_func_name, run_command
import concurrent.futures
import shutil


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
    print(
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
            print(f"[SETUP] Finished setting up Ghidra")
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
            print(f"[SETUP] Finished setting up Ghidra")
            return ghidra_folder

    raise Exception("Build failed or artifact not found")


def extract_decompilation(ghidra_home, version_tag, binaries):
    """
    Runs pyghidraRun --headless in parallel on the binaries.
    """

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
    env["GHIDRA_BENCH_TARGETS"] = get_func_name(binary, DATASET_PATH)

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
