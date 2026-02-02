import os
# CONFIGURATION
GHIDRA_REPO = "https://github.com/NationalSecurityAgency/ghidra"
GHIDRA_REPO_DIR = os.environ.get("GHIDRA_GIT_PATH")  # "/opt/ghidra_src"
GHIDRA_EXTRACTED_DIR = os.environ.get(
    "GHIDRA_EXTRACTED_PATH")  # "/opt/ghidra_exe"
BINARIES_DIR = os.path.abspath("Dataset/binary")
DATASET_PATH = os.path.abspath("Dataset/compiled_ds")
OUTPUT_DIR = os.path.abspath("outputs")
TARGET_FUNCTIONS = ["main", "test1", "test2", "test3", "test4"]
LLM_API_URL = os.environ.get("LLM_API_URL", "http://localhost:8900")
LLM_API_GEN = f"{LLM_API_URL}/generate"
LLM_API_SCORE = f"{LLM_API_URL}/score"
MAX_WORKERS = int(os.environ.get("GHIDRA_WORKERS", 4))
GRADLE_INSTALL_ROOT = "/opt/gradle"
MODELS_TO_BENCHMARK = []
MAX_SAMPLES = 25
