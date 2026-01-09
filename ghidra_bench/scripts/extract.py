
import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

#CONFIGURATION
TARGET_FUNCTIONS = os.environ.get("GHIDRA_BENCH_TARGETS").split(",") if os.environ.get("GHIDRA_BENCH_TARGETS") else []
OUTPUT_DIR = os.environ.get("GHIDRA_BENCH_OUTPUT", "/tmp")
VERSION_TAG = os.environ.get("GHIDRA_BENCH_TAG", "unknown")

def run():
    prog = currentProgram
    decomp = DecompInterface()
    decomp.openProgram(prog)
    monitor = ConsoleTaskMonitor()
    
    results = {}

    fm = prog.getFunctionManager()
    target_functions = TARGET_FUNCTIONS[:]

    if len(target_functions) == 0:
        print("[WARN] No target functions specified for decompilation. using all the functions.")
        target_functions = [f.getName() for f in fm.getFunctions(True)]
    
    for func_name in target_functions:
        funcs = fm.getFunctions(True)
        target_func = None
        for f in funcs:
            if f.getName() == func_name:
                target_func = f
                break
        
        if not target_func:
            print("[WARN] Function {} not found in {}".format(func_name, prog.getName()))
            continue
            
        res = decomp.decompileFunction(target_func, 0, monitor)
        if res.decompileCompleted():
            c_code = res.getDecompiledFunction().getC()
            results[func_name] = c_code
        else:
            print("[ERR] Failed to decompile {}".format(func_name))

    out_file = os.path.join(OUTPUT_DIR, "{}_{}.json".format(prog.getName(), VERSION_TAG))
    with open(out_file, 'w') as f:
        json.dump(results, f)
    print("[INFO] Exported decompilation to {}".format(out_file))

if __name__ == "__main__":
    run()