
import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

#CONFIGURATION
TARGET_FUNCTIONS = os.environ.get("GHIDRA_BENCH_TARGETS", "main,test1,test2,test3,test4").split(",")
OUTPUT_DIR = os.environ.get("GHIDRA_BENCH_OUTPUT", "/tmp")
VERSION_TAG = os.environ.get("GHIDRA_BENCH_TAG", "unknown")

def run():
    prog = currentProgram
    decomp = DecompInterface()
    decomp.openProgram(prog)
    monitor = ConsoleTaskMonitor()
    
    results = {}
    
    fm = prog.getFunctionManager()
    for func_name in TARGET_FUNCTIONS:
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