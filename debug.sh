#!/bin/bash

decompiler_path=/home/lurpigi/app/ghidra_12.0_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile

pid=$(pgrep -fn "$decompiler_path")
if [ -z $pid ]
then
    echo "No decompiler process found"
    exit 1
fi

echo "Attaching to decompiler process with pid $pid"
gdb -q -x gdb_init "$decompiler_path" $pid