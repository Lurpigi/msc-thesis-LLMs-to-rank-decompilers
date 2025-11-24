#!/bin/bash

ps -ax | grep -Ei 'ghidra|decompiler' | grep -v grep | awk '{print $1}' | while read pid; do
    kill -9 "$pid" 2>/dev/null
done

echo "Ghidra and decompiler killed"