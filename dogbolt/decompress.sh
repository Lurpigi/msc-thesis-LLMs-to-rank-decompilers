#!/bin/bash

src_dir="./src"
bin_dir="./bin"

find "$src_dir" -type f -name "*.c" | while read -r src_file; do
    filename=$(basename "$src_file" .c)
    if [ -f "$bin_dir/$filename" ]; then
        zcat "$src_file" > "$(dirname "$src_file")/decompiled.c"
    fi
done