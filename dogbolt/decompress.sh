#!/bin/bash

echo "Decompressing files to .c files in ./src directory..."

src_dir="./src"
bin_dir="./bin"

find "$src_dir" -type f -name "*.c" | while read -r src_file; do
    filename=$(basename "$src_file" .c)
    #echo "Processing $filename"
    if [ -f "$bin_dir/$filename.so" ]; then
        #echo "Found corresponding binary for $src_file"
        tmp_file="${src_file}.tmp"
        if zcat "$src_file" > "$tmp_file" 2>/dev/null; then
            mv "$tmp_file" "$src_file"
            echo "Decompressed: $src_file"
        else
            rm -f "$tmp_file"
        fi
    fi
done