#!/bin/bash

echo "Running dogbolt on all files in ./bin directory..."

for file in ./bin/*; do
    if [[ -f "$file" ]]; then
        ./dogbolt.sh "$file"
    fi
done

bash ./decompress.sh

echo "Dogbolt run completed."