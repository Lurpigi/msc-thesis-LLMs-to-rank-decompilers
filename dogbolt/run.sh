#!/bin/bash

for file in ./bin/*; do
    if [[ -f "$file" ]]; then
        ./dogbolt.sh "$file"
    fi
done