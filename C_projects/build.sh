#!/usr/bin/env bash
set -e

declare -A PROJS
# PROJS["name_project"]="directory:main.c"
PROJS["cat"]="src:cat.c"
PROJS["chmod"]="src:chmod.c"
PROJS["sleep"]="src:sleep.c"

OPTS=(O1 O2 O3)

# function
compile_proj () {
  local pname="$1"    # name, key
  local dir_and_file="$2"
  IFS=':' read -r dir mainc <<< "$dir_and_file"
  pushd "$dir" > /dev/null

  for opt in "${OPTS[@]}"; do
    local exe_name="${pname}_${opt}"
    echo "Compiling $pname with -$opt → $exe_name"
    gcc -std=c11 -Wall -g -"${opt}" "$mainc" -o "../bin/$exe_name"
    # ex: strip --strip-unneeded "$exe_name"
  done

  popd > /dev/null
}

# Iter
for pname in "${!PROJS[@]}"; do
  compile_proj "$pname" "${PROJS[$pname]}"
done

echo "Build finished"

