set dotenv-load

switch-branch branch:
    git checkout {{branch}}

stop:
    docker compose stop

make:
    cd C_projects && bash build.sh

decompile:
    #cp -r ./C_projects/bin/calculator ./dogbolt/bin/ #./C_projects/bin/*
    docker compose build decompile
    UID_GID="$(id -u):$(id -g)" docker compose up decompile
    cd dogbolt && bash decompress.sh

ownership:
    sudo chown -R $(whoami):$(whoami) ./C_projects/bin
    sudo chown -R $(whoami):$(whoami) ./dogbolt/src

gen_prompt:
    python3 ./prompt/gen_prompt.py

send_prompt:
    python3 ./prompt/send_prompt.py

huggingface:
    python3 ./prompt/huggingface.py

ghidra_bench:
    UID_GID="$(id -u):$(id -g)" docker compose up --build -d ghidra-bench

save_ghidra_image:
    docker save -o ghidra_bench_image.tar ghidra-bench:latest

load_ghidra_image:
    docker load -i ghidra_bench_image.tar

debug:
    sudo bash ./debug.sh

kill_ghidra:
    bash ./kill_ghidra.sh

study pc_type:
    python3 ./prompt/study.py {{pc_type}}

down:
    docker compose down --remove-orphans

destroy:
    docker stop $(docker ps -aq) 2>/dev/null || true
    docker system prune -a --volumes -f

mcp:
    #mcphost -m ollama:llama3.2 --config "/home/lurpigi/Documents/Tesi/mcp/local.json"
    mcphost -m ollama:qwen3:1.7b --config "/home/lurpigi/Documents/Tesi/mcp/local.json"