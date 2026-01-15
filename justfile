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

server:
    docker compose up --build -d llm-server

ghidra_bench:
    UID_GID="$(id -u):$(id -g)" docker compose up --build -d ghidra-bench && docker logs -f tesi-ghidra-bench-1

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

metrics:
    docker compose up -d --build grafana