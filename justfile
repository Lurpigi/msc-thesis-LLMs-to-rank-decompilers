set dotenv-load

switch-branch branch:
    git checkout {{branch}}

stop:
    docker compose stop

make:
    cd C_projects && bash build.sh

dogbolt:
    UID_GID="$(id -u):$(id -g)" docker compose up --build -d dogbolt && docker logs -f tesi-dogbolt-1

dogbolt_bench:
    UID_GID="$(id -u):$(id -g)" docker compose up --build -d dogbolt-bench && docker logs -f tesi-dogbolt-bench-1

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

dataset:
    docker compose up -d --build dataset-maker && docker logs -f tesi-dataset-maker-1

view:
    docker compose up -d --build report-viewer

all:
    just ghidra_bench && just stop && just dogbolt_bench