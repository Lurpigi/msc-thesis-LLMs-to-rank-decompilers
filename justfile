set dotenv-load

switch-branch branch:
    git checkout {{branch}}

stop:
    docker compose stop

make:
    docker compose build make #--no-cache
    docker compose up make

decompile:
    cp -r ./C_projects/bin/calculator ./dogbolt/bin/ #./C_projects/bin/*
    docker compose build decompile
    docker compose up decompile
    cd dogbolt && bash decompress.sh

ownership:
    sudo chown -R $(whoami):$(whoami) ./C_projects/bin
    sudo chown -R $(whoami):$(whoami) ./dogbolt/src

gen_prompt:
    python3 ./prompt/gen_prompt.py

send_prompt pc_type:
    python3 ./prompt/send_prompt.py {{pc_type}}

down:
    docker compose down --remove-orphans

destroy:
    docker stop $(docker ps -aq) 2>/dev/null
    docker system prune -a --volumes -f

mcp:
    #mcphost -m ollama:llama3.2 --config "/home/lurpigi/Documents/Tesi/mcp/local.json"
    mcphost -m ollama:qwen3:1.7b --config "/home/lurpigi/Documents/Tesi/mcp/local.json"