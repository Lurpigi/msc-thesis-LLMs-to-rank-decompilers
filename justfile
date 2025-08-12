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

down:
    docker compose down --remove-orphans
    docker volume prune -f
    docker network prune -f
    docker system prune -f
    docker builder prune -f
    docker image prune -f
    docker container prune -f