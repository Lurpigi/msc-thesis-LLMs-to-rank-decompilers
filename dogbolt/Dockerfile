FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y curl jq && \
    apt-get install -y tree && \
    rm -rf /var/lib/apt/lists/*
    

WORKDIR /app

RUN mkdir -p bin


WORKDIR /app
COPY bin/ ./bin/
COPY dogbolt.sh .
COPY run.sh .



RUN chmod +x dogbolt.sh run.sh

# Run the script
#CMD ["bash", "./run.sh"]