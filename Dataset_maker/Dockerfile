FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    lsb-release \
    software-properties-common \
    gnupg \
    docker.io \
    iptables \
    sudo \
    nano \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 18 all && \
    rm llvm.sh

ENV PATH="/usr/lib/llvm-18/bin:$PATH"
ENV LIBCLANG_PATH="/usr/lib/llvm-18/lib/libclang-18.so.1"

RUN pip3 install --upgrade pip && \
    pip3 install libclang pyyaml

WORKDIR /app

COPY run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh

ENTRYPOINT ["/usr/local/bin/run.sh"]