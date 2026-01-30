FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    software-properties-common \
    lsb-release \
    gnupg \
    docker.io \
    iptables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 18 all && \
    rm llvm.sh

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100

ENV LIBCLANG_PATH="/usr/lib/llvm-18/lib/libclang-18.so.1"
ENV PATH="/usr/lib/llvm-18/bin:$PATH"
ENV CC=clang
ENV CXX=clang++

RUN pip3 install --upgrade pip 

WORKDIR /app

COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]