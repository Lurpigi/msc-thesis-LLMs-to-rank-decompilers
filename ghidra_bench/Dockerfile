FROM gradle:jdk21-jammy

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    bison \
    flex \
    git \
    unzip \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel build requests

# GRADLE CACHE OPTIMIZATION
WORKDIR /tmp/ghidra-cache-warmup
RUN git clone --depth 1 https://github.com/NationalSecurityAgency/ghidra.git . && \
    mkdir flatRepo && \
    (./gradlew prepDev || ./gradlew dependencies || true) && \
    # cleanup
    cd .. && rm -rf ghidra-cache-warmup

WORKDIR /app
COPY . /app

ENV GHIDRA_BENCH_OUTPUT=/app/outputs
ENV GRADLE_USER_HOME=/app/.gradle

RUN mkdir -p /app/outputs

RUN chmod -R 777 /app

CMD ["python3", "benchmark.py"]