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

RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel build requests pyghidra

RUN mkdir -p /opt/ghidra_src /opt/ghidra_exe /opt/ghidra-dist /app/outputs /opt/gradle_cache && \
    chown -R gradle:gradle /opt/ghidra_src /opt/ghidra_exe /opt/ghidra-dist /app /opt/gradle_cache

#SPEEDING UP GRADLE
ENV GRADLE_USER_HOME=/opt/gradle_cache
RUN echo "org.gradle.caching=true\norg.gradle.jvmargs=-Xmx2g" > /opt/gradle_cache/gradle.properties

RUN git config --system --add safe.directory /opt/ghidra_src

USER gradle

WORKDIR /opt

RUN echo "[DOCKER] Cloning Ghidra Master..." && \
    git clone --depth 1 https://github.com/NationalSecurityAgency/ghidra.git ghidra_src

WORKDIR /opt/ghidra_src

RUN echo "[DOCKER] Fetching dependencies..." && \
    mkdir flatRepo && \
    ./gradlew -I gradle/support/fetchDependencies.gradle

RUN echo "[DOCKER] Building Ghidra (this may take a while)..." && \
    ./gradlew buildGhidra -x test -x integrationTest -x javadoc -x check -x ip -x createJavadocs -x createJsondocs -x zipJavadocs

RUN mkdir -p /opt/ghidra-dist && \
    find build/dist -name "ghidra_*.zip" -exec unzip -q {} -d /opt/ghidra-dist \; && \
    mv /opt/ghidra-dist/ghidra_*/* /opt/ghidra_exe/ && \
    rm -f /opt/ghidra_src/.git/index.lock

WORKDIR /app

COPY --chown=gradle:gradle . /app

ENV GHIDRA_GIT_PATH=/opt/ghidra_src
ENV GHIDRA_EXTRACTED_PATH=/opt/ghidra_exe
ENV GHIDRA_BENCH_OUTPUT=/app/outputs

RUN mkdir -p /app/outputs && \
    chown -R gradle:gradle /app/outputs

CMD ["python3", "benchmark.py"]