FROM ubuntu:22.04

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    git unzip wget \
    libarchive-tools \
    python3 python3-pip \
    build-essential bison flex \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /requirements.txt 
RUN pip3 install --no-cache-dir --upgrade -r /requirements.txt

RUN mkdir -p /opt/ghidra_src /opt/ghidra_exe /opt/ghidra-dist /app/outputs /opt/gradle_cache /opt/java_versions /opt/gradle_versions
    #chown -R gradle:gradle /opt/ghidra_src /opt/ghidra_exe /opt/ghidra-dist /app /opt/gradle_cache

#SPEEDING UP GRADLE
ENV GRADLE_USER_HOME=/opt/gradle_cache
RUN echo "org.gradle.caching=true\norg.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=512m" > /opt/gradle_cache/gradle.properties
#RUN chown -R gradle:gradle /opt

RUN git config --system --add safe.directory /opt/ghidra_src

#USER gradle

WORKDIR /opt

RUN echo "[DOCKER] Cloning Ghidra Master..." && \
    git clone https://github.com/NationalSecurityAgency/ghidra.git ghidra_src && \
    cd ghidra_src && \
    git checkout 14c2495cb06ccd09324050c787ad0fc756d35dae

WORKDIR /opt/ghidra_src

RUN echo "[DOCKER] Fetching dependencies..." && \
    mkdir flatRepo && \
    ./gradlew -I gradle/support/fetchDependencies.gradle

RUN echo "[DOCKER] Building Ghidra (this may take a while)..." && \
    ./gradlew buildGhidra

RUN mkdir -p /opt/ghidra-dist && \
    find build/dist -name "ghidra_*.zip" -exec unzip -q {} -d /opt/ghidra-dist \; && \
    mv /opt/ghidra-dist/ghidra_*/* /opt/ghidra_exe/ && \
    rm -f /opt/ghidra_src/.git/index.lock

WORKDIR /app

#COPY --chown=gradle:gradle . /app
COPY . /app

ENV GHIDRA_GIT_PATH=/opt/ghidra_src
ENV GHIDRA_EXTRACTED_PATH=/opt/ghidra_exe
ENV GHIDRA_BENCH_OUTPUT=/app/outputs
ENV PYTHONUNBUFFERED=1

RUN mkdir -p /app/outputs 
    #chown -R gradle:gradle /app/outputs

RUN mkdir -p /opt/ghidra_src/dependencies/flatRepo
#RUN chmod -R a+w /app /opt /opt/ghidra_src /opt/ghidra_exe /opt/ghidra-dist /opt/gradle_cache /opt/ghidra_src/dependencies/flatRepo
CMD ["python3", "benchmark.py"]
#In ~/.docker/config.json change credsStore to credStore