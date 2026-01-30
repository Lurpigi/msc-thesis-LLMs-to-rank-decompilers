#!/bin/bash
set -e

echo "[*] Starting internal Docker Daemon (direct mode)..."

rm -f /var/run/docker.pid

dockerd > /var/log/dockerd.log 2>&1 &

echo "Waiting for Docker daemon to be ready..."
TRIES=0
while ! docker info > /dev/null 2>&1; do
    sleep 1
    TRIES=$((TRIES+1))
    if [ $TRIES -ge 30 ]; then
            echo "[ERROR] Docker did not start within 30 seconds. Read the logs:"
            cat /var/log/dockerd.log
            exit 1
    fi
done

echo "[*] Docker Daemon is active and running!"

BASE_DIR="/app"
cd $BASE_DIR

# Clone fork
if [ ! -d "DecompileBench" ]; then
        echo "[*] Cloning DecompileBench..."
        git clone https://github.com/Lurpigi/DecompileBench.git
else
        echo "[*] DecompileBench already present."
fi

cd DecompileBench

# Clone oss-fuzz
if [ ! -d "oss-fuzz" ]; then
        echo "[*] Cloning oss-fuzz..."
        git clone https://github.com/google/oss-fuzz.git
fi

echo "[*] Applying patch to oss-fuzz..."
wget -q 'https://cloud.vul337.team:8443/public.php/dav/files/br9qNTzwnmGgagF/clang-extract.tar.gz' -O oss-fuzz/infra/base-images/base-builder/clang-extract.tar.gz

cd oss-fuzz
git checkout 4bca88f3a369679336485181961db305161fe240 || echo "Checkout warning (might already be on this commit)"
git apply ../oss-fuzz-patch/*.diff || echo "Patch might already be applied."
cd ..

echo "[*] Loading Docker images (this will take time)..."
curl -sL https://cloud.vul337.team:8443/public.php/dav/files/br9qNTzwnmGgagF/base-runner.tar.gz | docker load
curl -sL https://cloud.vul337.team:8443/public.php/dav/files/br9qNTzwnmGgagF/base-builder.tar.gz | docker load

echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt


echo "[*] Compiling dummy library..."
docker run --rm -w /work -v $(pwd):/work gcr.io/oss-fuzz-base/base-builder bash -c "clang dummy.c -o libfunction.so -O2 -fPIC -shared && clang ld.c -o ld.so -shared -fPIC -O2"

echo "[*] Running extract_functions.py..."
python3 extract_functions.py --project file
# python3 extract_functions.py

# pip3 uninstall -y clang
pip3 install libclang==18.1.1

echo "[*] Starting final compilation to $dataset_path..."
#export LIBCLANG_PATH="/usr/lib/llvm-18/lib/libclang-18.so.1"

python3 compile_ossfuzz.py --output "$dataset_path"

echo "[SUCCESS] Process completed! You can find the data in the ./Dataset folder on your host."
