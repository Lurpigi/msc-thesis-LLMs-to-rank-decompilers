#!/bin/bash

# ================= CONFIGURATION =================
WORK_DIR="$(pwd)/dataset_output"
SRC_DIR="$WORK_DIR/sources"
BIN_DIR="$WORK_DIR/binaries"
LOG_DIR="$WORK_DIR/logs"

OPTIMIZATIONS=("O0" "O1" "O2" "O3" "Os")

CORES=$(nproc)

mkdir -p "$SRC_DIR" "$BIN_DIR" "$LOG_DIR"

build_generic() {
    NAME=$1
    URL=$2
    BIN_NAME=$3
    BIN_REL_PATH=$4
    
    echo "[*] Processing project: $NAME (Target: $BIN_NAME)"
    
    cd "$SRC_DIR"
    if [ ! -d "$NAME" ]; then
        echo "    Downloading sources..."
        wget -q -O "$NAME.tar.gz" "$URL"
        mkdir -p "$NAME"
        tar -xf "$NAME.tar.gz" -C "$NAME" --strip-components=1
    fi
    
    cd "$NAME"

    for OPT in "${OPTIMIZATIONS[@]}"; do
        echo "    Compiling $BIN_NAME with -$OPT..."
        
        # Clean and set flags
        if [ -f "Makefile" ]; then make clean > /dev/null 2>&1; fi
        export CFLAGS="-$OPT -g -Wno-error"
        
        ./configure --disable-nls --quiet > "$LOG_DIR/${NAME}_${OPT}_conf.log" 2>&1
        
        make -j$CORES > "$LOG_DIR/${NAME}_${OPT}_make.log" 2>&1
        
        # Saving
        TARGET_SRC="$BIN_REL_PATH"
        OUTPUT_DIR="$BIN_DIR/$BIN_NAME" # Use BIN_NAME for the folder
        mkdir -p "$OUTPUT_DIR"
        
        if [ -f "$TARGET_SRC" ]; then
            cp "$TARGET_SRC" "$OUTPUT_DIR/${BIN_NAME}_${OPT}_debug"
            cp "$TARGET_SRC" "$OUTPUT_DIR/${BIN_NAME}_${OPT}_stripped"
            strip "$OUTPUT_DIR/${BIN_NAME}_${OPT}_stripped"
        else
            echo "    ERR: Binary $TARGET_SRC not found."
        fi
    done
}

build_sqlite() {
    NAME="sqlite3"
    echo "[*] Processing project: $NAME"
    cd "$SRC_DIR"
    if [ ! -f "sqlite3.c" ]; then
        wget -q https://www.sqlite.org/2023/sqlite-amalgamation-3440200.zip
        unzip -q sqlite-amalgamation-3440200.zip
        mv sqlite-amalgamation-3440200/* .
    fi

    for OPT in "${OPTIMIZATIONS[@]}"; do
        echo "    Compiling $NAME with -$OPT..."
        OUTPUT_DIR="$BIN_DIR/$NAME"
        mkdir -p "$OUTPUT_DIR"
        gcc -g -$OPT -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION sqlite3.c shell.c -o "$OUTPUT_DIR/sqlite3_${OPT}_debug" -ldl -lpthread
        cp "$OUTPUT_DIR/sqlite3_${OPT}_debug" "$OUTPUT_DIR/sqlite3_${OPT}_stripped"
        strip "$OUTPUT_DIR/sqlite3_${OPT}_stripped"
    done
}

build_redis() {
    NAME="redis"
    echo "[*] Processing project: $NAME"
    cd "$SRC_DIR"
    if [ ! -d "redis" ]; then
        git clone --quiet https://github.com/redis/redis.git
    fi
    cd redis
    
    for OPT in "${OPTIMIZATIONS[@]}"; do
        echo "    Compiling $NAME with -$OPT..."
        make distclean > /dev/null 2>&1
        make -j$CORES OPTIMIZATION="-$OPT" MALLOC=libc > "$LOG_DIR/${NAME}_${OPT}.log" 2>&1
        
        OUTPUT_DIR="$BIN_DIR/$NAME"
        mkdir -p "$OUTPUT_DIR"
        
        if [ -f "src/redis-server" ]; then
            cp "src/redis-server" "$OUTPUT_DIR/redis-server_${OPT}_debug"
            cp "src/redis-server" "$OUTPUT_DIR/redis-server_${OPT}_stripped"
            strip "$OUTPUT_DIR/redis-server_${OPT}_stripped"
        fi
    done
}


# 1. LS 
# Download coreutils but only save "ls"
build_generic "coreutils" "https://ftp.gnu.org/gnu/coreutils/coreutils-9.4.tar.gz" "ls" "src/ls"

# 2. GREP
build_generic "grep" "https://ftp.gnu.org/gnu/grep/grep-3.11.tar.gz" "grep" "src/grep"

# 3. BASH
build_generic "bash" "https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz" "bash" "bash"

# 4. NANO
build_generic "nano" "https://www.nano-editor.org/dist/v7/nano-7.2.tar.gz" "nano" "src/nano"

# 5. SQLITE
build_sqlite

# 6. REDIS
build_redis

echo ""
echo "=== DONE ==="