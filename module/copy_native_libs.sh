#!/bin/sh

set -e # 失败时立即退出

BUILD_DIR="$1"
MAGISK_DIR="$2"
MODULE_LIB_NAME="$3"

if [ -z "$BUILD_DIR" ] || [ -z "$MAGISK_DIR" ] || [ -z "$MODULE_LIB_NAME" ]; then
  echo "Error: Missing arguments."
  exit 1
fi

echo "--- Starting Native Library Copy Script ---"

# 创建必要目录
mkdir -p "$MAGISK_DIR/zygisk"

# 1. 处理主 Zygisk 模块 (lib${MODULE_LIB_NAME}.so -> zygisk/${abi}.so)
SO_FILES=$(find "$BUILD_DIR" \( -path '*/stripped_native_libs/*' -o -path '*/merged_native_libs/*' \) -name "lib${MODULE_LIB_NAME}.so")

if [ -z "$SO_FILES" ]; then
    echo "Error: Main library lib${MODULE_LIB_NAME}.so not found."
    exit 1
fi

echo "$SO_FILES" | while read -r so_path; do
  abi=$(basename "$(dirname "$so_path")")
  dest_path="$MAGISK_DIR/zygisk/${abi}.so"
  echo "Copying Main Module: $abi -> $dest_path"
  cp "$so_path" "$dest_path"
done

# 2. 处理 ShadowHook 动态库 (libshadowhook.so -> lib/${abi}/libshadowhook.so)
# 动态链接模式下，依赖库需要放在系统能找到的路径或 lib 目录
SHADOW_FILES=$(find "$BUILD_DIR" -name "libshadowhook.so")

if [ -n "$SHADOW_FILES" ]; then
    echo "$SHADOW_FILES" | while read -r so_path; do
      abi=$(basename "$(dirname "$so_path")")
      # Magisk 规范：依赖库存放在 lib/<abi>/ 下
      mkdir -p "$MAGISK_DIR/lib/$abi"
      dest_path="$MAGISK_DIR/lib/$abi/libshadowhook.so"
      echo "Copying Dependency: libshadowhook.so ($abi) -> $dest_path"
      cp "$so_path" "$dest_path"
    done
else
    echo "Warning: libshadowhook.so not found. If using static linking, ignore this."
fi

echo "--- Finished copying native libraries successfully ---"