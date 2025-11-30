#!/bin/sh

# 接收来自 Gradle 的参数
BUILD_DIR="$1"
MAGISK_DIR="$2"
MODULE_LIB_NAME="$3"

# 检查参数是否存在
if [ -z "$BUILD_DIR" ] || [ -z "$MAGISK_DIR" ] || [ -z "$MODULE_LIB_NAME" ]; then
  echo "Usage: $0 <build_dir> <magisk_dir> <module_lib_name>"
  exit 1
fi

echo "Searching for .so files in: $BUILD_DIR"
echo "Target Magisk directory: $MAGISK_DIR"

# 创建 zygisk 目录
mkdir -p "$MAGISK_DIR/zygisk"

# 使用 find 命令查找所有架构的 .so 文件
# -path '*/stripped_native_libs/*' 是一个优化，优先在已剥离符号的目录中查找
find "$BUILD_DIR" -path '*/stripped_native_libs/*' -name "lib${MODULE_LIB_NAME}.so" | while read -r so_path; do
  # 从路径中提取 ABI (例如 arm64-v8a)
  abi=$(basename "$(dirname "$so_path")")
  
  echo "Found: $so_path for ABI: $abi"
  
  # 构造目标路径
  dest_path="$MAGISK_DIR/zygisk/${abi}.so"
  
  # 复制并重命名
  echo "Copying to $dest_path"
  cp "$so_path" "$dest_path"
done

echo "Finished copying native libraries."