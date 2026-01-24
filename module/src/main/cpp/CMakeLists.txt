# 设置 CMake 最低版本
cmake_minimum_required(VERSION 3.22.1)

# 设置项目名
if (NOT DEFINED MODULE_NAME)
    project(zygisk_ns_proxy)
else ()
    project(${MODULE_NAME})
endif ()

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 20)

# ----------------- 嵌入式 Hook 库配置 -----------------
# 确定要嵌入的 libshadowhook.so 路径
if (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    set(SHADOWHOOK_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libshadowhook-64.so")
elseif (CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
    set(SHADOWHOOK_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libshadowhook-32.so")
else ()
    message(FATAL_ERROR "Unsupported ABI: ${CMAKE_ANDROID_ARCH_ABI}. Only arm64-v8a and armeabi-v7a are supported for embedded loading.")
endif ()

# 定义输出头文件路径
set(SHADOWHOOK_BLOB_HEADER "${CMAKE_CURRENT_BINARY_DIR}/shadowhook_blob.h")

# 使用 xxd 命令将 .so 文件转换为 C 数组
# 变量名将是 shadowhook_blob 和 shadowhook_blob_len
add_custom_command(
    OUTPUT ${SHADOWHOOK_BLOB_HEADER}
    COMMAND xxd -i ${SHADOWHOOK_LIB_PATH}
    > ${SHADOWHOOK_BLOB_HEADER}
    DEPENDS ${SHADOWHOOK_LIB_PATH}
    VERBATIM
)

# ----------------- 模块库配置 -----------------
# 添加你的模块库，源文件是 zygisk_module.cpp
add_library(${MODULE_NAME} SHARED zygisk_module.cpp)

# 确保编译时能找到自动生成的头文件
target_include_directories(${MODULE_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# 链接 Android 日志库
find_library(log-lib log)
target_link_libraries(${MODULE_NAME} ${log-lib})

# ----------------- 优化选项 -----------------
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-exceptions -fno-rtti -fvisibility-inlines-hidden")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections")

# 在 Release 构建时剥离符号
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()