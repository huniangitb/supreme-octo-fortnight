cmake_minimum_required(VERSION 3.22.1)

if (NOT DEFINED MODULE_NAME)
    project(zygisk_ns_proxy)
else ()
    project(${MODULE_NAME})
endif ()

set(CMAKE_CXX_STANDARD 20)

# -------------------------------------------------------------------
# Dobby 静态库配置 (硬核植入)
# -------------------------------------------------------------------

# 1. 头文件路径：既然你说头文件在代码同位置，直接把当前目录加进去
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 2. 导入静态库：根据 NDK 提供的 ABI 变量自动寻找对应架构的 .a 文件
# 路径格式：./arm64-v8a/libdobby.a
add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI}/libdobby.a"
)

# -------------------------------------------------------------------
# 模块构建
# -------------------------------------------------------------------

add_library(${MODULE_NAME} SHARED zygisk_module.cpp)

# 查找系统日志库
find_library(log-lib log)

# 链接库：把 Dobby 静态编入你的动态库中
# 注意：dobby 必须在 log-lib 之前（虽然静态库通常顺序不敏感，但养成好习惯）
target_link_libraries(${MODULE_NAME} dobby ${log-lib})

# -------------------------------------------------------------------
# 编译选项与优化 (保持你的犀利风格)
# -------------------------------------------------------------------

# 编译器标志
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-exceptions -fno-rtti -fvisibility-inlines-hidden")

# 链接器标志：GC Sections 是必须的，把没用到的符号全剔除，减小体积
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections")

# Release 模式自动 Strip
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()