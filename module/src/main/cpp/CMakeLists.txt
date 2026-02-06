cmake_minimum_required(VERSION 3.22.1)

# ===================================================================
# 1. 项目与模块基础配置
# ===================================================================
if (NOT DEFINED MODULE_NAME)
    set(MODULE_NAME "zygisk_ns_proxy")
endif ()

project(${MODULE_NAME})

# 强制禁用 C++ 标准库 (关键：避免链接 libc++_shared / libc++_static)
set(ANDROID_STL "none")

# Zygisk 框架虽然使用 C++ 类定义，但我们将代码限制在 C 逻辑
set(CMAKE_CXX_STANDARD 17)

# ===================================================================
# 2. 控制开关
# ===================================================================
option(ENABLE_DOBBY "Enable Dobby Hook Framework" OFF)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 源文件
add_library(${MODULE_NAME} SHARED zygisk_module.cpp)

# 查找必要的系统 C 库
find_library(log-lib log)
# 当 ANDROID_STL 为 none 时，有时需要手动链接基本的 c 和 m 库
find_library(c-lib c)
find_library(m-lib m)

# ===================================================================
# 3. 依赖链接配置
# ===================================================================
if (ENABLE_DOBBY)
    message(STATUS "Dobby Hook is ENABLED")
    add_library(dobby STATIC IMPORTED)
    set_target_properties(dobby PROPERTIES
        IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI}/libdobby.a"
    )
    target_link_libraries(${MODULE_NAME} dobby ${log-lib} ${c-lib} ${m-lib})
    target_compile_definitions(${MODULE_NAME} PRIVATE USE_DOBBY)
else ()
    message(STATUS "Dobby Hook is DISABLED (Pure C Reporting Mode)")
    # 仅链接日志库和基础 C 库
    target_link_libraries(${MODULE_NAME} ${log-lib} ${c-lib} ${m-lib})
endif ()

# ===================================================================
# 4. 严苛的编译器标志 (最小化体积与稳定性)
# ===================================================================

# -fno-rtti -fno-exceptions: 彻底禁用 C++ 特性
# -nostdlib++: 确保不使用任何 C++ 标准头文件路径（如果代码中误用了会报错）
set(COMMON_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CXX_ONLY_FLAGS "-fno-exceptions -fno-rtti -fno-use-cxa-atexit -fno-threadsafe-statics -fvisibility-inlines-hidden")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS} ${CXX_ONLY_FLAGS}")

# 链接器优化
# --gc-sections: 移除未使用的代码段
# --exclude-libs,ALL: 隐藏所有符号，防止冲突
set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--as-needed -Wl,--exclude-libs,ALL -Wl,-z,norelro -Wl,--hash-style=both")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

# ===================================================================
# 5. 构建后处理 (Strip 符号表)
# ===================================================================
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()