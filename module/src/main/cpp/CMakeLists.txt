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

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI}/libdobby.a"
)

# -------------------------------------------------------------------
# 模块构建
# -------------------------------------------------------------------

add_library(${MODULE_NAME} SHARED zygisk_module.cpp)

# 查找系统库
find_library(log-lib log)

# 链接库：使用静态链接模式
target_link_libraries(${MODULE_NAME} dobby ${log-lib})

# -------------------------------------------------------------------
# 极致静态链接配置 (最小化C++运行时依赖)
# -------------------------------------------------------------------

# 启用C++静态链接
set(CMAKE_CXX_STANDARD_LIBRARIES "-static-libgcc -static-libstdc++")

# C 编译器标志
set(C_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-stack-protector")

# C++ 编译器标志 (完全禁用C++运行时特性)
set(CXX_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-exceptions -fno-rtti -fno-use-cxa-atexit -fno-threadsafe-statics -fvisibility-inlines-hidden -fno-builtin -fno-merge-constants")

# 链接器标志：强制静态链接，排除动态依赖
set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--as-needed -Wl,--no-undefined -Wl,--exclude-libs,ALL -static-libgcc -static-libstdc++ -Wl,-Bstatic")

# 应用标志
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

# Release 模式自动 Strip
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()