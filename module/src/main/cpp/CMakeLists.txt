# 设置 CMake 最低版本
cmake_minimum_required(VERSION 3.22.1)

# 设置项目名，可以从 build.gradle 传入，也可以在这里写死
if (NOT DEFINED MODULE_NAME)
    project(zygisk_ns_proxy) # 写一个默认名字
else ()
    project(${MODULE_NAME})
endif ()

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 20)

# ------------------------------------------------------------------
#  移除所有和 find_package 以及 shadowhook 相关的链接指令
#  我们不需要编译时链接，因为代码里用了 dlopen
# ------------------------------------------------------------------

# 添加你的模块库，源文件是 main.cpp
# 假设你的模块名叫 ${MODULE_NAME}，这是由 Zygisk 模板定义的
add_library(${MODULE_NAME} SHARED main.cpp)

# 只链接 Android 日志库，这是我们唯一需要的外部库
find_library(log-lib log)
target_link_libraries(${MODULE_-NAME} ${log-lib})

# ----------------- 可选：保留你的优化选项 -----------------
# 这些优化选项对于 Zygisk 模块来说是很好的，可以保留
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-exceptions -fno-rtti -fvisibility-inlines-hidden")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections")

# 在 Release 构建时剥离符号
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()