cmake_minimum_required(VERSION 3.22.1)

# 如果 Gradle 没有传 MODULE_NAME，给它一个默认值，防止报错
if (NOT DEFINED MODULE_NAME)
    set(MODULE_NAME "imgui_modmenu") # 改为报错脚本期望的名称
endif ()

project(${MODULE_NAME})

set(CMAKE_CXX_STANDARD 20)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 创建动态库，名称使用变量
add_library(${MODULE_NAME} SHARED zygisk_module.cpp)

find_library(log-lib log)

# 链接日志库
target_link_libraries(${MODULE_NAME} ${log-lib})

# ===================================================================
# 编译器标志配置 (严格 C 风格，无 C++ 库依赖，隐藏符号)
# ===================================================================
set(C_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CXX_FLAGS "${C_FLAGS} -fno-exceptions -fno-rtti -fno-use-cxa-atexit -fno-threadsafe-statics -fvisibility-inlines-hidden")
set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--exclude-libs,ALL -Wl,-z,norelro")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

# 编译后自动 Strip 符号表
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()