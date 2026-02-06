cmake_minimum_required(VERSION 3.22.1)
project(ZygiskPropHidden)

set(CMAKE_CXX_STANDARD 20)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(module SHARED zygisk_module.cpp)
find_library(log-lib log)

target_link_libraries(module ${log-lib})

# 编译优化与隐藏符号
set(C_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CXX_FLAGS "${C_FLAGS} -fno-exceptions -fno-rtti -fno-use-cxa-atexit -fno-threadsafe-statics -fvisibility-inlines-hidden")
set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--exclude-libs,ALL -Wl,-z,norelro")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET module POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:module>")
endif ()