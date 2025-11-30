cmake_minimum_required(VERSION 3.22.1)

if (NOT DEFINED MODULE_NAME)
    message(FATAL_ERROR "MODULE_NAME is not set")
else ()
    project(${MODULE_NAME})
endif ()

message("Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 20)

# <<< 修复：将所有标志放在一个字符串中，用空格分隔
set(C_FLAGS "-fdata-sections -ffunction-sections -fno-unwind-tables")
set(CXX_FLAGS "-fno-exceptions -fno-rtti")

# <<< 修复：将所有标志放在一个字符串中，用空格分隔
set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Release 模式下的极致优化
    set(C_FLAGS "${C_FLAGS} -Os -fvisibility=hidden -fvisibility-inlines-hidden -flto")
    set(LINKER_FLAGS "${LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all -Wl,--icf=all -Wl,--as-needed -Wl,-Bsymbolic -flto")
else ()
    # Debug 模式
    set(C_FLAGS "${C_FLAGS} -O0 -Werror=format")
endif ()

# 将我们自定义的标志追加到 CMake 的默认标志后面
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

find_library(log-lib log)
find_library(android android)

# 只编译 main.cpp
add_library(${MODULE_NAME} SHARED main.cpp)

target_link_libraries(${MODULE_NAME} log android)

# 由于 -Wl,--strip-all 已经处理了剥离，这一步是可选的，但保留也无害
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${MODULE_NAME}.so")
endif ()