cmake_minimum_required(VERSION 3.22.1)

if (NOT DEFINED MODULE_NAME)
    message(FATAL_ERROR "MODULE_NAME is not set")
else ()
    project(${MODULE_NAME})
endif ()

message("Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 20)

# 统一的编译标志
set(C_FLAGS
    "-fdata-sections -ffunction-sections"       # 允许垃圾回收
    "-fno-unwind-tables"                        # 禁用堆栈展开
)
set(CXX_FLAGS "-fno-exceptions -fno-rtti")      # 禁用 RTTI 和异常

# 统一的链接标志
set(LINKER_FLAGS
    "-ffixed-x18"                               # AArch64 ABI 标志
    "-Wl,--hash-style=both"
)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Release 模式下的极致优化
    set(C_FLAGS "${C_FLAGS} -Os -fvisibility=hidden -fvisibility-inlines-hidden -flto") # <<< 建议：使用 -Os 优化体积
    set(LINKER_FLAGS "${LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all -Wl,--icf=all -Wl,--as-needed -Wl,-Bsymbolic -flto") # <<< 修复：为链接器标志添加 -Wl,
else ()
    # Debug 模式
    set(C_FLAGS "${C_FLAGS} -O0 -Werror=format")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

find_library(log-lib log)
find_library(android android)

# 只编译 main.cpp
add_library(${MODULE_NAME} SHARED main.cpp)

# 建议将链接器标志放在库之前，虽然现代工具链通常能处理
target_link_libraries(${MODULE_NAME} log android)

# <<< 建议：可以移除此部分，因为 -Wl,--strip-all 已经处理了剥离
# if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
#     add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
#             COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${MODULE_NAME}.so")
# endif ()