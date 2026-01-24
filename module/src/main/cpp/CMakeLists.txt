cmake_minimum_required(VERSION 3.22.1)

if (NOT DEFINED MODULE_NAME)
    message(FATAL_ERROR "MODULE_NAME is not set")
else ()
    project(${MODULE_NAME})
endif ()

set(CMAKE_CXX_STANDARD 20)

# 编译优化与标志
set(C_FLAGS "-fdata-sections -ffunction-sections -fno-unwind-tables")
set(CXX_FLAGS "-fno-exceptions -fno-rtti")
set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(C_FLAGS "${C_FLAGS} -Os -fvisibility=hidden -fvisibility-inlines-hidden -flto")
    set(LINKER_FLAGS "${LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all -Wl,--icf=all -Wl,--as-needed -Wl,-Bsymbolic -flto")
else ()
    set(C_FLAGS "${C_FLAGS} -O0 -Werror=format")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

# 查找库
find_package(shadowhook REQUIRED CONFIG)
find_library(log-lib log)
find_library(android android)

# 主模块
add_library(${MODULE_NAME} SHARED main.cpp)
target_link_libraries(${MODULE_NAME} shadowhook::shadowhook ${log-lib} ${android})

# 新增库
add_library(mylib SHARED mylib.c)
target_link_libraries(${MODULE_NAME} 
    shadowhook::shadowhook_static  # 使用静态库
    ${log-lib} 
    ${android}
)
# 后处理剥离
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${MODULE_NAME}.so")
endif ()