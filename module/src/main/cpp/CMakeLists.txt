cmake_minimum_required(VERSION 3.22.1)

# ===================================================================
# 1. 项目基础配置
# ===================================================================
if (NOT DEFINED MODULE_NAME)
    project(zygisk_prop_mod)
else ()
    project(${MODULE_NAME})
endif ()

# Zygisk 接口通常需要 C++ 编译环境，但我们内部逻辑使用 C
set(CMAKE_CXX_STANDARD 20)

# 默认开启 Dobby，因为这是核心需求
option(ENABLE_DOBBY "Enable Dobby Hook Framework" ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 模块主源文件
add_library(${MODULE_NAME} SHARED zygisk_module.cpp)

# 查找安卓系统日志库
find_library(log-lib log)

# ===================================================================
# 2. Dobby 库配置
# ===================================================================
if (ENABLE_DOBBY)
    message(STATUS "Dobby Hook is ENABLED")
    
    # 定义 Dobby 静态库
    # 路径匹配你要求的：当前目录/${ANDROID_ABI}/libdobby.a
    add_library(dobby STATIC IMPORTED)
    set_target_properties(dobby PROPERTIES
        IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI}/libdobby.a"
    )
    
    # 链接 Dobby 和 log
    target_link_libraries(${MODULE_NAME} dobby ${log-lib})
    
    # 定义宏以便在代码中使用 #ifdef USE_DOBBY
    target_compile_definitions(${MODULE_NAME} PRIVATE USE_DOBBY)
else ()
    message(STATUS "Dobby Hook is DISABLED")
    target_link_libraries(${MODULE_NAME} ${log-lib})
endif ()

# ===================================================================
# 3. 严格限制 C++ 库使用 & 优化体积
# ===================================================================

# C 编译标志
set(C_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")

# C++ 编译标志：通过禁用异常和 RTTI 来最小化对 C++ 标准库的依赖
# 同时加入你要求的优化参数
set(CXX_FLAGS "${C_FLAGS} -fno-exceptions -fno-rtti -fno-use-cxa-atexit -fno-threadsafe-statics -fvisibility-inlines-hidden")

# 链接器标志：强制排除不必要的库引用，gc-sections 用于剔除无用代码
set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--as-needed -Wl,--exclude-libs,ALL -Wl,-z,norelro -Wl,--hash-style=both")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

# ===================================================================
# 4. 后处理：Strip 符号表
# ===================================================================
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()