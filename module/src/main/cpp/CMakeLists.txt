cmake_minimum_required(VERSION 3.22.1)

if (NOT DEFINED MODULE_NAME)
    project(zygisk_ns_proxy)
else ()
    project(${MODULE_NAME})
endif ()

set(CMAKE_CXX_STANDARD 20)

# ===================================================================
# 1. 定义控制开关 (默认 ON，即开启 Dobby)
# ===================================================================
option(ENABLE_DOBBY "Enable Dobby Hook Framework" OFF)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 创建模块目标
add_library(${MODULE_NAME} SHARED zygisk_module.cpp)

# 查找系统日志库
find_library(log-lib log)

# ===================================================================
# 2. 根据开关配置依赖
# ===================================================================
if (ENABLE_DOBBY)
    message(STATUS "Dobby Hook is ENABLED")
    
    # 引入 Dobby 静态库
    add_library(dobby STATIC IMPORTED)
    set_target_properties(dobby PROPERTIES
        IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI}/libdobby.a"
    )
    
    # 链接 Dobby 和 log
    target_link_libraries(${MODULE_NAME} dobby ${log-lib})
    
    # 定义 C++ 宏 USE_DOBBY，让源码知道是否开启
    target_compile_definitions(${MODULE_NAME} PRIVATE USE_DOBBY)
else ()
    message(STATUS "Dobby Hook is DISABLED")
    
    # 只链接 log，不链接 Dobby
    target_link_libraries(${MODULE_NAME} ${log-lib})
endif ()

# ===================================================================
# 编译器标志配置 (保持你原有的优化配置)
# ===================================================================

set(C_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CXX_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-exceptions -fno-rtti -fno-use-cxa-atexit -fno-threadsafe-statics -fvisibility-inlines-hidden")
set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--as-needed -Wl,--exclude-libs,ALL -Wl,-z,norelro -Wl,--hash-style=both")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()