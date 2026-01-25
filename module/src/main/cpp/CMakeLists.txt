cmake_minimum_required(VERSION 3.22.1)

if (NOT DEFINED MODULE_NAME)
    project(zygisk_ns_proxy)
else ()
    project(${MODULE_NAME})
endif ()

set(CMAKE_CXX_STANDARD 20)

# 设置不使用C++标准库
set(CMAKE_CXX_STANDARD_LIBRARIES "")
set(CMAKE_EXE_LINKER_FLAGS "-nostdlib++")

# -------------------------------------------------------------------
# Dobby 静态库配置
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

# 链接库
target_link_libraries(${MODULE_NAME} dobby ${log-lib})

# -------------------------------------------------------------------
# 无C++运行时依赖配置
# -------------------------------------------------------------------

set(C_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-stack-protector")
set(CXX_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden -fno-exceptions -fno-rtti -fno-use-cxa-atexit -fno-threadsafe-statics -fvisibility-inlines-hidden -nostdinc++")

set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--as-needed -Wl,--no-undefined -Wl,--exclude-libs,ALL -nodefaultlibs")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

# Release 模式自动 Strip
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${MODULE_NAME}>")
endif ()