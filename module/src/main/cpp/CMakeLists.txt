cmake_minimum_required(VERSION 3.22.1)

if (NOT DEFINED MODULE_NAME)
    project(zygisk_media_block)
else ()
    project(${MODULE_NAME})
endif ()

set(CMAKE_CXX_STANDARD 20)

# 极致优化：减小体积并增强隐藏性
set(C_FLAGS "-fdata-sections -ffunction-sections -fno-stack-protector -fvisibility=hidden")
set(CXX_FLAGS "-fno-exceptions -fno-rtti -fvisibility-inlines-hidden")
set(LINKER_FLAGS "-Wl,--gc-sections -Wl,--strip-all -Wl,--exclude-libs,ALL")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")

# 查找 ShadowHook
find_package(shadowhook REQUIRED CONFIG)

# 仅保留主模块，删除之前报错的 mylib
add_library(${MODULE_NAME} SHARED main.cpp)

# 关键：链接 shadowhook_static (静态库版本)
# 注意：Prefab 默认可能只提供 shadowhook::shadowhook，它会自动根据依赖选择
target_link_libraries(${MODULE_NAME}
    log 
    android
)

# 强制剥离所有符号
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${MODULE_NAME}.so")
endif ()