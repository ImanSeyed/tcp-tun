cmake_minimum_required(VERSION 3.5)

project(tcp-tun)
include_directories(include/)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "src/*.c")
add_executable(${PROJECT_NAME} ${SOURCES}
        src/utils/tun.c
        include/utils/tun.h)
