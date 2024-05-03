cmake_minimum_required(VERSION 3.5)

project(tcp-tun)
include_directories(include/)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
set(CMAKE_C_FLAGS "-Wall -Wextra ${CMAKE_C_FLAGS}")
file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "src/*.c")
add_executable(${PROJECT_NAME} ${SOURCES})
