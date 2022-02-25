cmake_minimum_required(VERSION 3.17)
project(pe-parser C)

set(CMAKE_C_STANDARD 99)

add_executable(pe-parser main.c headers.h)