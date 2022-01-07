cmake_minimum_required(VERSION 3.20)
project(teethgrind)

set(CMAKE_CXX_STANDARD 14)

add_library(teeCgrind SHARED library.cpp)
