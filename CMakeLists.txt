cmake_minimum_required(VERSION 3.10)
project(IslemYoneticisi)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/utf-8)
    add_compile_options(/W4)
    add_definitions(-DNOMINMAX)
endif()

add_executable(IslemYoneticisi main.cpp)

target_link_libraries(IslemYoneticisi psapi wtsapi32 userenv) 