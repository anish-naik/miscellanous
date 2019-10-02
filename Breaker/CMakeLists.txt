project(breaker)

cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_FLAGS "-g")
set(CMAKE_CXX_STANDARD 14)


include_directories(src)

add_executable(breaker
        main.cpp
        crypto/aes.cpp
        crypto/aes.h
        crypto/cryptoUtil.cpp
        crypto/cryptoUtil.h)
