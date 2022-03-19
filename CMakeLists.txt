cmake_minimum_required(VERSION 3.13)
project(tester)
set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES tester.cpp)

find_package(SEAL CONFIG REQUIRED)

add_executable(tester ${SOURCE_FILES})

target_link_libraries(tester SEAL::seal)
