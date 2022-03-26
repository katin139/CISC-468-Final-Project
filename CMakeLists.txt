cmake_minimum_required(VERSION 3.13)
project(tester)
set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES tester.cpp)

find_package(SEAL 4.0 REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(tester ${SOURCE_FILES})

target_link_libraries(tester SEAL::seal)
target_link_libraries(tester OpenSSL::SSL)
