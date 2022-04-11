# CISC-468-Final-Project

This set up is for a linux system 

Build Microsoft SEAL globaly to install go here and following the instructions : 
https://github.com/microsoft/SEAL#installing-microsoft-seal

Then clone this repository and run the following:
To run the vcpkg, you need to first download the git submodule:
```
git submodule update --init --recursive
./vcpkg/bootstrap-vcpkg.sh
```

In order to use vcpkg with CMake and run the program:
```
mkdir bin
cmake -B bin -S . -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build bin
./bin/tester
```
