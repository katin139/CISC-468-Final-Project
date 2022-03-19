# CISC-468-Final-Project

This set up is for a linux system 

To run the vcpkg, you need to first download the git submodule:
```
git submodule update --init --recursive
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg/ install seal
```

In order to use vcpkg with CMake:
```
mkdir bin
cmake -B bin -S . -DCMAKE_TOOLCHAIN_FILE=/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build bin
```
