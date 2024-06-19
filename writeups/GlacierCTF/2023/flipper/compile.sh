#!/bin/bash
# small script to compile and run the os
# Usage: ./compile.sh <OS code directory>
# Example: ./compile.sh ./sweb

# Type `make qemu` in the build directory to run the OS
# or `make qemugdb` to debug it with gdb

cd ~/Desktop/ctf/glacierCTF/flipper/build
rm -r *
cmake ../$1 -DDEBUG=1
make -j8

