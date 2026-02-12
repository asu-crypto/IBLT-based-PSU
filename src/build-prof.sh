#!/bin/bash

rm -rf ./build
mkdir -p ./build

# cmake --build ./build/ --target clean

cmake -S . -B ./build -DCMAKE_BUILD_TYPE=Profile -DCMAKE_PREFIX_PATH=./cryptoTools -DCMAKE_CXX_FLAGS=-pg -DCMAKE_EXE_LINKER_FLAGS=-pg -DCMAKE_SHARED_LINKER_FLAGS=-pg
cmake --build ./build 
