#!/bin/sh

rm -rf ./build
mkdir -p ./build

cmake -S . -B ./build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON -DBUILD_BENCH=OFF
cmake --build ./build 
