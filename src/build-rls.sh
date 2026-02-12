#!/bin/sh

rm -rf ./build
mkdir -p ./build

cmake -S . -B ./build -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCH=OFF -DBUILD_TESTS=OFF
cmake --build ./build 
