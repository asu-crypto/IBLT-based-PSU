#! /bin/sh

cmake -DCMAKE_BUILD_TYPE=Debug -S . -B ./build -DBUILD_TESTS=ON -DBUILD_BENCH=OFF

cmake --build ./build
