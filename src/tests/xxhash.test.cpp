#include "catch2/catch_test_macros.hpp"
#include <cstdint>
#include <xxhash.h>
#include <iostream>

TEST_CASE("hashing using xxhash","[64bithash]") {
    
    uint64_t input = 1234567890123456789ULL;
    uint64_t seed = 3235907767789422689; // Seed can be set to any value, here we use 0 for simplicity
    uint64_t hash = XXH64(&input, sizeof(input), seed);
    
    std::cout << "Hash of " << input << " is: " << hash << std::endl;   

}