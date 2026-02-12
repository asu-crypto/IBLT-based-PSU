#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <vector>
#include <unordered_set>
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"

using osuCrypto::BitVector;

TEST_CASE("bool array xoring", "[xor]") {
    BENCHMARK_ADVANCED("bool array xoring")(Catch::Benchmark::Chronometer meter) {
        const size_t nbits = 1 << 20; // 2^20 bits
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG

        bool* a1,* a2,* a3;
        a1 = new bool[nbits];
        a2 = new bool[nbits];
        a3 = new bool[nbits];

        for (size_t i = 0; i < nbits; ++i) {
            a1[i] = prng.get<bool>();
            a2[i] = prng.get<bool>();
        }

        meter.measure([&a1, &a2, &a3]() {
            for (size_t i = 0; i < nbits; ++i) {
                a3[i] = a1[i] ^ a2[i];
            }
        });
    
        delete[] a1;
        delete[] a2;
        delete[] a3;
    };
}

TEST_CASE("BitVector xoring", "[xor]") {
    BENCHMARK_ADVANCED("BitVector xoring")(Catch::Benchmark::Chronometer meter) {
        const size_t nbits = 1 << 20; // 2^20 bits
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG

        BitVector a1(nbits), a2(nbits), a3(nbits);

        a1.randomize(prng);
        a2.randomize(prng);

        meter.measure([&a1, &a2, &a3]() {
            a3 = a1 ^ a2; // BitVector xoring
        });
    
        
    };
}