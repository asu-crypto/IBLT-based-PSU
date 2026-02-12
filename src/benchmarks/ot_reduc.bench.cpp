#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <vector>
#include <unordered_set>
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include <immintrin.h>

using namespace osuCrypto;

TEST_CASE("naive block array xoring", "[xor]") {
    BENCHMARK_ADVANCED("naive block array xoring")(Catch::Benchmark::Chronometer meter) {

        const size_t num_blocks = 23068700; 
        AlignedVector<block> blocks1(num_blocks);
        AlignedVector<block> blocks2(num_blocks);
        AlignedVector<block> result(num_blocks);
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG
        prng.get(blocks1.data(), blocks1.size());
        prng.get(blocks2.data(), blocks2.size());

        meter.measure([&]() {
            for (size_t i = 0; i < num_blocks; ++i) {
                result[i] = blocks1[i] ^ blocks2[i];
            }
        });

    };

}

TEST_CASE("naive block array in place xoring", "[xor]") {
    BENCHMARK_ADVANCED("naive block array in place xoring")(Catch::Benchmark::Chronometer meter) {

        const size_t num_blocks = 23068700; 
        AlignedVector<block> blocks1(num_blocks);
        AlignedVector<block> blocks2(num_blocks);
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG
        prng.get(blocks1.data(), blocks1.size());
        prng.get(blocks2.data(), blocks2.size());

        meter.measure([&]() {
            for (size_t i = 0; i < num_blocks; ++i) {
                blocks1[i] ^= blocks2[i];
            }
        });

    };

}

