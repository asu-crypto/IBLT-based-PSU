#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <vector>
#include <unordered_set>
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include <array>
#include <immintrin.h>

using namespace osuCrypto;

TEST_CASE("1-oo-2 OT message masking scenario", "[1-oo-2-ot][msg-masking]") {
    BENCHMARK_ADVANCED("1-oo-2 OT message masking scenario")(Catch::Benchmark::Chronometer meter) {

        const size_t num_ots = 2*23068700;

        BitVector masked_choices(num_ots);
        AlignedVector<std::array<uint64_t, 2>> maskedMsgs(num_ots);
        AlignedVector<std::array<osuCrypto::block, 2>> randMsgs(num_ots);
        AlignedVector<uint16_t> cnt(num_ots);
        AlignedVector<uint64_t> sum(num_ots);

        block b1, b2, r;
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG

        for (size_t i = 0; i < num_ots; ++i) {
            cnt[i] = prng.get<uint16_t>() % 3; // Random count between 0 and 2
            sum[i] = prng.get<uint64_t>();
        }

        masked_choices.randomize(prng);
        prng.get(randMsgs.data(), randMsgs.size());

        meter.measure([&]() {
            for (size_t i = 0; i < num_ots; ++i) {
                uint8_t choice = masked_choices[i];

                maskedMsgs[i][0] = randMsgs[i][choice].get<std::uint64_t>()[0];
                maskedMsgs[i][1] = (osuCrypto::block(0,((cnt[i]==1)*sum[i])) ^ randMsgs[i][1 ^ choice]).get<std::uint64_t>()[0];
            }
        });

        uint64_t sumc = 0;

        for (size_t i = 0; i < 10; ++i) {
            size_t j = prng.get<size_t>() % num_ots;
            sumc += j*(maskedMsgs[j][0] ^ maskedMsgs[j][1]);
        }

        std::cout << "Checksum: " << sumc << std::endl;

    };

}

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

TEST_CASE("simd block array xoring", "[xor]") {
    BENCHMARK_ADVANCED("simd block array xoring")(Catch::Benchmark::Chronometer meter) {

        const size_t num_blocks = 23068700;
        AlignedVector<block> blocks1(num_blocks);
        AlignedVector<block> blocks2(num_blocks);
        AlignedVector<block> result(num_blocks);
        osuCrypto::PRNG prng(osuCrypto::block(0x123456789abcdef, 0xfedcba9876543210));
        prng.get(blocks1.data(), blocks1.size());
        prng.get(blocks2.data(), blocks2.size());

        meter.measure([&]() {
            
            for (size_t i = 0; i < num_blocks; i += 4) {
                __m128i b1_0 = _mm_loadu_si128((__m128i*)&blocks1[i]);
                __m128i b1_1 = _mm_loadu_si128((__m128i*)&blocks1[i + 1]);
                __m128i b1_2 = _mm_loadu_si128((__m128i*)&blocks1[i + 2]);
                __m128i b1_3 = _mm_loadu_si128((__m128i*)&blocks1[i + 3]);

                __m128i b2_0 = _mm_loadu_si128((__m128i*)&blocks2[i]);
                __m128i b2_1 = _mm_loadu_si128((__m128i*)&blocks2[i + 1]);
                __m128i b2_2 = _mm_loadu_si128((__m128i*)&blocks2[i + 2]);
                __m128i b2_3 = _mm_loadu_si128((__m128i*)&blocks2[i + 3]);

                __m128i r0 = _mm_xor_si128(b1_0, b2_0);
                __m128i r1 = _mm_xor_si128(b1_1, b2_1);
                __m128i r2 = _mm_xor_si128(b1_2, b2_2);
                __m128i r3 = _mm_xor_si128(b1_3, b2_3);

                _mm_storeu_si128((__m128i*)&
                    result[i], r0);
                _mm_storeu_si128((__m128i*)&
                    result[i + 1], r1);
                _mm_storeu_si128((__m128i*)&    
                    result[i + 2], r2);
                _mm_storeu_si128((__m128i*)&
                    result[i + 3], r3);
            }
        });
    };
}

TEST_CASE("avx2 block array xoring", "[xor][avx2]") {
    BENCHMARK_ADVANCED("avx2 block array xoring")(Catch::Benchmark::Chronometer meter) {
        const size_t num_blocks = 23068700;
        AlignedVector<block> blocks1(num_blocks);
        AlignedVector<block> blocks2(num_blocks);
        AlignedVector<block> result(num_blocks);
        osuCrypto::PRNG prng(osuCrypto::block(0x123456789abcdef, 0xfedcba9876543210));
        prng.get(blocks1.data(), blocks1.size());
        prng.get(blocks2.data(), blocks2.size());

        meter.measure([&]() {
            constexpr size_t blocks_per_vec = 2; // 2 blocks * 128 bits = 256 bits
            size_t i = 0;
            for (; i + blocks_per_vec <= num_blocks; i += blocks_per_vec) {
                __m256i b1 = _mm256_loadu_si256((__m256i*)&blocks1[i]);
                __m256i b2 = _mm256_loadu_si256((__m256i*)&blocks2[i]);
                __m256i r = _mm256_xor_si256(b1, b2);
                _mm256_storeu_si256((__m256i*)&result[i], r);
            }
            // Handle any remaining blocks
            for (; i < num_blocks; ++i) {
                result[i] = blocks1[i] ^ blocks2[i];
            }
        });
    };
}

