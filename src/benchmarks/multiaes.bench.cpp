#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <vector>
#include <unordered_set>
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/MultiKeyAES.h"

using osuCrypto::AES;
using osuCrypto::MultiKeyAES;
using osuCrypto::block;
using std::vector;

TEST_CASE("Multiple AES instances", "[naive]") {
    BENCHMARK_ADVANCED("Multiple AES instances")(Catch::Benchmark::Chronometer meter) {
        const size_t n = 1<<20; // 2^20 instances
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG
        std::vector<osuCrypto::AES> aes_instances(n);
        vector<block> pts(n), cts(n);

        for (size_t i = 0; i < n; ++i) {
            osuCrypto::block key = prng.get<osuCrypto::block>();
            pts[i] = prng.get<osuCrypto::block>();
            aes_instances[i].setKey(key);
        } 

        meter.measure([&]() {
            for (size_t i = 0; i < aes_instances.size(); ++i) {
                cts[i] = aes_instances[i].ecbEncBlock(pts[i]);
            }
        });
    };
}

TEST_CASE("Single AES instance reseting key", "[naive]") {
    BENCHMARK_ADVANCED("Single AES instance reseting key")(Catch::Benchmark::Chronometer meter) {
        const size_t n = 1<<20; // 2^20 instances
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG
        AES aes;
        vector<block> pts(n), cts(n), keys(n);

        for (size_t i = 0; i < n; ++i) {
            keys[i] = prng.get<osuCrypto::block>();
            pts[i] = prng.get<osuCrypto::block>();
        } 

        meter.measure([&]() {
            for (size_t i = 0; i < keys.size(); ++i) {
                aes.setKey(keys[i]);
                cts[i] = aes.ecbEncBlock(pts[i]);
            }
        });
    };
}

TEST_CASE("MultiKeyAES", "[cryptoTools]") {
    BENCHMARK_ADVANCED("MultiKeyAES")(Catch::Benchmark::Chronometer meter) {
        constexpr size_t n = 1<<20; // 2^20 instances
        osuCrypto::PRNG prng(osuCrypto::block(0x12345678, 0x9abcdef0)); // Seed the PRNG
        vector<block> keys(n);
        block* pts = new block[n];
        block* cts = new block[n];

        for (size_t i = 0; i < n; ++i) {
            keys[i] = prng.get<osuCrypto::block>();
            pts[i] = prng.get<osuCrypto::block>();
        }
        
        //MultiKeyAES<n> aes(keys);

        meter.measure([&]() {
            //aes.ecbEncNBlocks(pts,cts);
        });
    };
}
