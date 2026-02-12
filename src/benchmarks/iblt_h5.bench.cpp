#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include "../iblt_h5.hpp"
#include "cryptoTools/Crypto/PRNG.h"
#include <cstdint>
#include <vector>
#include <unordered_set>

using std::vector;
using std::unordered_set;

using namespace osuCrypto;

static void gen_rand_input_sets(PRNG& prng, std::vector<uint64_t>& set_vec, size_t set_size) {
    set_vec.clear();
    set_vec.reserve(set_size);
    unordered_set<uint64_t> set;
    set.reserve(set_size);
    
    while (set.size() < set_size) {
        uint64_t item = prng.get<uint64_t>();
        if (set.find(item) == set.end()) {
            set.insert(item);
            set_vec.push_back(item);
        }
    }

    assert(std::find(set_vec.begin(), set_vec.end(), 0) == set_vec.end());

}

TEST_CASE("element removal", "[remove]") {
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const size_t input_set_size = 1 << 16;
        const size_t remove_set_size = 1 << 16;

        PRNG test_prng(block(2418951022965926883ULL, 1180171376053301268ULL));

        vector<uint64_t> in_set;
        in_set.reserve(input_set_size);

        gen_rand_input_sets(test_prng, in_set, input_set_size);

        vector<uint64_t> remove_set;
        remove_set.reserve(remove_set_size);
        remove_set.insert(remove_set.end(), in_set.begin(), in_set.begin() + remove_set_size);

        iblt_5h iblt(block(1297368095696537325ULL, 14396362045511039940ULL), input_set_size, 3.5);
        iblt.add(in_set);

        REQUIRE(in_set.size() == input_set_size);
        REQUIRE(remove_set.size() == remove_set_size);

        meter.measure([&iblt,&remove_set]() {
                iblt.remove(remove_set);
            });
    };
}