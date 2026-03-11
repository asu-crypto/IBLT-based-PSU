#include "iblt_h5.hpp"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <cstring>
#include <array>
#include <xxhash.h>
#include <ankerl/unordered_dense.h>

using namespace osuCrypto;
using std::vector;
using std::unordered_set;
using std::array;

inline void hash_keys(AES& aes, vector<uint64_t>& keys, vector<uint32_t>& hash_out) {
    block* in_blks = new block[keys.size()*2];
    hash_out.resize(keys.size()*8);
    
    for (size_t i = 0; i < keys.size(); i++) {
        in_blks[2*i] = block(0, keys[i]);
        in_blks[2*i + 1] = block(11400095595373522076ULL, keys[i]);
    }

    aes.hashBlocks(in_blks, keys.size()*2 , (block*) hash_out.data());   

    delete [] in_blks;
}

inline void hash_keys(AES& aes, std::span<uint64_t> keys, std::vector<uint32_t>& hash_out) {
    block* in_blks = new block[keys.size()*2];
    hash_out.resize(keys.size()*8);
    
    for (size_t i = 0; i < keys.size(); i++) {
        in_blks[2*i] = block(0, keys[i]);
        in_blks[2*i + 1] = block(11400095595373522076ULL, keys[i]);
    }

    aes.hashBlocks(in_blks, keys.size()*2 , (block*) hash_out.data());   

    delete [] in_blks;
}

inline void hash_key(AES& aes, uint64_t key, size_t* hash_out) {
    block in_blks[2];
    block out_blks[2];

    in_blks[0] = block(0, key);
    in_blks[1] = block(11400095595373522076ULL, key);

    aes.hashBlocks(in_blks, 2, out_blks);

    uint32_t* data0 = (uint32_t*) out_blks[0].data();
    uint32_t* data1 = (uint32_t*) out_blks[1].data();

    hash_out[0] = static_cast<size_t>(data0[0]);
    hash_out[1] = static_cast<size_t>(data0[1]);
    hash_out[2] = static_cast<size_t>(data0[2]);
    hash_out[3] = static_cast<size_t>(data0[3]);
    hash_out[4] = static_cast<size_t>(data1[0]);
}

void iblt_5h::add(vector<uint64_t>& keys, vector<block>& seeds) {
    assert(keys.size() == seeds.size());

    std::vector<uint32_t> hash_out;
    hash_keys(aes, keys, hash_out);

    for (size_t i = 0; i < keys.size(); i++) {
        uint64_t key = keys[i];
        size_t hash_out_offset = i * 8;

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = (hash_out[hash_out_offset + j] % subtab_len) + j * subtab_len;
            this->sum[idx] ^= key;
            this->seedsum[idx] ^= seeds[i];
            this->cnt[idx]++;
        }
    }

}

void iblt_5h::add(std::span<uint64_t> keys, std::span<osuCrypto::block> seeds) {
    assert(keys.size() == seeds.size());

    std::vector<uint32_t> hash_out;
    hash_keys(aes, keys, hash_out);

    for (size_t i = 0; i < keys.size(); i++) {
        uint64_t key = keys[i];
        size_t hash_out_offset = i * 8;

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = (hash_out[hash_out_offset + j] % subtab_len) + j * subtab_len;
            this->sum[idx] ^= key;
            this->seedsum[idx] ^= seeds[i];
            this->cnt[idx]++;
        }
    }

}

void iblt_5h::add(ankerl::unordered_dense::set<uint64_t>& keys, std::span<osuCrypto::block> seeds) {
    assert(keys.size() == seeds.size());

    std::vector<uint32_t> hash_out;
    vector<uint64_t> keys_vec(keys.begin(), keys.end());
    hash_keys(aes, keys_vec, hash_out);

    this->add(keys_vec, seeds);

}

void iblt_5h::addKeys(vector<uint64_t>& keys) {
    std::vector<uint32_t> hash_out;
    hash_keys(aes, keys, hash_out);

    for (size_t i = 0; i < keys.size(); i++) {
        uint64_t key = keys[i];
        size_t hash_out_offset = i * 8;

        #pragma loop unroll
        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = (hash_out[hash_out_offset + j] % subtab_len) + j * subtab_len;
            this->sum[idx] ^= key;
            this->cnt[idx]++;
        }
    }
}

void iblt_5h::remove(vector<uint64_t>& keys, vector<block>& seeds) {
    assert(keys.size() == seeds.size());

    vector<uint32_t> inter_hash_out;
    hash_keys(aes, keys, inter_hash_out);

    for (size_t i = 0; i < keys.size(); i++) {
        uint64_t key = keys[i];
        size_t hash_out_offset = i * 8;

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = (inter_hash_out[hash_out_offset + j] % subtab_len) + j * subtab_len;
            sum[idx] ^= key;
            seedsum[idx] ^= seeds[i];
            cnt[idx]--;
        }
    }

}

void iblt_5h::removeKeys(vector<uint64_t>& keys) {
    vector<uint32_t> inter_hash_out;
    hash_keys(aes, keys, inter_hash_out);

    for (size_t i = 0; i < keys.size(); i++) {
        uint64_t key = keys[i];
        size_t hash_out_offset = i * 8;

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = (inter_hash_out[hash_out_offset + j] % subtab_len) + j * subtab_len;
            sum[idx] ^= key;
            cnt[idx]--;
        }
    }

}
    

void iblt_5h::is_peelable(unordered_set<uint64_t>& peeled_keys) {

    peeled_keys.reserve(this->threshold);

    const size_t MAX_QUEUE_LEN = 10*this->threshold;
    size_t queue_tail = 0;
    size_t queue_head = 0;
    uint64_t* queue = new uint64_t[MAX_QUEUE_LEN];

    size_t hash_out[NUM_HASH_FUNCS];

    for (size_t i = 0; i < tab_len; i++) {
        if (cnt[i] == 1) {
            uint64_t val = sum[i];
            peeled_keys.insert(val);

            hash_key(aes, val, hash_out);

            #pragma loop unroll
            for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
                size_t table_idx = (hash_out[j] % subtab_len) + j * subtab_len;

                sum[table_idx] ^= val;
                cnt[table_idx]--;
                
                queue[queue_tail] = table_idx;

                queue_tail = (queue_tail + 1) % MAX_QUEUE_LEN;
                #ifdef DEBUG_MODE
                    if (queue_tail == queue_head) {
                        std::cout << "Queue overflow" << std::endl;
                    }
                #endif
            }
        }
    }

    while (queue_head != queue_tail) {
        size_t table_idx = queue[queue_head];
        queue_head = (queue_head + 1) % MAX_QUEUE_LEN;

        if (cnt[table_idx] == 1) {
            uint64_t val = sum[table_idx];
            peeled_keys.insert(val);

            hash_key(aes, val, hash_out);

            #pragma unroll
            for (size_t i = 0; i < NUM_HASH_FUNCS; i++) {
                size_t table_idx = (hash_out[i] % subtab_len) + i * subtab_len;

                sum[table_idx] ^= val;
                cnt[table_idx]--;
                
                queue[queue_tail] = table_idx;
                queue_tail = (queue_tail + 1) % MAX_QUEUE_LEN;
                #ifdef DEBUG_MODE
                    if (queue_tail == queue_head) {
                        std::cout << "Queue overflow" << std::endl;
                    }
                #endif
            }
        }
    }

    delete[] queue;

}

void iblt_5h::unique_hash_evals(std::vector<uint64_t>& keys, osuCrypto::AlignedVector<size_t>& tab_idxs, BitVector& exclude_bm) {
    tab_idxs.reserve(keys.size() * NUM_HASH_FUNCS);
    std::memset(unique_hash_evals_bitmap, 0, tab_len * sizeof(bool));

    std::vector<uint32_t> hash_out;
    hash_keys(aes, keys, hash_out);

    for (size_t i = 0; i < keys.size(); i++) {
        uint64_t key = keys[i];
        size_t hash_out_offset = i * 8;

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = (hash_out[hash_out_offset + j] % subtab_len) + j * subtab_len;
            
            if (!unique_hash_evals_bitmap[idx] && exclude_bm[idx] == 0) {
                unique_hash_evals_bitmap[idx] = true;
                tab_idxs.push_back(idx);
            }

        }
    }
    
    
}

void iblt_5h::addKeys(ankerl::unordered_dense::set<uint64_t>& keys) {
    std::vector<uint32_t> hash_out;
    vector<uint64_t> keys_vec(keys.begin(), keys.end());
    hash_keys(aes, keys_vec, hash_out);

    this->addKeys(keys_vec);
}

//void iblt_5h::hash_eval(uint64_t key, size_t* tab_idxs) {
//    hash_keys(aes, key, tab_idxs);
//}