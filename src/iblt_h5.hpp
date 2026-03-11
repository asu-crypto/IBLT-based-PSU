#pragma once

#include <iostream>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include <cmath>
#include <span>
#include <array>
#include <ankerl/unordered_dense.h>
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"

struct iblt_5h {
    static constexpr size_t NUM_HASH_FUNCS = 5;
    
    uint64_t* sum;
    osuCrypto::block* seedsum;
    size_t* cnt;
    bool* unique_hash_evals_bitmap = nullptr;
    size_t threshold;
    size_t tab_len;
    size_t subtab_len;
    osuCrypto::AES aes;
    
    osuCrypto::AlignedVector<uint64_t>* sum_vec;
    osuCrypto::AlignedVector<osuCrypto::block>* seedsum_vec;
    osuCrypto::AlignedVector<size_t>* cnt_vec;

    iblt_5h(osuCrypto::block hash_seed, size_t threshold, double mult_fac) {
        this->threshold = threshold;
        this->subtab_len = calc_subtab_len(threshold, mult_fac);
        this->tab_len = calc_tab_len(threshold, mult_fac);
        this->aes.setKey(hash_seed);
        this->unique_hash_evals_bitmap = new bool[this->tab_len]();
        this->sum_vec = new osuCrypto::AlignedVector<uint64_t>(this->tab_len);
        this->seedsum_vec = new osuCrypto::AlignedVector<osuCrypto::block>(this->tab_len);
        this->cnt_vec = new osuCrypto::AlignedVector<size_t>(this->tab_len);
        
        this->sum = this->sum_vec->data();
        this->seedsum = this->seedsum_vec->data();
        this->cnt = this->cnt_vec->data();
        
    }

    iblt_5h(const iblt_5h&) = default;

    ~iblt_5h() {
        delete[] unique_hash_evals_bitmap;
        delete sum_vec;
        delete seedsum_vec;
        delete cnt_vec;
    } 

    void add(std::vector<uint64_t>& keys, std::vector<osuCrypto::block>& seeds);
    void add(std::span<uint64_t> keys, std::span<osuCrypto::block> seeds);
    void add(ankerl::unordered_dense::set<uint64_t>& keys, std::span<osuCrypto::block> seeds);
    void addKeys(std::vector<uint64_t>& keys);
    void addKeys(ankerl::unordered_dense::set<uint64_t>& keys);
    //void remove(std::vector<uint64_t>& keys, std::vector<size_t>& unique_hash_evals);
    void remove(std::vector<uint64_t>& keys, std::vector<osuCrypto::block>& seeds);
    void removeKeys(std::vector<uint64_t>& keys);
    void is_peelable(std::unordered_set<uint64_t>& peeled_keys);
    void unique_hash_evals(std::vector<uint64_t>& keys, osuCrypto::AlignedVector<size_t>& tab_idx, osuCrypto::BitVector& exclude_bm);
    void hash_eval(uint64_t key, size_t* tab_idxs);

    //void peel(std::vector<std::unordered_set<uint64_t>*>& peeled_keys_by_round);

    static constexpr size_t calc_subtab_len(size_t threshold, double mult_fac) {
        return static_cast<size_t>(ceil((mult_fac * ((double) threshold)) / ((double) NUM_HASH_FUNCS)));
    }

    static constexpr size_t calc_tab_len(size_t threshold, double mult_fac) {
        return NUM_HASH_FUNCS * iblt_5h::calc_subtab_len(threshold, mult_fac);
    }

};
