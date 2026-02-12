#pragma once

#include <unordered_map>
#include <unordered_set>
#include <sparsehash/dense_hash_map>
#include <set>
#include <vector>
#include <array>
#include <ankerl/unordered_dense.h>
#include "./iblt_h5.hpp"
#include "volePSI/RsOprf.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <cstdint>
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Common/BitVector.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"

namespace psu {

    inline size_t max_num_bin_probes(size_t iblt_tab_len, size_t num_iblt_hash_funcs, size_t sender_set_size, size_t recvr_set_size) {
        size_t max_union_set_size = sender_set_size + recvr_set_size;

        return iblt_tab_len + max_union_set_size*(num_iblt_hash_funcs-1);
    }

    inline size_t max_num_bin_probes_per_round(iblt_5h& iblt) {
        return iblt.tab_len;
    }

    struct Sender {
        ankerl::unordered_dense::set<uint64_t>* set_items;
        size_t recvr_set_size;
        size_t sndr_set_size;
        iblt_5h* iblt = nullptr;
        osuCrypto::block iblt_seed;
        double iblt_mult_fac = 3.5;
        size_t softspoken_ot_field_size = 2;
        bool oprf_reduced_rounds = false;
        size_t num_peel_iterations = 0;

        osuCrypto::block seed;
        osuCrypto::PRNG prng;

        volePSI::RsOprfSender* oprfSender = nullptr;
        
        osuCrypto::BitVector* otCorrRecvChoices = nullptr;
        osuCrypto::AlignedVector<osuCrypto::block>* otCorrRecvMsgs = nullptr;
        osuCrypto::AlignedVector<std::array<osuCrypto::block,2>>* otCorrSendMsgs = nullptr;

        osuCrypto::BitVector peeled_bm;
        osuCrypto::AlignedVector<std::array<uint64_t, 2>>* rMaskedMsgs = nullptr;
        std::vector<uint64_t> round_sender_owned_pld_els;
        osuCrypto::AlignedVector<size_t> iblt_remove_unique_hash_evals;
        //osuCrypto::AlignedVector<osuCrypto::block>* otCorrRecvMsgs128 = nullptr;
        //osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>* otCorrSendMsgs128 = nullptr;

        osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>> baseSend;
        
        size_t consumed_recv_ots = 0;
        size_t consumed_send_ots = 0;
        uint64_t curr_round = 0;

        Sender(const osuCrypto::block seed, 
               const size_t sndr_set_size, 
               const size_t recvr_set_size, 
               const osuCrypto::block iblt_seed,
               const double iblt_mult_fac,
               const size_t softspoken_ot_field_size,
               const bool oprf_reduced_rounds) : seed(seed), sndr_set_size(sndr_set_size), recvr_set_size(recvr_set_size), iblt_seed(iblt_seed), iblt_mult_fac(iblt_mult_fac), softspoken_ot_field_size(softspoken_ot_field_size), oprf_reduced_rounds(oprf_reduced_rounds) {
            prng.SetSeed(seed);

            auto otRecvr = new osuCrypto::SoftSpokenShOtReceiver<>();
            otRecvr->init(softspoken_ot_field_size, true);

            size_t iblt_tab_len = iblt_5h::calc_tab_len(recvr_set_size + sndr_set_size, iblt_mult_fac);
            size_t max_n_bin_probes = max_num_bin_probes(iblt_tab_len, iblt_5h::NUM_HASH_FUNCS, sndr_set_size, recvr_set_size);
            
            this->otCorrRecvChoices = new osuCrypto::BitVector(max_n_bin_probes + otRecvr->baseOtCount());
            this->otCorrRecvMsgs = new osuCrypto::AlignedVector<osuCrypto::block>(max_n_bin_probes + otRecvr->baseOtCount());
            //this->otCorrRecvMsgs128 = new osuCrypto::AlignedVector<osuCrypto::block>(max_n_bin_probes + otRecvr->baseOtCount());
            this->otCorrSendMsgs = new osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>(2*max_n_bin_probes);
            //this->otCorrSendMsgs128 = new osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>(2*max_n_bin_probes);

            round_sender_owned_pld_els.reserve(sndr_set_size + recvr_set_size);
            iblt_remove_unique_hash_evals.reserve(iblt_tab_len);
            peeled_bm.resize(iblt_tab_len);
            //sender_in_set.reserve(sndr_set_size);

            delete otRecvr;
        }

        ~Sender() {
            if (otCorrSendMsgs != nullptr) delete otCorrSendMsgs;
            if (otCorrRecvChoices != nullptr) delete otCorrRecvChoices;
            if (otCorrRecvMsgs != nullptr) delete otCorrRecvMsgs;
            if (oprfSender != nullptr) delete oprfSender;
            if (rMaskedMsgs != nullptr) delete rMaskedMsgs;
            if (iblt != nullptr) delete iblt;
            //if (otCorrRecvMsgs128 != nullptr) delete otCorrRecvMsgs128;
            //if (otCorrSendMsgs128 != nullptr) delete otCorrSendMsgs128;
        }

        coproto::task<void> setup(coproto::Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items);
        coproto::task<void> wan_setup(coproto::Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items);

        coproto::task<void> send(coproto::Socket& sock, ankerl::unordered_dense::set<uint64_t>& pld_els);    
    
    };

    struct Receiver {
        ankerl::unordered_dense::set<uint64_t>* set_items;
        size_t sndr_set_size;
        size_t recvr_set_size;
        iblt_5h* iblt = nullptr;
        osuCrypto::block iblt_seed;
        double iblt_mult_fac = 3.5;
        size_t softspoken_ot_field_size = 2;
        bool oprf_reduced_rounds = false;
        size_t num_peel_iterations = 0;
        
        osuCrypto::block seed;
        osuCrypto::PRNG prng;

        osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>* otCorrSendMsgs = nullptr;
        osuCrypto::BitVector* otCorrRecvChoices = nullptr;
        osuCrypto::AlignedVector<osuCrypto::block>* otCorrRecvMsgs = nullptr;

        // The following datastructures are allocated as part of of the sender to avoid unnecessary memory allocations during the protocol.
        osuCrypto::AlignedVector<std::array<uint64_t, 2>>* rMaskedMsgs = nullptr;
        std::vector<uint64_t> round_pld_els;
        std::vector<uint64_t> round_recvr_owned_pld_els;
        osuCrypto::AlignedVector<size_t> iblt_remove_unique_hash_evals;
        std::vector<osuCrypto::block> round_recvr_owned_pld_seeds;     
        osuCrypto::BitVector peeled_bm;   

        osuCrypto::BitVector baseChoices;
        osuCrypto::AlignedVector<osuCrypto::block> baseRecv;

        size_t consumed_send_ots = 0;
        size_t consumed_recv_ots = 0;
        uint64_t curr_round = 0;

        Receiver(const osuCrypto::block seed, 
                 const size_t recvr_set_size, 
                 const size_t sndr_set_size, 
                 const osuCrypto::block iblt_seed,
                 const double iblt_mult_fac,
                 const size_t softspoken_ot_field_size,
                 const bool oprf_reduced_rounds) : seed(seed), recvr_set_size(recvr_set_size), sndr_set_size(sndr_set_size), iblt_seed(iblt_seed), iblt_mult_fac(iblt_mult_fac), softspoken_ot_field_size(softspoken_ot_field_size), oprf_reduced_rounds(oprf_reduced_rounds) {
            prng.SetSeed(seed);

            auto otRecvr = new osuCrypto::SoftSpokenShOtReceiver<>();
            otRecvr->init(softspoken_ot_field_size, true);

            size_t iblt_tab_len = iblt_5h::calc_tab_len(recvr_set_size + sndr_set_size, iblt_mult_fac);
            size_t max_n_bin_probes = max_num_bin_probes(iblt_tab_len, iblt_5h::NUM_HASH_FUNCS, sndr_set_size, recvr_set_size);

            this->otCorrSendMsgs = new osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>(max_n_bin_probes + otRecvr->baseOtCount());
            this->otCorrRecvChoices = new osuCrypto::BitVector(2*max_n_bin_probes);
            this->otCorrRecvMsgs = new osuCrypto::AlignedVector<osuCrypto::block>(2*max_n_bin_probes);
            this->round_pld_els.reserve(recvr_set_size + sndr_set_size);
            this->round_recvr_owned_pld_els.reserve(recvr_set_size);
            this->iblt_remove_unique_hash_evals.reserve(iblt_tab_len);
            this->round_recvr_owned_pld_seeds.reserve(recvr_set_size);
            peeled_bm.resize(iblt_tab_len);
            //this->recvr_in_set.reserve(recvr_set_size);

            delete otRecvr;
        }

        ~Receiver() {
            if (otCorrSendMsgs != nullptr) delete otCorrSendMsgs;
            if (otCorrRecvChoices != nullptr) delete otCorrRecvChoices;
            if (otCorrRecvMsgs != nullptr) delete otCorrRecvMsgs;
            if (rMaskedMsgs != nullptr) delete rMaskedMsgs;
            if (iblt != nullptr) delete iblt;
            //if (otCorrRecvMsgs128 != nullptr) delete otCorrRecvMsgs128;
            //if (otCorrSendMsgs128 != nullptr) delete otCorrSendMsgs128;
        }

        coproto::task<void> setup(coproto::Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items);
        coproto::task<void> wan_setup(coproto::Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items);
        //coproto::task<void> recv(coproto::Socket& sock, std::set<size_t>& q_set, iblt_5h& iblt);
        coproto::task<void> recv(coproto::Socket& sock, ankerl::unordered_dense::set<uint64_t>& pld_els);

    };

    void msk_cnt0_choice_bits(size_t iblt_tab_len, 
                              size_t* cnt, 
                              osuCrypto::BitVector& maskedChoices, 
                              osuCrypto::BitVector& randChoices,
                              size_t randChoicesOffset);

    void msk_cnt0_choice_bits(osuCrypto::AlignedVector<size_t>& probe_idxs, 
                              size_t* cnt, 
                              osuCrypto::BitVector& maskedChoices, 
                              osuCrypto::BitVector& randChoices,
                              size_t randChoicesOffset);

};
