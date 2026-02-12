#include "psu.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "volePSI/RsOprf.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/BitIterator.h"

#include "libOTe/Vole/SoftSpokenOT/SmallFieldVole.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVole.h"
#include "libOTe/Tools/RepetitionCode.h"

#include <thread>
#include <vector>
#include <random>
#include <span>
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

using psu::Sender;
using psu::Receiver;
using volePSI::RsOprfSender;
using volePSI::RsOprfReceiver;
using std::vector;
using std::array;
using coproto::Socket;
using volePSI::Proto;
using namespace osuCrypto;

static constexpr size_t IBLT_NUM_HASH_FUNCS = 5;

static coproto::task<void> setup_sender_eq_seeds(Socket& sock, 
                                                 Sender& sender) {
    MC_BEGIN(Proto, &sock, &sender,
             vals = (vector<block>*) nullptr,
             evalOut = (vector<block>*) nullptr,
             n_sndr_qs = size_t(0),
             threshold = size_t(0),
             otRecvr = (SoftSpokenShOtReceiver<>*) nullptr);
        otRecvr = new SoftSpokenShOtReceiver<>();
        otRecvr->init(sender.softspoken_ot_field_size, true);
        sender.oprfSender = new RsOprfSender();
        vals = new vector<block>();
        evalOut = new vector<block>();
        
        sender.baseSend.resize(otRecvr->baseOtCount());

        MC_AWAIT(sender.oprfSender->send(sender.recvr_set_size + otRecvr->baseOtCount(), sender.prng, sock, 0, sender.oprf_reduced_rounds));

        n_sndr_qs = 2*otRecvr->baseOtCount();

        vals->resize(n_sndr_qs);
        evalOut->resize(n_sndr_qs);

        for (size_t i = 0; i < n_sndr_qs; i = i + 2) {
            (*vals)[i] = block(1, i/2);
            (*vals)[i+1] = block(2, i/2);
        }

        sender.oprfSender->eval(*vals, *evalOut);

        for (size_t i = 0; i < n_sndr_qs; i = i + 2) {
            sender.baseSend[i/2][0] = (*evalOut)[i];
            sender.baseSend[i/2][1] = (*evalOut)[i+1];
        }

        threshold = sender.recvr_set_size + sender.sndr_set_size;

        sender.iblt = new iblt_5h(sender.iblt_seed, threshold, sender.iblt_mult_fac);
        sender.iblt->addKeys(*(sender.set_items));

        delete vals;
        delete evalOut;
        delete otRecvr;

    MC_END();
}

static coproto::task<void> setup_recvr_eq_seeds(Socket& sock, 
                                                Receiver& recvr) {
    MC_BEGIN(Proto, &sock, &recvr,
             oprfRecvr = (RsOprfReceiver*) nullptr,
             vals = (vector<block>*) nullptr,
             recvOut = (vector<block>*) nullptr,
             eq_seed_span = std::span<block>(),
             threshold = size_t(0),
             i = size_t(0),
             otSender = (SoftSpokenShOtSender<>*) nullptr);
        otSender = new SoftSpokenShOtSender<>();
        otSender->init(recvr.softspoken_ot_field_size, true);
        oprfRecvr = new RsOprfReceiver();
        vals = new vector<block>();
        recvOut = new vector<block>();


        recvr.baseChoices.resize(otSender->baseOtCount()); 
        recvr.baseRecv.resize(otSender->baseOtCount());

        recvr.baseChoices.randomize(recvr.prng);
        vals->resize(recvr.set_items->size() + otSender->baseOtCount());
        recvOut->resize(recvr.set_items->size() + otSender->baseOtCount());

        i=0;
        for (uint64_t set_item : *(recvr.set_items)) {
            (*vals)[i] = block(0, set_item);
            ++i;
        }

        /*for (size_t i = 0; i < recvr.set_items->size(); ++i) {
            (*vals)[i] = block(0, recvr.set_items[i]);
        }*/
        for (size_t i = 0; i < otSender->baseOtCount(); ++i) {
            if(recvr.baseChoices[i] == true) {
                (*vals)[i+recvr.set_items->size()] = block(2, i);
            } else {
                (*vals)[i+recvr.set_items->size()] = block(1, i);
            }
        }

        MC_AWAIT(oprfRecvr->receive(*vals, *recvOut, recvr.prng, sock, 0, recvr.oprf_reduced_rounds));

        eq_seed_span = std::span<block>(recvOut->data(), recvr.set_items->size());

        threshold = recvr.recvr_set_size + recvr.sndr_set_size;

        recvr.iblt = new iblt_5h(recvr.iblt_seed, threshold, recvr.iblt_mult_fac);
        recvr.iblt->add(*(recvr.set_items), eq_seed_span);

        for (size_t i = 0; i < otSender->baseOtCount(); ++i) {
            recvr.baseRecv[i] = (*recvOut)[i + recvr.set_items->size()];
        }

        delete oprfRecvr;
        delete vals;
        delete recvOut;
        delete otSender;

    MC_END();
}

/*static size_t max_n_bin_probes(iblt_5h& iblt, size_t sender_set_size, size_t recvr_set_size) {
    size_t num_iblt_hash_funcs = iblt.NUM_HASH_FUNCS;
    size_t iblt_tab_len = iblt.tab_len;
    size_t max_union_set_size = sender_set_size + recvr_set_size;

    return iblt_tab_len + max_union_set_size*(num_iblt_hash_funcs);
}

static size_t max_n_bin_probes_per_round(iblt_5h& iblt) {
    return iblt.tab_len;
}
    */

static coproto::task<void> setup_receiver_ots_correlations(Socket& sock, 
                                                         Receiver& receiver,
                                                         iblt_5h& sender_iblt,
                                                         size_t sender_set_size, 
                                                         size_t recvr_set_size,
                                                         AlignedVector<block>& baseRecv,
                                                         BitVector& baseChoice) {
    MC_BEGIN(Proto, &sock, &receiver, &sender_iblt, &baseRecv, &baseChoice, sender_set_size, recvr_set_size,
             numOts = size_t(0),
             max_num_bin_probes = size_t(0),
             baseSend = span<std::array<block, 2>>(),
             otReceiver = (SoftSpokenShOtReceiver<>*) nullptr,
             otSender = (SoftSpokenShOtSender<>*) nullptr);
        otSender = new SoftSpokenShOtSender<>();
        otSender->init(receiver.softspoken_ot_field_size, true);
        otReceiver = new SoftSpokenShOtReceiver<>();
        otReceiver->init(receiver.softspoken_ot_field_size, true);

        max_num_bin_probes = psu::max_num_bin_probes(sender_iblt.tab_len, iblt_5h::NUM_HASH_FUNCS, sender_set_size, recvr_set_size);
        numOts = max_num_bin_probes;

        otSender->setBaseOts(baseRecv, baseChoice);

        MC_AWAIT(otSender->send((*receiver.otCorrSendMsgs), receiver.prng, sock));

        baseSend = receiver.otCorrSendMsgs->subspan(numOts, otReceiver->baseOtCount());

        otReceiver->setBaseOts(baseSend);

        numOts = max_num_bin_probes*2;

        receiver.otCorrRecvChoices->randomize(receiver.prng);
        MC_AWAIT(otReceiver->receive(*(receiver.otCorrRecvChoices), *(receiver.otCorrRecvMsgs), receiver.prng, sock));

        delete otReceiver;
        delete otSender;

    MC_END();
}

static coproto::task<void> setup_sender_ots_correlations(Socket& sock, 
                                                        Sender& sender,
                                                        iblt_5h& recvr_iblt,
                                                        size_t sender_set_size, 
                                                        size_t recvr_set_size,
                                                        AlignedVector<std::array<block, 2>>& baseSend) {
    MC_BEGIN(Proto, &sock, &sender, &baseSend, &recvr_iblt, sender_set_size, recvr_set_size,
             numOts = size_t(0),
             max_num_bin_probes = size_t(0),
             baseChoices = (BitVector*) nullptr,
             baseRecvMsgsSubspan = span<block>(),
             otSender = (SoftSpokenShOtSender<>*) nullptr,
             otRecvr = (SoftSpokenShOtReceiver<>*) nullptr);
        otRecvr = new SoftSpokenShOtReceiver<>();
        otRecvr->init(sender.softspoken_ot_field_size, true);
        otSender = new SoftSpokenShOtSender<>();
        otSender->init(sender.softspoken_ot_field_size, true);

        otRecvr->setBaseOts(baseSend);

        max_num_bin_probes = psu::max_num_bin_probes(recvr_iblt.tab_len, iblt_5h::NUM_HASH_FUNCS, sender_set_size, recvr_set_size);
        numOts = max_num_bin_probes;

        sender.otCorrRecvChoices->randomize(sender.prng);

        MC_AWAIT(otRecvr->receive(*(sender.otCorrRecvChoices), *(sender.otCorrRecvMsgs), sender.prng, sock));

        baseChoices = new BitVector(sender.otCorrRecvChoices->data(), otSender->baseOtCount(), numOts);

        sender.otCorrRecvChoices->resize(numOts);

        baseRecvMsgsSubspan = sender.otCorrRecvMsgs->subspan(numOts, otSender->baseOtCount());

        otSender->setBaseOts(baseRecvMsgsSubspan, *baseChoices);

        numOts = max_num_bin_probes*2;

        MC_AWAIT(otSender->send(*(sender.otCorrSendMsgs), sender.prng, sock));

        delete otRecvr;
        delete otSender;
        delete baseChoices;
      
    MC_END();
}

coproto::task<void> psu::Sender::setup(Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items) {
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
       
        this->set_items = &set_items;
        
        t0 = std::chrono::high_resolution_clock::now();

        MC_AWAIT(setup_sender_eq_seeds(sock, *this));

        MC_AWAIT(setup_sender_ots_correlations(sock, *this, *(this->iblt), this->set_items->size(), this->recvr_set_size, this->baseSend));

        this->rMaskedMsgs = new AlignedVector<std::array<uint64_t, 2>>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    MC_END();
}

coproto::task<void> psu::Sender::wan_setup(Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items) {
    
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
       
        this->set_items = &set_items;
        
        t0 = std::chrono::high_resolution_clock::now();

        MC_AWAIT(setup_sender_eq_seeds(sock, *this));

        MC_AWAIT(setup_sender_ots_correlations(sock, *this, *(this->iblt), this->set_items->size(), this->recvr_set_size, this->baseSend));

        this->rMaskedMsgs = new AlignedVector<std::array<uint64_t, 2>>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    MC_END();

}


coproto::task<void> psu::Receiver::setup(Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items) {
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));

        this->set_items = &set_items;

        t0 = std::chrono::high_resolution_clock::now();

        // std::cout << "Receiver setup started." << std::endl;

        MC_AWAIT(setup_recvr_eq_seeds(sock, *this));

        // std::cout << "Receiver eq seeds setup finished." << std::endl;

        MC_AWAIT(setup_receiver_ots_correlations(sock, *this, *(this->iblt), this->sndr_set_size, this->set_items->size(), this->baseRecv, this->baseChoices));

        // std::cout << "Receiver OTs setup finished." << std::endl;

        this->rMaskedMsgs = new AlignedVector<std::array<uint64_t, 2>>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    MC_END();
}

coproto::task<void> psu::Receiver::wan_setup(Socket& sock, ankerl::unordered_dense::set<uint64_t>& set_items) {
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));

        this->set_items = &set_items;

        t0 = std::chrono::high_resolution_clock::now();

        // std::cout << "Receiver setup started." << std::endl;

        MC_AWAIT(setup_recvr_eq_seeds(sock, *this));

        // std::cout << "Receiver eq seeds setup finished." << std::endl;

        MC_AWAIT(setup_receiver_ots_correlations(sock, *this, *(this->iblt), this->sndr_set_size, this->set_items->size(), this->baseRecv, this->baseChoices));

        // std::cout << "Receiver OTs setup finished." << std::endl;

        this->rMaskedMsgs = new AlignedVector<std::array<uint64_t, 2>>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    MC_END();
}

static void comp_u_vector_peel_round(Sender& sender, 
                                     iblt_5h& sender_iblt, 
                                     PRNG& prng,  
                                     span<block>& first_ots_out,
                                     size_t round_num,
                                     AlignedVector<size_t> probe_idxs, 
                                     AlignedUnVector<block>& uv) {

    uint64_t* sum = sender_iblt.sum;
    size_t* cnt = sender_iblt.cnt;
    size_t tab_len = sender_iblt.tab_len;
    uint64_t* first_ots_out_u64_ptr = reinterpret_cast<uint64_t*>(first_ots_out.data());

    block* oprf_pts_arr = new block[tab_len];
    block* oprf_out_arr = new block[tab_len];

    size_t prng_out_len = 0;
    size_t oprf_pts_idx = 0;
    for (size_t i = 0; i < probe_idxs.size(); ++i) {
        size_t idx = probe_idxs[i];
        if (cnt[idx] == 1) {
            oprf_pts_arr[oprf_pts_idx] = block(0, sum[idx]);
            oprf_pts_idx++;
        } else if (first_ots_out_u64_ptr[2*i] != 0) {
            oprf_pts_arr[oprf_pts_idx] = block(0, first_ots_out_u64_ptr[2*i]);
            oprf_pts_idx++;
        } else {
            prng_out_len++;
        }
    }

    span<block> oprf_pts(oprf_pts_arr, oprf_pts_idx);
    span<block> oprf_out(oprf_out_arr, oprf_pts_idx);

    sender.oprfSender->eval(oprf_pts, oprf_out);

    block* prng_out = new block[prng_out_len];
    prng.get<block>(prng_out, prng_out_len);

    size_t prng_out_idx = 0;
    size_t oprf_out_idx = 0;

    AES aes;

    for (size_t i = 0; i < probe_idxs.size(); ++i) {
        size_t idx = probe_idxs[i];
        block b = block(round_num, idx);
        
        if (cnt[idx] == 1 || first_ots_out_u64_ptr[2*i] != 0) {
            aes.setKey(oprf_out_arr[oprf_out_idx]);
            uv[i] = aes.ecbEncBlock(b);
            oprf_out_idx++;
        } else {
            uv[i] = prng_out[prng_out_idx];
            prng_out_idx++;
        }
    }

    delete [] prng_out;
    delete [] oprf_pts_arr;
    delete [] oprf_out_arr;

}

static void comp_u_vector_first_peel_round(Sender& sender, iblt_5h& sender_iblt, PRNG& prng,  span<block>& first_ots_out, AlignedUnVector<block>& uv) {

    uint64_t* sum = sender_iblt.sum;
    size_t* cnt = sender_iblt.cnt;
    size_t tab_len = sender_iblt.tab_len;

    block* oprf_pts_arr = new block[tab_len];
    block* oprf_out_arr = new block[tab_len];

    uint64_t* first_ots_out_u64_ptr = reinterpret_cast<uint64_t*>(first_ots_out.data());

    

    size_t prng_out_len = 0;
    size_t oprf_pts_idx = 0;
    for (size_t i = 0; i < tab_len; ++i) {
        if (cnt[i] == 1) {
            oprf_pts_arr[oprf_pts_idx] = block(0, sum[i]);
            oprf_pts_idx++;
        } else if (first_ots_out_u64_ptr[2*i] != 0) {
            oprf_pts_arr[oprf_pts_idx] = block(0,first_ots_out_u64_ptr[2*i]);
            oprf_pts_idx++;
        } else {
            prng_out_len++;
        }
    }

    span<block> oprf_pts(oprf_pts_arr, oprf_pts_idx);
    span<block> oprf_out(oprf_out_arr, oprf_pts_idx);

    auto t0 = std::chrono::high_resolution_clock::now();

    sender.oprfSender->eval(oprf_pts, oprf_out);

    block* prng_out = new block[prng_out_len];
    prng.get<block>(prng_out, prng_out_len);

    auto t1 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    //std::cout << "Sender first peel round oprf eval time (ms): " << duration << std::endl;

    size_t prng_out_idx = 0;
    size_t oprf_out_idx = 0;

    AES aes;

    for (size_t i = 0; i < tab_len; ++i) {
        block b = block(0,i);
        
        if (cnt[i] == 1 || first_ots_out_u64_ptr[2*i] != 0) {
            aes.setKey(oprf_out_arr[oprf_out_idx]);
            uv[i] = aes.ecbEncBlock(b);
            oprf_out_idx++;
        } else {
            uv[i] = prng_out[prng_out_idx];
            prng_out_idx++;
        }
    }

    //auto t1 = std::chrono::high_resolution_clock::now();
    //auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    //std::cout << "Sender first peel round u vector computation time (ms): " << duration << std::endl;

    delete [] prng_out;
    delete [] oprf_pts_arr;
    delete [] oprf_out_arr;

}

/*static inline void populate_probe_bitmap(BitVector& probe_bitmap, iblt_5h& iblt, uint64_t elem, uint64_t already_probed_bin) {
    
    size_t tab_idxs[iblt_5h::NUM_HASH_FUNCS];
    iblt.hash_eval(elem, tab_idxs);

    for (size_t i = 0; i < iblt_5h::NUM_HASH_FUNCS; ++i) {
       probe_bitmap[tab_idxs[i]] = already_probed_bin != tab_idxs[i]; 
    }

}*/

static coproto::task<void> sender_first_peel_round(Socket& sock, 
                                    Sender& sender,
                                    iblt_5h& iblt,
                                    ankerl::unordered_dense::set<uint64_t>& pld_els,
                                    vector<uint64_t>& round_sender_owned_pld_els,
                                    ankerl::unordered_dense::set<uint64_t>& sender_in_set,
                                    vector<uint64_t>& round_pld_els,
                                    BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &sender, &iblt, &pld_els, &round_sender_owned_pld_els, &sender_in_set, &round_pld_els, &peeled_bm,
             cnt = (size_t*) nullptr,
             sum = (uint64_t*) nullptr,
             sMaskedChoices = (BitVector*) nullptr,
             rMaskedChoices = (BitVector*) nullptr,
             maskedChoice = uint8_t(0),
            maskedChoice1 = uint8_t(0),
             randChoices = (BitVector*) nullptr,
            consumed_recv_ots = size_t(0),
            consumed_send_ots = size_t(0),
            rMaskedMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
            sMaskedMsgs = (AlignedUnVector<array<uint64_t, 2>>*) nullptr,
            unmaskedMsg = uint64_t(0),
            intChoice = uint8_t(0),
            randRecvOtMsgs = (uint64_t*) nullptr,
            randSendMsgs = (AlignedVector<std::array<block, 2>>*) nullptr,
            first_ots_out = span<block>(),
            uv = (AlignedUnVector<block>*) nullptr,
            round_pld_els_size = size_t(0),
            t0 = std::chrono::high_resolution_clock::time_point{},
            t1 = std::chrono::high_resolution_clock::time_point{},
            duration = int64_t(0));
        sMaskedChoices = new BitVector(iblt.tab_len);
        randChoices = sender.otCorrRecvChoices;

        cnt = sender.iblt->cnt;

        consumed_recv_ots = sender.consumed_recv_ots;

        t0 = std::chrono::high_resolution_clock::now();

        psu::msk_cnt0_choice_bits(iblt.tab_len, cnt, *sMaskedChoices, *randChoices, consumed_recv_ots);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << " (Sender) choice masking time (ms) during round 1: " << duration << std::endl;

        MC_AWAIT(sock.send(std::move(*sMaskedChoices)));

        delete sMaskedChoices;

        rMaskedMsgs = sender.rMaskedMsgs;
        MC_AWAIT(sock.recvResize(*rMaskedMsgs));

        randRecvOtMsgs = reinterpret_cast<uint64_t*>(sender.otCorrRecvMsgs->data());
        t0 = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < iblt.tab_len; ++i) {
            intChoice = (cnt[i] == 0);

            randRecvOtMsgs[2*(i + consumed_recv_ots)] ^= (*rMaskedMsgs)[i][intChoice]; 
        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
       // std::cout << "Sender first peel round unmasking time (ms): " << duration << std::endl;

        sender.consumed_recv_ots += iblt.tab_len;

        first_ots_out = sender.otCorrRecvMsgs->subspan(0, sender.consumed_recv_ots);

        uv = new AlignedUnVector<block>(iblt.tab_len);

        t0 = std::chrono::high_resolution_clock::now();

        comp_u_vector_first_peel_round(sender, iblt, sender.prng, first_ots_out, *uv);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Sender first peel round u vector computation time (ms): " << duration << std::endl;

        rMaskedChoices = new BitVector(2*iblt.tab_len);
        MC_AWAIT(sock.recv(*rMaskedChoices));
        
        consumed_send_ots = sender.consumed_send_ots;
        sum = sender.iblt->sum;
        randSendMsgs = sender.otCorrSendMsgs;
        sMaskedMsgs = new AlignedUnVector<array<uint64_t, 2>>(iblt.tab_len);
        for (size_t i = 0; i < iblt.tab_len; ++i) {
            maskedChoice = (uint8_t) (*rMaskedChoices)[2*i];
            maskedChoice1 = (uint8_t) (*rMaskedChoices)[2*i + 1];
            uint64_t cond_probed_sum = (cnt[i] == 1) * sum[i];

            (*sMaskedMsgs)[i][0] = cond_probed_sum ^ (*randSendMsgs)[2*i + consumed_send_ots][maskedChoice].get<std::uint64_t>()[0] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][maskedChoice1].get<std::uint64_t>()[0];
            (*sMaskedMsgs)[i][1] = (*uv)[i].get<uint64_t>()[0] ^ (*randSendMsgs)[2*i + consumed_send_ots][1^maskedChoice].get<uint64_t>()[0] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][maskedChoice1].get<std::uint64_t>()[0];

        }

        MC_AWAIT(sock.send(*sMaskedMsgs));
        delete sMaskedMsgs;
        
        sender.consumed_send_ots += 2*iblt.tab_len;

        delete rMaskedChoices;
        delete uv;
        
        MC_AWAIT(sock.recv(round_pld_els_size));

        round_pld_els.resize(round_pld_els_size);

        if (round_pld_els.size() > 0) {
            MC_AWAIT(sock.recv(peeled_bm));
            MC_AWAIT(sock.recv(round_pld_els));
        }

        for (size_t i = 0; i < round_pld_els.size(); ++i) {
            pld_els.insert(round_pld_els[i]);
           if (sender_in_set.contains(round_pld_els[i])) {
                round_sender_owned_pld_els.push_back(round_pld_els[i]);
            }
        }

    MC_END();
}

static coproto::task<void> receiver_first_peel_round(Socket& sock, 
                                       Receiver& receiver,
                                       iblt_5h& iblt,
                                       ankerl::unordered_dense::set<uint64_t>& pld_els,
                                       vector<uint64_t>& round_recvr_owned_pld_els,
                                       vector<block>& round_recvr_owned_pld_seeds,
                                       vector<uint64_t>& round_pld_els,
                                       BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &receiver, &iblt, &pld_els, &round_recvr_owned_pld_els, &round_recvr_owned_pld_seeds, &round_pld_els, &peeled_bm,
             sMaskedChoices = BitVector(iblt.tab_len),
             rMaskedChoices =  BitVector(2*iblt.tab_len),
             maskedChoice = uint8_t(0),
             cnt = (size_t*) nullptr,
             sum = (uint64_t*) nullptr,
             seed_sum = (block*) nullptr,
             consumed_send_ots = size_t(0),
             consumed_recv_ots = size_t(0),
             rMaskedMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             sMaskedMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             //randSendMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             //randSendMsgs = (uint64_t*) nullptr,
             randChoices = (BitVector*) nullptr,
             intChoice = uint8_t(0),
             ot_out = block(0,0),
             randRecvOtMsgs = (block*) nullptr,
             b = block(0, 0),
             aes = AES(),
             ot_out_u64 = uint64_t(0),
            t0 = std::chrono::high_resolution_clock::time_point{},
            t1 = std::chrono::high_resolution_clock::time_point{},
            duration = int64_t(0));

        //sMaskedChoices = new BitVector(iblt.tab_len);
        rMaskedMsgs = receiver.rMaskedMsgs;

        MC_AWAIT(sock.recv(sMaskedChoices));

        cnt = receiver.iblt->cnt;
        sum = receiver.iblt->sum;
        seed_sum = receiver.iblt->seedsum;
        //randSendMsgs = receiver.otCorrSendMsgs;
        //randSendMsgs = reinterpret_cast<uint64_t*>(receiver.otCorrSendMsgs->data());

        t0 = std::chrono::high_resolution_clock::now();

        consumed_send_ots = receiver.consumed_send_ots;
        for (size_t i = 0; i < iblt.tab_len; ++i) {
           maskedChoice = (uint8_t) sMaskedChoices[i];
           
           (*rMaskedMsgs)[i][0] = (*receiver.otCorrSendMsgs)[i + consumed_send_ots][maskedChoice].get<uint64_t>()[0];
           (*rMaskedMsgs)[i][1] = (((*receiver.iblt->cnt_vec)[i] == 1) * (*receiver.iblt->sum_vec)[i] ) ^ (*receiver.otCorrSendMsgs)[i + consumed_send_ots][1 ^ maskedChoice].get<uint64_t>()[0];

        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Receiver first peel round unmasking time (ms): " << duration << std::endl;

        receiver.consumed_send_ots += iblt.tab_len;

        MC_AWAIT(sock.send(*rMaskedMsgs));

       // delete sMaskedChoices;

        randChoices = receiver.otCorrRecvChoices;
        consumed_recv_ots = receiver.consumed_recv_ots;
        #pragma omp simd
        for (size_t i = 0; i < iblt.tab_len; ++i) {
            rMaskedChoices[2*i] = (cnt[i] == 1) ^ (*randChoices)[2*i + consumed_recv_ots];
            rMaskedChoices[2*i + 1] = (cnt[i] > 1) ^ (*randChoices)[2*i + 1 + consumed_recv_ots];
        }

        MC_AWAIT(sock.send(rMaskedChoices));
        //delete rMaskedChoices;

        sMaskedMsgs = new AlignedVector<array<uint64_t, 2>>(iblt.tab_len);
        MC_AWAIT(sock.recv(*sMaskedMsgs));
        randRecvOtMsgs = reinterpret_cast<block*>(receiver.otCorrRecvMsgs->data());
        for (size_t i = 0; i < iblt.tab_len; ++i) {
            if(cnt[i] > 1) continue;
            intChoice = (uint8_t) cnt[i];

            ot_out_u64 = (*sMaskedMsgs)[i][intChoice] ^ randRecvOtMsgs[2*i + consumed_recv_ots].get<uint64_t>()[0]
                     ^ randRecvOtMsgs[2*i + 1 + consumed_recv_ots].get<uint64_t>()[0];

            if (cnt[i] == 0 && ot_out_u64 != 0) {

                peeled_bm[i] = 1;
                if(pld_els.insert(ot_out_u64).second) {
                    round_pld_els.push_back(ot_out_u64);                    

                    //if (recvr_in_set.find(ot_out) != recvr_in_set.end()) { This is probably not needed
                    //    round_recvr_owned_pld_els.push_back(ot_out);
                    //}
                }

            } else if (cnt[i] == 1) {
                b = block(0, i);

                aes.setKey(seed_sum[i]);

                if (ot_out_u64 == aes.ecbEncBlock(b).get<uint64_t>()[0]) {

                    peeled_bm[i] = 1;

                    if (pld_els.insert(sum[i]).second) {
                        round_pld_els.push_back(sum[i]);
                        round_recvr_owned_pld_els.push_back(sum[i]);
                        round_recvr_owned_pld_seeds.push_back(seed_sum[i]);

                        //if (recvr_in_set.find(sum[i]) != recvr_in_set.end()) { // This is probably not needed
                        //    round_recvr_owned_pld_els.push_back(sum[i]);
                        //}
                    }
                }
            }
        }

        delete sMaskedMsgs;

        receiver.consumed_recv_ots += 2*iblt.tab_len;

        MC_AWAIT(sock.send(round_pld_els.size()));

        if(round_pld_els.size() > 0) {
            MC_AWAIT(sock.send(peeled_bm));
            MC_AWAIT(sock.send(round_pld_els));
        }

    MC_END();
}

static coproto::task<void> sender_peel_round(Socket& sock, 
                                             Sender& sender,
                                             iblt_5h& iblt,
                                             size_t round_num,
                                             AlignedVector<size_t>& probe_idxs,
                                             ankerl::unordered_dense::set<uint64_t>& pld_els,
                                             vector<uint64_t>& round_sender_owned_pld_els,
                                             ankerl::unordered_dense::set<uint64_t>& sender_in_set,
                                             vector<uint64_t>& round_pld_els,
                                             BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &sender, &iblt, round_num, &probe_idxs, &pld_els, &round_sender_owned_pld_els, &sender_in_set, &round_pld_els, &peeled_bm,
             cnt = (size_t*) nullptr,
             sum = (uint64_t*) nullptr,
             sMaskedChoices = (BitVector*) nullptr,
             rMaskedChoices = (BitVector*) nullptr,
             maskedChoice = uint8_t(0),
             maskedChoice1 = uint8_t(0),
             randChoices = (BitVector*) nullptr,
             consumed_recv_ots = size_t(0),
             consumed_send_ots = size_t(0),
             rMaskedMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             sMaskedMsgs = (AlignedUnVector<array<uint64_t, 2>>*) nullptr,
             intChoice = uint8_t(0),
             randRecvOtMsgs = (uint64_t*) nullptr,
             randSendMsgs = (AlignedVector<std::array<block, 2>>*) nullptr,
             first_ots_out = span<block>(),
             uv = (AlignedUnVector<block>*) nullptr,
             probe_idx = size_t(0),
             round_pld_els_size = size_t(0),
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));

        sMaskedChoices = new BitVector(probe_idxs.size());
        randChoices = sender.otCorrRecvChoices;

        cnt = sender.iblt->cnt;
        consumed_recv_ots = sender.consumed_recv_ots;

        t0 = std::chrono::high_resolution_clock::now();

        psu::msk_cnt0_choice_bits(probe_idxs, cnt, *sMaskedChoices, *randChoices, consumed_recv_ots);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << " (Sender) choice masking time (ms) during round " << round_num << ": " << duration << std::endl;

        MC_AWAIT(sock.send(std::move(*sMaskedChoices)));

        delete sMaskedChoices;

        rMaskedMsgs = sender.rMaskedMsgs;

        MC_AWAIT(sock.recvResize(*rMaskedMsgs));

        t0 = std::chrono::high_resolution_clock::now();
        randRecvOtMsgs = reinterpret_cast<uint64_t*>(sender.otCorrRecvMsgs->data());
        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            probe_idx = probe_idxs[i];
            intChoice = (cnt[probe_idx] == 0);

            randRecvOtMsgs[2*(i + consumed_recv_ots)] ^= (*rMaskedMsgs)[i][intChoice]; 
        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Sender peel round " << round_num << " unmasking time (ms): " << duration << std::endl;

        sender.consumed_recv_ots += probe_idxs.size();

        first_ots_out = sender.otCorrRecvMsgs->subspan(sender.consumed_recv_ots-probe_idxs.size(), probe_idxs.size());
        
        uv = new AlignedUnVector<block>(probe_idxs.size());

        t0 = std::chrono::high_resolution_clock::now();

        comp_u_vector_peel_round(sender, iblt, sender.prng, first_ots_out, round_num, probe_idxs, *uv);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Sender peel round " << round_num << " u vector computation time (ms): " << duration << std::endl;

        rMaskedChoices = new BitVector(2*probe_idxs.size());
        MC_AWAIT(sock.recv(*rMaskedChoices));

        consumed_send_ots = sender.consumed_send_ots;
        sum = sender.iblt->sum;
        randSendMsgs = sender.otCorrSendMsgs;
        
        //sMaskedMsgs = new AlignedUnVector<array<block, 2>>(probe_idxs.size());
        sMaskedMsgs = new AlignedUnVector<array<uint64_t, 2>>(probe_idxs.size());
        
        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            probe_idx = probe_idxs[i];
            maskedChoice = (uint8_t) (*rMaskedChoices)[2*i];
            maskedChoice1 = (uint8_t) (*rMaskedChoices)[2*i + 1];

            uint64_t cond_probed_sum = (cnt[probe_idx] == 1) * sum[probe_idx];

            (*sMaskedMsgs)[i][0] = cond_probed_sum ^ (*randSendMsgs)[2*i + consumed_send_ots][maskedChoice].get<std::uint64_t>()[0] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][maskedChoice1].get<std::uint64_t>()[0];
            (*sMaskedMsgs)[i][1] = (*uv)[i].get<uint64_t>()[0] ^ (*randSendMsgs)[2*i + consumed_send_ots][1^maskedChoice].get<uint64_t>()[0] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][maskedChoice1].get<std::uint64_t>()[0];
        }

        MC_AWAIT(sock.send(std::move(*sMaskedMsgs)));
        delete sMaskedMsgs;

        sender.consumed_send_ots += 2*probe_idxs.size();

        delete rMaskedChoices;
        delete uv;

        MC_AWAIT(sock.recv(round_pld_els_size));

        round_pld_els.resize(round_pld_els_size);
        
        if(round_pld_els.size() > 0) {
            MC_AWAIT(sock.recv(peeled_bm));
            MC_AWAIT(sock.recv(round_pld_els));
        }

        for (size_t i = 0; i < round_pld_els.size(); ++i) {
            pld_els.insert(round_pld_els[i]);
            if (sender_in_set.contains(round_pld_els[i])) {
                round_sender_owned_pld_els.push_back(round_pld_els[i]);
            }
        }


    MC_END();

}


static coproto::task<void> receiver_peel_round(Socket& sock, 
                                               Receiver& receiver,
                                               iblt_5h& iblt,
                                               size_t round_num,
                                               AlignedVector<size_t>& probe_idxs,
                                               ankerl::unordered_dense::set<uint64_t>& pld_els,
                                               vector<uint64_t>& round_recvr_owned_pld_els,
                                                vector<block>& round_recvr_owned_pld_seeds,
                                               vector<uint64_t>& round_pld_els,
                                               BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &receiver, &iblt, &pld_els, &probe_idxs, round_num, &round_recvr_owned_pld_els, &round_recvr_owned_pld_seeds, &round_pld_els, &peeled_bm,
             sMaskedChoices = (BitVector*) nullptr,
             rMaskedChoices = (BitVector*) nullptr,
             maskedChoice = uint8_t(0),
             cnt = (size_t*) nullptr,
             sum = (uint64_t*) nullptr,
             seed_sum = (block*) nullptr,
             consumed_send_ots = size_t(0),
             consumed_recv_ots = size_t(0),
             rMaskedMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             sMaskedMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             //randSendMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             //randSendMsgs = (uint64_t*) nullptr,
             rMaskedMsgsSpan = span<array<uint64_t, 2>>(),
             randChoices = (BitVector*) nullptr,
             intChoice = uint8_t(0),
             ot_out = block(0,0),
             ot_out_u64 = uint64_t(0),
             randRecvOtMsgs = (block*) nullptr,
             probe_idx = size_t(0),
             b = block(0, 0),
             aes = AES(),
             //peeled_bin_bm = (BitVector*) nullptr,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
        round_pld_els.reserve(probe_idxs.size());

        sMaskedChoices = new BitVector(probe_idxs.size());
        rMaskedMsgs = receiver.rMaskedMsgs;

        // std::cout << "Receiving sMaskedChoices: " << probe_idxs.size() << std::endl;

        //std::cout << " (Receiver) Before MC_AWAIT(sock.recv(*sMaskedChoices));" << std::endl;

        MC_AWAIT(sock.recv(*sMaskedChoices));

        //std::cout << " (After) Before MC_AWAIT(sock.recv(*sMaskedChoices));" << std::endl;

        //t0 = std::chrono::high_resolution_clock::now();
        //duration = std::chrono::duration_cast<std::chrono::milliseconds>(t0 - t1).count();
        //std::cout << "t0 in milliseconds since epoch: " << duration << std::endl;

        // std::cout << "Received sMaskedChoices." << std::endl;

        cnt = receiver.iblt->cnt;
        sum = receiver.iblt->sum;
        seed_sum = receiver.iblt->seedsum;
        //randSendMsgs = receiver.otCorrSendMsgs;
        //randSendMsgs = reinterpret_cast<uint64_t*>(receiver.otCorrSendMsgs->data());

        consumed_send_ots = receiver.consumed_send_ots;

        t0 = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            probe_idx = probe_idxs[i];
            maskedChoice = (uint8_t) (*sMaskedChoices)[i];

            (*rMaskedMsgs)[i][0] = (*receiver.otCorrSendMsgs)[i + consumed_send_ots][maskedChoice].get<uint64_t>()[0]; // Xor by 0 is implicit
            (*rMaskedMsgs)[i][1] = ( (cnt[probe_idx] == 1) *  sum[probe_idx]) ^ (*receiver.otCorrSendMsgs)[i + consumed_send_ots][1 ^ maskedChoice].get<uint64_t>()[0];
        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Receiver peel round " << round_num << " unmasking time (ms): " << duration << std::endl;

        receiver.consumed_send_ots += probe_idxs.size();
        
        rMaskedMsgsSpan = rMaskedMsgs->subspan(0, probe_idxs.size());

        // std::cout << "Sending rMaskedMsgs." << std::endl;

        //t0 = std::chrono::high_resolution_clock::now();
        //duration = std::chrono::duration_cast<std::chrono::milliseconds>(t0 - t1).count();
        //std::cout << "rMaskedMsgs send time is " << duration << " ms during round " << round_num << std::endl;
        //std::cout << "rMaskedMsgs size: " << (rMaskedMsgsSpan.size() * sizeof(array<uint64_t, 2>) * 8 / 1000000.0) << " megabits" << std::endl;

        MC_AWAIT(sock.send(std::move(rMaskedMsgsSpan)));

        // std::cout << "Sent rMaskedMsgs." << std::endl;

        delete sMaskedChoices;

        randChoices = receiver.otCorrRecvChoices;
        consumed_recv_ots = receiver.consumed_recv_ots;
        rMaskedChoices = new BitVector(2*probe_idxs.size());
        #pragma omp simd
        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            probe_idx = probe_idxs[i];
            (*rMaskedChoices)[2*i] =  (cnt[probe_idx] == 1) ^ (*randChoices)[2*i + consumed_recv_ots];
            (*rMaskedChoices)[2*i + 1] = (cnt[probe_idx] > 1) ^ (*randChoices)[2*i + 1 + consumed_recv_ots];
        }

        MC_AWAIT(sock.send(*rMaskedChoices));
        delete rMaskedChoices;

        sMaskedMsgs = new AlignedVector<array<uint64_t, 2>>(probe_idxs.size());
        MC_AWAIT(sock.recv(*sMaskedMsgs));

        //t0 = std::chrono::high_resolution_clock::now();
        //randRecvOtMsgs = receiver.otCorrRecvMsgs->data();
        //peeled_bin_bm = new BitVector(iblt.tab_len);
        randRecvOtMsgs = receiver.otCorrRecvMsgs->data();
        for (size_t i=0;i < probe_idxs.size(); ++i) {
            probe_idx = probe_idxs[i];
            if(cnt[probe_idx] > 1) continue;
            intChoice = (uint8_t) cnt[probe_idx];

            ot_out_u64 = (*sMaskedMsgs)[i][intChoice] ^ randRecvOtMsgs[2*i + consumed_recv_ots].get<std::uint64_t>()[0]
                     ^ randRecvOtMsgs[2*i + 1 + consumed_recv_ots].get<std::uint64_t>()[0];

            if (cnt[probe_idx] == 0 && ot_out_u64 != 0) {
                
                peeled_bm[probe_idx] = 1;
                if(pld_els.insert(ot_out_u64).second) {
                    //populate_probe_bitmap(*peeled_bin_bm, iblt, ot_out_u64, probe_idx);

                    round_pld_els.push_back(ot_out_u64);

                    //if (recvr_in_set.find(ot_out) != recvr_in_set.end()) { // This is probably not needed
                    //    round_recvr_owned_pld_els.push_back(ot_out);
                    //}
                }
            } else if (cnt[probe_idx] == 1) {
                b = block(round_num, probe_idx);

                aes.setKey(seed_sum[probe_idx]);

              
                if (ot_out_u64 == aes.ecbEncBlock(b).get<uint64_t>()[0]) {
                    
                    peeled_bm[probe_idx] = 1;
                    
                    if (pld_els.insert(sum[probe_idx]).second) {
                        //populate_probe_bitmap(*peeled_bin_bm, iblt, sum[probe_idx], probe_idx);

                        round_pld_els.push_back(sum[probe_idx]);
                        round_recvr_owned_pld_els.push_back(sum[probe_idx]);
                        round_recvr_owned_pld_seeds.push_back(seed_sum[probe_idx]);

                        //if (recvr_in_set.find(sum[probe_idx]) != recvr_in_set.end()) {
                        //    round_recvr_owned_pld_els.push_back(sum[probe_idx]);
                        //}
                    }
                }
            }

        }

        //t1 = std::chrono::high_resolution_clock::now();
        //duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Receiver peel round " << round_num << " finished in " << duration << " ms." << std::endl;

        delete sMaskedMsgs;

        receiver.consumed_recv_ots += 2*probe_idxs.size();

        MC_AWAIT(sock.send(round_pld_els.size()));

        if(round_pld_els.size() > 0) {
            MC_AWAIT(sock.send(peeled_bm));
            MC_AWAIT(sock.send(round_pld_els));
            //MC_AWAIT(sock.send(std::move(*peeled_bin_bm)));
        }

        //delete peeled_bin_bm;

    MC_END();

}


coproto::task<void> psu::Sender::send(Socket& sock, ankerl::unordered_dense::set<uint64_t>& pld_els) {
    MC_BEGIN(Proto, this, &sock, &pld_els,
             round_num = size_t(0),
             round_pld_els = vector<uint64_t>());
        pld_els.reserve(recvr_set_size + set_items->size());

         //std::cout << "Sender first peel round started." << std::endl;

        MC_AWAIT(sender_first_peel_round(sock, *this, *(this->iblt), pld_els, round_sender_owned_pld_els, *(this->set_items), round_pld_els, this->peeled_bm));        

        // std::cout << "Sender first peel round finished." << std::endl;

        this->iblt->removeKeys(round_sender_owned_pld_els);
        this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm);

        round_num = 1;

        while (iblt_remove_unique_hash_evals.size() > 0) {
            round_sender_owned_pld_els.clear();
            round_pld_els.clear();
            
             //std::cout << "Sender peel round " << round_num << " started, with " << iblt_remove_unique_hash_evals.size() << " unique hash evaluations." << std::endl;

             //std::cout << "Sender processing round " << round_num << " with " << iblt_remove_unique_hash_evals.size() << " unique hash evaluations." << std::endl;

            MC_AWAIT(sender_peel_round(sock, *this, *(this->iblt), round_num, iblt_remove_unique_hash_evals, pld_els, round_sender_owned_pld_els, *(this->set_items), round_pld_els, this->peeled_bm));

            //std::cout << "Sender peel round " << round_num << " finished, with " << round_pld_els.size() << " peeled elements." << std::endl;

            iblt_remove_unique_hash_evals.clear();

            this->iblt->removeKeys(round_sender_owned_pld_els); 
            this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm); 

            round_num++;
        }

       // std::cout << "Sender finished peeling." << std::endl;

        this->num_peel_iterations = round_num;

        // std::cout << "Sender finished peeling." << std::endl;

    MC_END();
}

coproto::task<void> psu::Receiver::recv(Socket& sock, ankerl::unordered_dense::set<uint64_t>& pld_els) {
    MC_BEGIN(Proto, this, &sock, &pld_els,
             round_num = size_t(0),
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
        pld_els.reserve(sndr_set_size + set_items->size());

        //t0 = std::chrono::high_resolution_clock::now();

        // std::cout << "Receiver first peel round started." << std::endl;


        MC_AWAIT(receiver_first_peel_round(sock, *this, *(this->iblt), pld_els, round_recvr_owned_pld_els, round_recvr_owned_pld_seeds, round_pld_els, this->peeled_bm));


        // std::cout << "Receiver first peel round finished." << std::endl;

        this->iblt->remove(round_recvr_owned_pld_els, round_recvr_owned_pld_seeds);
        this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm);

       // t1 = std::chrono::high_resolution_clock::now();
       // duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
      //  std::cout << "Receiver first peel round finished in " << duration << " ms" << std::endl;
      //  std::cout << "Parties peeled " << round_pld_els.size() << " elements during first peel round." << std::endl;

        round_num = 1;

       // std::cout << "Round 1 Done" << std::endl; 

        while (iblt_remove_unique_hash_evals.size() > 0) {
          //  t0 = std::chrono::high_resolution_clock::now();

            round_recvr_owned_pld_els.clear();
            round_recvr_owned_pld_seeds.clear();
            round_pld_els.clear();

            //std::cout << "Receiver processing round " << round_num << " with " << iblt_remove_unique_hash_evals.size() << " unique hash evaluations." << std::endl;

            //std::cout << "Receiver peel round " << round_num << " started." << std::endl;

            MC_AWAIT(receiver_peel_round(sock, *this, *(this->iblt), round_num, iblt_remove_unique_hash_evals, pld_els, round_recvr_owned_pld_els, round_recvr_owned_pld_seeds, round_pld_els, this->peeled_bm));

            //std::cout << "Round " << round_num + 1 << " Done" << std::endl;

            // std::cout << "Receiver peel round " << round_num << " finished." << std::endl;

            iblt_remove_unique_hash_evals.clear();

            this->iblt->remove(round_recvr_owned_pld_els, round_recvr_owned_pld_seeds); 
            this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm);

          //  t1 = std::chrono::high_resolution_clock::now();
         //   duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
         //   std::cout << "Receiver peel round " << round_num << " finished in " << duration << " ms" << std::endl;

            //std::cout << "Parties peeled " << round_pld_els.size() << " elements during round " << round_num << "." << std::endl;
            //std::cout << "Amount of bins to probe in next round: " << iblt_remove_unique_hash_evals.size() << std::endl;

            round_num++;
        }

       // std::cout << "Receiver finished peeling." << std::endl;

        this->num_peel_iterations = round_num;

    MC_END();
}

void psu::msk_cnt0_choice_bits(size_t iblt_tab_len, size_t* cnt, osuCrypto::BitVector& maskedChoices, osuCrypto::BitVector& randChoices, size_t randChoicesOffset) {
    // #pragma omp simd aligned(cnt:32)
    for (size_t i = 0; i < iblt_tab_len; ++i) {
        maskedChoices[i] = (cnt[i] == 0) ^ randChoices[i + randChoicesOffset];
    }
}

void psu::msk_cnt0_choice_bits(AlignedVector<size_t>& probe_idxs, 
                              size_t* cnt, 
                              osuCrypto::BitVector& maskedChoices, 
                              osuCrypto::BitVector& randChoices,
                              size_t randChoicesOffset) {
    

    for (size_t i = 0; i < probe_idxs.size(); ++i) {
        size_t probe_idx = probe_idxs[i];
        maskedChoices[i] = (cnt[probe_idx] == 0) ^ randChoices[i + randChoicesOffset];
    }

}