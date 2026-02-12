#include "catch2/catch_test_macros.hpp"
#include "volePSI/RsOprf.h"
#include "../psu.h"
#include "../iblt_h5.hpp"
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include <ankerl/unordered_dense.h>

using coproto::LocalAsyncSocket;
using namespace osuCrypto;

using macoro::sync_wait;
using macoro::when_all_ready;
using psu::Sender;
using psu::Receiver;
using osuCrypto::block;
using osuCrypto::PRNG;
using std::vector;
using std::unordered_set;
using volePSI::RsOprfSender;

static constexpr size_t FIELD_BITS = 8;
static constexpr bool OPRF_REDUCED_ROUNDS = false;

static void gen_input_sets(std::vector<uint64_t>& set_items, size_t n, size_t start) {
    assert(start > 0);
    
    set_items.clear();
    for (size_t i = start; i < start+n; ++i) {
        set_items.push_back(i);
    }
    
}

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

static void gen_rand_input_sets(PRNG& prng, 
                                vector<uint64_t>& set_vec1, 
                                vector<uint64_t>& set_vec2,
                                size_t set_size,
                                size_t num_matching_elements) {
    assert(set_size >= num_matching_elements);

    set_vec1.clear(); set_vec2.clear(); 
    set_vec1.reserve(set_size); set_vec2.reserve(set_size);
    unordered_set<uint64_t> set1, set2;
    set1.reserve(set_size); set2.reserve(set_size);
    
    while (set1.size() < num_matching_elements) {
        uint64_t item = prng.get<uint64_t>();
        if (set1.find(item) == set1.end()) {
            set1.insert(item);
            set2.insert(item);
            set_vec1.push_back(item);
            set_vec2.push_back(item);
        }
    }

    while (set1.size() < set_size) {
        uint64_t item = prng.get<uint64_t>();
        if (set1.find(item) == set1.end() && set2.find(item) == set2.end()) {
            set1.insert(item);
            set_vec1.push_back(item);
        }
    }

    while (set2.size() < set_size) {
        uint64_t item = prng.get<uint64_t>();
        if (set2.find(item) == set2.end() && set1.find(item) == set1.end()) {
            set2.insert(item);
            set_vec2.push_back(item);
        }
    }

    assert(std::find(set_vec1.begin(), set_vec1.end(), 0) == set_vec1.end());
    assert(std::find(set_vec2.begin(), set_vec2.end(), 0) == set_vec2.end());
}

TEST_CASE("protocol correctly computes the union of two sets with random inputs and forced matched elements","[trypeel][send][recv]") {

    auto sockets = LocalAsyncSocket::makePair();
    block sender_seed(804127122578564875ULL, 6452408941779289156ULL);
    block receiver_seed(16925767379666885198ULL, 13843614222775765652ULL);
    block iblt_seed(13438521297964321511ULL, 3492639623355484125ULL);
    block test_rand_seed(11822403601324123185ULL, 8714761473228724932ULL);

    PRNG test_prng(test_rand_seed);

    const size_t iblt_mult_fac = 3.5;
    const size_t input_set_size = 1 << 16;
    const size_t num_matching_elements = 1 << 8;  
    
    vector<uint64_t> sender_in_set_vec;
    vector<uint64_t> receiver_in_set_vec;
    
    gen_rand_input_sets(test_prng, sender_in_set_vec, receiver_in_set_vec, input_set_size, num_matching_elements);

    ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
    ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

    Sender sender(sender_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac, FIELD_BITS, OPRF_REDUCED_ROUNDS);
    Receiver receiver(receiver_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac, FIELD_BITS, OPRF_REDUCED_ROUNDS);

    auto p0 = sender.setup(sockets[0], sender_in_set);
    auto p1 = receiver.setup(sockets[1], receiver_in_set);

    sync_wait(when_all_ready(std::move(p0), std::move(p1)));
   
    ankerl::unordered_dense::set<uint64_t> recvr_pld_els;
    ankerl::unordered_dense::set<uint64_t> sndr_pld_els;
    
    auto p2 = sender.send(sockets[0], sndr_pld_els);
    auto p3 = receiver.recv(sockets[1], recvr_pld_els);

    sync_wait(when_all_ready(std::move(p2), std::move(p3)));

    ankerl::unordered_dense::set<uint64_t> expected_union_set(sender_in_set.begin(), sender_in_set.end());
    expected_union_set.insert(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

    REQUIRE(expected_union_set.size() == 2*input_set_size - num_matching_elements);
    REQUIRE(sender_in_set.size() == input_set_size);
    REQUIRE(receiver_in_set_vec.size() == input_set_size);
    REQUIRE(sndr_pld_els.size() == expected_union_set.size());
    REQUIRE(recvr_pld_els.size() == expected_union_set.size());
    REQUIRE(sndr_pld_els == expected_union_set);
    REQUIRE(recvr_pld_els == expected_union_set);

}

TEST_CASE("protocol correctly computes the union of two sets with random inputs","[trypeel][send][recv]") {

    auto sockets = LocalAsyncSocket::makePair();
    block sender_seed(804127122578564875ULL, 6452408941779289156ULL);
    block receiver_seed(16925767379666885198ULL, 13843614222775765652ULL);
    block iblt_seed(4672171876689324624ULL, 6415789310665420428ULL);
    block test_rand_seed(11150919802476511020ULL,15969001429946269061ULL);

    PRNG test_prng(test_rand_seed);

    const size_t iblt_mult_fac = 3.5;
    const size_t input_set_size = 1 << 16;
    
    vector<uint64_t> sender_in_set_vec;
    vector<uint64_t> receiver_in_set_vec;
    
    gen_rand_input_sets(test_prng, sender_in_set_vec, input_set_size);
    gen_rand_input_sets(test_prng, receiver_in_set_vec, input_set_size);

    ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
    ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

    Sender sender(sender_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac, FIELD_BITS, OPRF_REDUCED_ROUNDS);
    Receiver receiver(receiver_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac, FIELD_BITS, OPRF_REDUCED_ROUNDS);

    auto p0 = sender.setup(sockets[0], sender_in_set);
    auto p1 = receiver.setup(sockets[1], receiver_in_set);

    sync_wait(when_all_ready(std::move(p0), std::move(p1)));
   
    ankerl::unordered_dense::set<uint64_t> recvr_pld_els;
    ankerl::unordered_dense::set<uint64_t> sndr_pld_els;
    
    auto p2 = sender.send(sockets[0], sndr_pld_els);
    auto p3 = receiver.recv(sockets[1], recvr_pld_els);

    sync_wait(when_all_ready(std::move(p2), std::move(p3)));

    ankerl::unordered_dense::set<uint64_t> expected_union_set(sender_in_set.begin(), sender_in_set.end());
    expected_union_set.insert(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

    REQUIRE(sender_in_set.size() == input_set_size);
    REQUIRE(receiver_in_set_vec.size() == input_set_size);
    REQUIRE(sndr_pld_els.size() == expected_union_set.size());
    REQUIRE(recvr_pld_els.size() == expected_union_set.size());
    REQUIRE(sndr_pld_els == expected_union_set);
    REQUIRE(recvr_pld_els == expected_union_set);

}

TEST_CASE("trypeel: ots are correctly extended during setup phase","[trypeel][send]") {

    auto sockets = LocalAsyncSocket::makePair();
    block sender_seed(block(804127122578564875ULL, 6452408941779289156ULL));
    block receiver_seed(block(16925767379666885198ULL, 13843614222775765652ULL));
    block iblt_seed(9971019762749484704ULL, 5740886910012278797ULL);

    auto otRecvr = new SoftSpokenShOtReceiver<>();
    otRecvr->init(FIELD_BITS, true);

    const size_t iblt_mult_fac = 3.5;
    size_t input_set_size = 1 << 16;
    size_t threshhold = input_set_size*2;
    vector<uint64_t> sender_in_set_vec;
    vector<uint64_t> receiver_in_set_vec;
    gen_input_sets(sender_in_set_vec, input_set_size, 1);
    gen_input_sets(receiver_in_set_vec, input_set_size, input_set_size/2);

    ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
    ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

    Sender sender(sender_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac, FIELD_BITS, OPRF_REDUCED_ROUNDS);
    Receiver receiver(receiver_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac, FIELD_BITS, OPRF_REDUCED_ROUNDS);

    auto p0 = sender.setup(sockets[0], sender_in_set);
    auto p1 = receiver.setup(sockets[1], receiver_in_set);
    sync_wait(when_all_ready(std::move(p0), std::move(p1)));

    REQUIRE(sender.otCorrSendMsgs != nullptr);
    REQUIRE(sender.otCorrRecvChoices != nullptr);
    REQUIRE(sender.otCorrRecvMsgs != nullptr);
    REQUIRE(receiver.otCorrRecvChoices != nullptr);
    REQUIRE(receiver.otCorrRecvMsgs != nullptr);
    REQUIRE(receiver.otCorrSendMsgs != nullptr);

    const size_t max_union_set_size = input_set_size*2;
    const size_t max_num_bin_probes = sender.iblt->tab_len + max_union_set_size*(iblt_5h::NUM_HASH_FUNCS - 1);

    REQUIRE(sender.otCorrSendMsgs->size() == max_num_bin_probes*2);
    REQUIRE(sender.otCorrRecvChoices->size() == max_num_bin_probes);
    REQUIRE(sender.otCorrRecvMsgs->size() == max_num_bin_probes + otRecvr->baseOtCount()); 
    REQUIRE(receiver.otCorrSendMsgs->size() == max_num_bin_probes + otRecvr->baseOtCount());
    REQUIRE(receiver.otCorrRecvMsgs->size() == max_num_bin_probes*2);
    REQUIRE(receiver.otCorrRecvChoices->size() == max_num_bin_probes*2);

    size_t numOts = sender.otCorrSendMsgs->size();

    for (size_t i = 0; i < numOts; ++i) {
        REQUIRE(sender.otCorrSendMsgs->at(i)[0] != sender.otCorrSendMsgs->at(i)[1]);
        size_t choiceInt = ((*(receiver.otCorrRecvChoices))[i]) ? 1 : 0;
        REQUIRE(receiver.otCorrRecvMsgs->at(i).get<uint64_t>()[0] == sender.otCorrSendMsgs->at(i)[choiceInt].get<uint64_t>()[0]);
    }

    numOts = receiver.otCorrSendMsgs->size()- otRecvr->baseOtCount(); 
    for (size_t i = 0; i < numOts; ++i) {
        REQUIRE(receiver.otCorrSendMsgs->at(i)[0] != receiver.otCorrSendMsgs->at(i)[1]);
        size_t choiceInt = ((*(sender.otCorrRecvChoices))[i]) ? 1 : 0;
        REQUIRE(sender.otCorrRecvMsgs->at(i).get<uint64_t>()[0] == receiver.otCorrSendMsgs->at(i)[choiceInt].get<uint64_t>()[0]);
    }

    delete otRecvr;

}
/*
TEST_CASE("trypeel: equality check seeds are correctly setup","[trypeel][send]") {

    auto sockets = LocalAsyncSocket::makePair();
    block sender_seed(block(804127122578564875ULL, 6452408941779289156ULL));
    block receiver_seed(block(16925767379666885198ULL, 13843614222775765652ULL));
    block iblt_seed(3458015234153926932ULL, 12725375868491624636ULL);


    const size_t iblt_mult_fac = 3.5;
    size_t input_set_size = 1 << 16;
    size_t threshhold = input_set_size*2;
    vector<uint64_t> sender_in_set;
    vector<uint64_t> receiver_in_set_vec;
    gen_input_sets(sender_in_set, input_set_size, 1);
    gen_input_sets(receiver_in_set_vec, input_set_size, input_set_size/2);

    Sender sender(sender_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac);
    Receiver receiver(receiver_seed,input_set_size,input_set_size, iblt_seed, iblt_mult_fac);

    auto p0 = sender.setup(sockets[0], sender_in_set);
    auto p1 = receiver.setup(sockets[1], receiver_in_set_vec);
    sync_wait(when_all_ready(std::move(p0), std::move(p1)));

    REQUIRE(sender.oprfSender != nullptr);
    //REQUIRE(receiver.eq_seeds.size() == input_set_size);

    //for (const auto& [item, aes] : receiver.eq_seeds) {
    //    REQUIRE(sender.oprfSender->eval(block(0, item)) == aes.getKey());
    //}

}*/