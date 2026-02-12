#include "volePSI/RsOprf.h"
#include "../psu.h"
#include "../iblt_h5.hpp"
#include <vector>
#include <chrono>
#include <unordered_set>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>

using coproto::LocalAsyncSocket;

using macoro::sync_wait;
using macoro::when_all_ready;
using psu::Sender;
using psu::Receiver;
using osuCrypto::block;
using osuCrypto::PRNG;
using std::vector;
using std::unordered_set;
using volePSI::Proto;

static void gen_input_sets(std::vector<uint64_t>& set_items, size_t n, size_t start) {
    assert(start > 0);
    
    set_items.clear();
    for (size_t i = start; i < start+n; ++i) {
        set_items.push_back(i);
    }
}

static coproto::task<void> sender_exec(coproto::LocalAsyncSocket& sock, 
                                       psu::Sender& sender, 
                                        ankerl::unordered_dense::set<uint64_t>& set_items, 
                                       size_t recvr_set_size,
                                       ankerl::unordered_dense::set<uint64_t>& pld_els) {
    MC_BEGIN(Proto, &sock, &sender, &set_items, recvr_set_size, &pld_els,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
        
    MC_AWAIT(sender.setup(sock, set_items));
    
    MC_AWAIT(sender.send(sock, pld_els));
    
    MC_END();
}

static coproto::task<void> recvr_exec(coproto::LocalAsyncSocket& sock, 
                                       psu::Receiver& receiver, 
                                        ankerl::unordered_dense::set<uint64_t>& set_items, 
                                       size_t sndr_set_size,
                                       ankerl::unordered_dense::set<uint64_t>& pld_els) {
    MC_BEGIN(Proto, &sock, &receiver, &set_items, sndr_set_size, &pld_els,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
        
    MC_AWAIT(receiver.setup(sock, set_items));

    MC_AWAIT(receiver.recv(sock, pld_els));
    
    MC_END();
}

int main() {

    const double IBLT_MULT_FAC = 1.5;
    size_t INPUT_SET_SIZE = 1 << 20;
    size_t THRESHOLD = INPUT_SET_SIZE*2;
    const size_t SOFTSPOKEN_OT_FIELD_SIZE = 3;
    const bool OPRF_REDUCED_ROUNDS = false;

    const block SENDER_SEED(block(804127122578564875ULL, 6452408941779289156ULL));
    const block RECVR_SEED(block(16925767379666885198ULL, 13843614222775765652ULL));
    const block IBLT_SEED(block(4672171876689324624ULL, 6415789310665420428ULL));

    auto sockets = LocalAsyncSocket::makePair();
    
    vector<uint64_t> sender_in_set_vec;
    vector<uint64_t> receiver_in_set_vec;
    gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
    gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE/2);

    ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
    ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

    Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
    Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

    ankerl::unordered_dense::set<uint64_t> sender_pld_els;
    ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

    auto p0 = sender_exec(sockets[0], sender, sender_in_set, receiver_in_set.size(), sender_pld_els);
    auto p1 = recvr_exec(sockets[1], receiver, receiver_in_set, sender_in_set.size(), receiver_pld_els);

    coproto::sync_wait(macoro::when_all_ready(std::move(p0), std::move(p1)));

    return 0;

}
