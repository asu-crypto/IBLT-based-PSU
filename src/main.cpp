#include "coproto/Socket/AsioSocket.h"
#include "coproto/coproto.h"
#include "volePSI/RsOprf.h"
#include "./psu.h"
#include "./iblt_h5.hpp"
#include <vector>
#include <chrono>
#include <unordered_set>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <boost/optional.hpp>
#include <ankerl/unordered_dense.h>

using namespace coproto;

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

void run_receiver(const block RECVR_SEED, size_t INPUT_SET_SIZE, size_t IBLT_SIZE, const block IBLT_SEED, double IBLT_MULT_FAC, size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, bool OPRF_REDUCED_ROUNDS) {

    std::string ip = "127.0.0.1:1212";
    
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(1);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioConnect connector(ip, ioc);

    AsioSocket receiver_socket = std::get<0>(macoro::sync_wait(macoro::when_all_ready(std::move(connector)))).result();

    vector<uint64_t> receiver_in_set_vec;
    gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE/2);

    ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

    Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

    ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

    for(size_t i = 0; i < 5; i++) {
         auto p = receiver.setup(receiver_socket, receiver_in_set);

        auto t0 = std::chrono::high_resolution_clock::now();

        sync_wait(when_all_ready(std::move(p)));

        p = receiver.recv(receiver_socket, receiver_pld_els);

        sync_wait(when_all_ready(std::move(p)));

            auto t1 = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> diff = t1 - t0;
            std::cout << "Receiver done in " << diff.count() << " seconds." << std::endl;
    }

    w.reset();

    for (auto& t : thrds)
        t.join();

}

void run_sender(const block SENDER_SEED, size_t INPUT_SET_SIZE, const block IBLT_SEED, double IBLT_MULT_FAC, size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE, bool OPRF_REDUCED_ROUNDS) {

    std::string ip = "127.0.0.1:1212";

    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(1);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);

    AsioSocket sender_socket = std::get<0>(macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept()))).result();

    vector<uint64_t> sender_in_set_vec;
    gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);

    ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
    
    Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

    ankerl::unordered_dense::set<uint64_t> sender_pld_els;

    for (size_t i = 0; i < 5; i++)
    {
        auto p = sender.setup(sender_socket, sender_in_set);

        sync_wait(when_all_ready(std::move(p)));

        p = sender.send(sender_socket, sender_pld_els);

        sync_wait(when_all_ready(std::move(p)));
    }

    w.reset();

    for (auto& t : thrds)
        t.join();

}

int main(int argc, char** argv) {
    
    if (argc < 8) {
        std::cerr << "Usage: " << argv[0] << " <player_index> <log2_set_size> <iblt_mult_factor> <ot_field_size> <oprf_reduced_rounds> <iblt_seed_1> <iblt_seed_2>" << std::endl;
        return 1;
    }

    int player_index = std::atoi(argv[1]);
    int log2_set_size = std::atoi(argv[2]);
    double iblt_mult_factor = std::atof(argv[3]);
    size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = std::atoi(argv[4]);
    bool OPRF_REDUCED_ROUNDS = (std::atoi(argv[5]) != 0);
    uint64_t iblt_seed_1 = std::stoull(argv[6]);
    uint64_t iblt_seed_2 = std::stoull(argv[7]);

    size_t set_size = 1ULL << log2_set_size;

    std::cout << "Player " << player_index << " with log2_set_size " << log2_set_size << " (set_size=" << set_size << ") and IBLT mult factor " << iblt_mult_factor << " OT field size " << LOCAL_SOFTSPOKEN_OT_FIELD_SIZE << " OPRF reduced rounds " << OPRF_REDUCED_ROUNDS << " IBLT seeds: " << iblt_seed_1 << ", " << iblt_seed_2 << std::endl;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

    if(player_index == 0) {
        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(iblt_seed_1, iblt_seed_2));
        run_sender(SENDER_SEED, set_size, IBLT_SEED, iblt_mult_factor, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
    }
    else {
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(iblt_seed_1, iblt_seed_2));
        run_receiver(RECVR_SEED, set_size, set_size, IBLT_SEED, iblt_mult_factor, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

    }

    return 0;

}