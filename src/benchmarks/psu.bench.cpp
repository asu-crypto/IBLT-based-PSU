#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include "coproto/Socket/AsioSocket.h"
#include "coproto/coproto.h"
#include "volePSI/RsOprf.h"
#include "../psu.h"
#include "../iblt_h5.hpp"
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

static void warmup_sockets(AsioSocket& src, AsioSocket& dest, macoro::thread_pool& pool0, macoro::thread_pool& pool1, size_t byte_count, size_t iterations) {
    std::vector<uint8_t> send_buffer(byte_count);
    std::vector<uint8_t> recv_buffer(byte_count);

    for (size_t i = 0; i < iterations; ++i) {
        // std::cout << "Warmup iteration " << i+1 << " / " << iterations << std::endl;
    
        // Fill buffer with random data
        PRNG prng(osuCrypto::sysRandomSeed());
        prng.get(send_buffer.data(), send_buffer.size());

        auto p0 = src.send(send_buffer);
        auto p1 = dest.recv(recv_buffer);

        coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));

    }

}

static void gen_input_sets(std::vector<uint64_t>& set_items, size_t n, size_t start) {
    assert(start > 0);
    
    set_items.clear();
    for (size_t i = start; i < start+n; ++i) {
        set_items.push_back(i);
    }
}

static coproto::task<void> sender_exec(coproto::Socket& sock, 
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

static coproto::task<void> recvr_exec(coproto::Socket& sock, 
                                       psu::Receiver& receiver, 
                                       ankerl::unordered_dense::set<uint64_t>& set_items, 
                                       size_t sndr_set_size,
                                       ankerl::unordered_dense::set<uint64_t>& pld_els) {
    MC_BEGIN(Proto, &sock, &receiver, &set_items, sndr_set_size, &pld_els,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));

   // t0 = std::chrono::high_resolution_clock::now();
        
    MC_AWAIT(receiver.setup(sock, set_items));

    //t1 = std::chrono::high_resolution_clock::now();
    //duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    //std::cout << "Receiver setup time: " << duration << " ms" << std::endl;

  //  t0 = std::chrono::high_resolution_clock::now();

    MC_AWAIT(receiver.recv(sock, pld_els));

   // t1 = std::chrono::high_resolution_clock::now();
  //  duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
   // std::cout << "Receiver online time: " << duration << " ms" << std::endl;
    
    MC_END();
}

TEST_CASE("setup phase for n=2^16 set sizes", "[setup][n=2^16][local]") {
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        const size_t INPUT_SET_SIZE = 1 << 16;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.setup(sockets[0], sender_in_set);
        auto p1 = receiver.setup(sockets[1], receiver_in_set);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
    };
}

TEST_CASE("setup phase for n=2^20 set sizes", "[setup][n=2^20][local]") {
    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 20;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.setup(sockets[0], sender_in_set);
        auto p1 = receiver.setup(sockets[1], receiver_in_set);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        std::cout << "Total num of MB(s) exchanged: " << (((double) sockets[0].bytesSent() + sockets[1].bytesSent())/(1024.0*1024.0)) << std::endl;
    };
}

TEST_CASE("online phase for n=2^16 set sizes", "[online][n=2^16][local]") {
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        size_t INPUT_SET_SIZE = 1 << 16;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.setup(sockets[0], sender_in_set);
        auto p1 = receiver.setup(sockets[1], receiver_in_set);

        sync_wait(when_all_ready(std::move(p0), std::move(p1)));

        p0 = sender.send(sockets[0], sender_pld_els);
        p1 = receiver.recv(sockets[1], receiver_pld_els);

        //auto p0 = sender_exec(sockets[0], sender, sender_iblt, sender_in_set_vec_vec, receiver_in_set_vec.size(), sender_pld_els);
        //auto p1 = recvr_exec(sockets[1], receiver, recvr_iblt, receiver_in_set_vec, sender_in_set_vec_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

    };
}

TEST_CASE("online phase for n=2^20 set sizes", "[online][n=2^20][local]") {
    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 20;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.setup(sockets[0], sender_in_set);
        auto p1 = receiver.setup(sockets[1], receiver_in_set);

        sync_wait(when_all_ready(std::move(p0), std::move(p1)));

        p0 = sender.send(sockets[0], sender_pld_els);
        p1 = receiver.recv(sockets[1], receiver_pld_els);

        //auto p0 = sender_exec(sockets[0], sender, sender_iblt, sender_in_set_vec_vec, receiver_in_set_vec.size(), sender_pld_els);
        //auto p1 = recvr_exec(sockets[1], receiver, recvr_iblt, receiver_in_set_vec, sender_in_set_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

    };
}

TEST_CASE("setup and online phase for n=2^14 set sizes using local sockets", "[full][n=2^14][local]") {
    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 4.5;
        size_t INPUT_SET_SIZE = 1 << 14;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 3;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        std::string ip = "127.0.0.1:1212";
		
		boost::asio::io_context ioc;

		std::vector<std::thread> thrds(2);

        boost::optional<boost::asio::io_context::work> w(ioc);

		for (auto& t : thrds)
			t = std::thread([&] {ioc.run(); });

		AsioAcceptor connectionAcceptor(ip, ioc);
		AsioConnect connector(ip, ioc);

        auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

        AsioSocket
			sender_socket = std::get<0>(sockets).result(),
			receiver_socket = std::get<1>(sockets).result();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

       sender_socket.setExecutor(pool0);
       receiver_socket.setExecutor(pool1);

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        
        std::cout << "Total num of MB(s) exchanged: " << (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0)) << std::endl;

        w.reset();

		for (auto& t : thrds)
			t.join();

    };
}

TEST_CASE("setup and online phase for n=2^16 set sizes", "[full][n=2^16][local]") {
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        size_t INPUT_SET_SIZE = 1 << 16;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sockets[0], sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(sockets[1], receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        //std::cout << "Sender num of MB(s) sent: " << (((double) sockets[0].bytesSent())/(1024.0*1024.0)) << std::endl;
        //std::cout << "Receiver num of MB(s) sent: " << (((double) sockets[1].bytesSent())/(1024.0*1024.0)) << std::endl;
        std::cout << "Total num of MB(s) exchanged: " << (((double) sockets[0].bytesSent() + sockets[1].bytesSent())/(1024.0*1024.0)) << std::endl;

    };
}

TEST_CASE("setup and online phase for n=2^18 set sizes", "[full][n=2^18][local]") {
    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 2.0;
        size_t INPUT_SET_SIZE = 1 << 18;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sockets[0], sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(sockets[1], receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        
        std::cout << "Total num of MB(s) exchanged: " << (((double) sockets[0].bytesSent() + sockets[1].bytesSent())/(1024.0*1024.0)) << std::endl;

    };
}

TEST_CASE("setup and online phase for n=2^20 set sizes", "[full][n=2^20][local]") {
    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 20;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));
        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE+1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sockets[0], sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(sockets[1], receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        
        
        
        std::cout << "Total num of MB(s) exchanged: " << (((double) sockets[0].bytesSent() + sockets[1].bytesSent())/(1024.0*1024.0)) << std::endl;

    };
}

TEST_CASE("setup and online phase for n=2^22 set sizes", "[full][n=2^22][local]") {
    BENCHMARK_ADVANCED("n=2^22")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 22;
        const size_t LOCAL_SOFTSPOKEN_OT_FIELD_SIZE = 2;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        auto sockets = LocalAsyncSocket::makePair();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LOCAL_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sockets[0], sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(sockets[1], receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

        std::cout << "Total num of MB(s) exchanged: " << (((double) sockets[0].bytesSent() + sockets[1].bytesSent())/(1024.0*1024.0)) << std::endl;

    };
}

TEST_CASE("setup and online phase for n=2^14 set sizes using asio sockets", "[full][n=2^14][lan]") {
    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 4.5;
        size_t INPUT_SET_SIZE = 1 << 14;
        const size_t LAN_SOFTSPOKEN_OT_FIELD_SIZE = 3;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        std::string ip = "127.0.0.1:1212";
		
		boost::asio::io_context ioc;

		std::vector<std::thread> thrds(2);

        boost::optional<boost::asio::io_context::work> w(ioc);

		for (auto& t : thrds)
			t = std::thread([&] {ioc.run(); });

		AsioAcceptor connectionAcceptor(ip, ioc);
		AsioConnect connector(ip, ioc);

        auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

        AsioSocket
			sender_socket = std::get<0>(sockets).result(),
			receiver_socket = std::get<1>(sockets).result();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

       sender_socket.setExecutor(pool0);
       receiver_socket.setExecutor(pool1);

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

        w.reset();

		for (auto& t : thrds)
			t.join();

    };
}

TEST_CASE("setup and online phase for n=2^16 set sizes using asio sockets", "[full][n=2^16][lan]") {
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        size_t INPUT_SET_SIZE = 1 << 16;
        const size_t LAN_SOFTSPOKEN_OT_FIELD_SIZE = 3;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        std::string ip = "127.0.0.1:1212";
		
		boost::asio::io_context ioc;

		std::vector<std::thread> thrds(2);

        boost::optional<boost::asio::io_context::work> w(ioc);

		for (auto& t : thrds)
			t = std::thread([&] {ioc.run(); });

		AsioAcceptor connectionAcceptor(ip, ioc);
		AsioConnect connector(ip, ioc);

        auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

        AsioSocket
			sender_socket = std::get<0>(sockets).result(),
			receiver_socket = std::get<1>(sockets).result();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

       sender_socket.setExecutor(pool0);
       receiver_socket.setExecutor(pool1);

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

        w.reset();

		for (auto& t : thrds)
			t.join();

    };
}

TEST_CASE("setup and online phase for n=2^18 set sizes using asio sockets", "[full][n=2^18][lan]") {
    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 2.0;
        size_t INPUT_SET_SIZE = 1 << 18;
        const size_t LAN_SOFTSPOKEN_OT_FIELD_SIZE = 3;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        std::string ip = "127.0.0.1:1212";
		
		boost::asio::io_context ioc;

		std::vector<std::thread> thrds(2);

        boost::optional<boost::asio::io_context::work> w(ioc);

		for (auto& t : thrds)
			t = std::thread([&] {ioc.run(); });

		AsioAcceptor connectionAcceptor(ip, ioc);
		AsioConnect connector(ip, ioc);

        auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

        AsioSocket
			sender_socket = std::get<0>(sockets).result(),
			receiver_socket = std::get<1>(sockets).result();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

       sender_socket.setExecutor(pool0);
       receiver_socket.setExecutor(pool1);

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

         ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

        w.reset();

		for (auto& t : thrds)
			t.join();

    };
}

TEST_CASE("setup and online phase for n=2^20 set sizes using asio sockets", "[full][n=2^20][lan]") {
    
     std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    std::cout << "Warming up sockets... (This may take some time)" << std::endl;

    const size_t warmup_byte_transfer_per_iteration = 1 << 24;
    const size_t num_warmup_iterations = 1;

    warmup_sockets(sender_socket, receiver_socket, pool0, pool1, warmup_byte_transfer_per_iteration, num_warmup_iterations);
    warmup_sockets(receiver_socket, sender_socket, pool1, pool0, warmup_byte_transfer_per_iteration, num_warmup_iterations);

    std::cout << "Warming up done, starting benchmark..." << std::endl;
    
    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 20;
        const size_t LAN_SOFTSPOKEN_OT_FIELD_SIZE = 3;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, ((double) INPUT_SET_SIZE)*0.9);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();
}

TEST_CASE("setup and online phase for n=2^22 set sizes using asio sockets", "[full][n=2^22][lan]") {
    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);    

    std::cout << "Warming up sockets... (This may take some time)" << std::endl;

    const size_t warmup_byte_transfer_per_iteration = 1 << 24;
    const size_t num_warmup_iterations = 1;

    warmup_sockets(sender_socket, receiver_socket, pool0, pool1, warmup_byte_transfer_per_iteration, num_warmup_iterations);
    warmup_sockets(receiver_socket, sender_socket, pool1, pool0, warmup_byte_transfer_per_iteration, num_warmup_iterations);

    std::cout << "Warming up done, starting benchmark..." << std::endl;
    
    BENCHMARK_ADVANCED("n=2^22")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 22;
        const size_t LAN_SOFTSPOKEN_OT_FIELD_SIZE = 3;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));
        
        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE*0.9);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, LAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

    };

     w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("setup and online phase for n=2^14 set sizes using asio sockets", "[full][n=2^14][wan]") {
     std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

     std::cout << "Warming up sockets... (This may take some time)" << std::endl;

    const size_t warmup_byte_transfer_per_iteration = 1 << 24;
    const size_t num_warmup_iterations = 1;

    warmup_sockets(sender_socket, receiver_socket, pool0, pool1, warmup_byte_transfer_per_iteration, num_warmup_iterations);
    warmup_sockets(receiver_socket, sender_socket, pool1, pool0, warmup_byte_transfer_per_iteration, num_warmup_iterations);

    std::cout << "Warming up done, starting benchmark..." << std::endl;
    

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 4.5;
        size_t INPUT_SET_SIZE = 1 << 14;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8;
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

    };    

    w.reset();

    for (auto& t : thrds)
        t.join();
    
}

TEST_CASE("setup and online phase for n=2^16 set sizes using asio sockets", "[full][n=2^16][wan]") {

    std::string ip = "127.0.0.1:1212";
    
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    connectionAcceptor.mAcceptor.set_option(boost::asio::ip::tcp::no_delay(true));

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

     std::cout << "Warming up sockets... (This may take some time)" << std::endl;

    const size_t warmup_byte_transfer_per_iteration = 1 << 24;
    const size_t num_warmup_iterations = 1;

    warmup_sockets(sender_socket, receiver_socket, pool0, pool1, warmup_byte_transfer_per_iteration, num_warmup_iterations);
    warmup_sockets(receiver_socket, sender_socket, pool1, pool0, warmup_byte_transfer_per_iteration, num_warmup_iterations);

    std::cout << "Warming up done, starting benchmark..." << std::endl;

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        size_t INPUT_SET_SIZE = 1 << 16;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8; // Should be 8 for true WAN setting
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

         ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

    };

    w.reset();

	for (auto& t : thrds)
	    t.join();

}

TEST_CASE("setup phase for n=2^16 set sizes using asio sockets", "[setup][n=2^16][lan]") {
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        size_t INPUT_SET_SIZE = 1 << 16;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 3;
        const bool OPRF_REDUCED_ROUNDS = false;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        std::string ip = "127.0.0.1:1212";
		
		boost::asio::io_context ioc;

		std::vector<std::thread> thrds(2);

        boost::optional<boost::asio::io_context::work> w(ioc);

		for (auto& t : thrds)
			t = std::thread([&] {ioc.run(); });

		AsioAcceptor connectionAcceptor(ip, ioc);
		AsioConnect connector(ip, ioc);

        auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

        AsioSocket
			sender_socket = std::get<0>(sockets).result(),
			receiver_socket = std::get<1>(sockets).result();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

       sender_socket.setExecutor(pool0);
       receiver_socket.setExecutor(pool1);

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.setup(sender_socket, sender_in_set);
        auto p1 = receiver.setup(receiver_socket, receiver_in_set);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        w.reset();

		for (auto& t : thrds)
			t.join();

    };
}

TEST_CASE("setup phase for n=2^16 set sizes using asio sockets", "[setup][n=2^16][wan]") {
    
    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);
    
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        size_t INPUT_SET_SIZE = 1 << 16;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8;
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.wan_setup(sender_socket, sender_in_set);
        auto p1 = receiver.wan_setup(receiver_socket, receiver_in_set);

        warmup_sockets(sender_socket, receiver_socket, pool0, pool1, 1 << 26, 1);
        warmup_sockets(receiver_socket, sender_socket, pool1, pool0, 1 << 26, 1);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

    };

    w.reset();

    for (auto& t : thrds)
        t.join();
}

TEST_CASE("online phase for n=2^16 set sizes using asio sockets", "[online][n=2^16][wan]") {
    
    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(4);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);
    
    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 3.5;
        size_t INPUT_SET_SIZE = 1 << 16;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8;
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.wan_setup(sender_socket, sender_in_set);
        auto p1 = receiver.wan_setup(receiver_socket, receiver_in_set);

        sync_wait(when_all_ready(std::move(p0), std::move(p1)));

        p0 = sender.send(sender_socket, sender_pld_els);
        p1 = receiver.recv(receiver_socket, receiver_pld_els);

        warmup_sockets(sender_socket, receiver_socket, pool0, pool1, 1 << 26, 1);
        warmup_sockets(receiver_socket, sender_socket, pool1, pool0, 1 << 26, 1);

        //auto p0 = sender_exec(sockets[0], sender, sender_iblt, sender_in_set_vec_vec, receiver_in_set_vec.size(), sender_pld_els);
        //auto p1 = recvr_exec(sockets[1], receiver, recvr_iblt, receiver_in_set_vec, sender_in_set_vec_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("setup and online phase for n=2^18 set sizes using asio sockets", "[full][n=2^18][wan]") {
        std::string ip = "127.0.0.1:1212";
		
		boost::asio::io_context ioc;

		std::vector<std::thread> thrds(2);

        boost::optional<boost::asio::io_context::work> w(ioc);

		for (auto& t : thrds)
			t = std::thread([&] {ioc.run(); });

		AsioAcceptor connectionAcceptor(ip, ioc);
		AsioConnect connector(ip, ioc);

        auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

        AsioSocket
			sender_socket = std::get<0>(sockets).result(),
			receiver_socket = std::get<1>(sockets).result();

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

       sender_socket.setExecutor(pool0);
       receiver_socket.setExecutor(pool1);

       std::cout << "Warming up sockets... (This may take some time)" << std::endl;

       const size_t warmup_byte_transfer_per_iteration = 1 << 24;
       const size_t num_warmup_iterations = 1;

       warmup_sockets(sender_socket, receiver_socket, pool0, pool1, warmup_byte_transfer_per_iteration, num_warmup_iterations);
       warmup_sockets(receiver_socket, sender_socket, pool1, pool0, warmup_byte_transfer_per_iteration, num_warmup_iterations);

       std::cout << "Warming up done, starting benchmark..." << std::endl;
    
    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 2.0;
        size_t INPUT_SET_SIZE = 1 << 18;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8;
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();
}

TEST_CASE("online phase for n=2^18 set sizes using asio sockets", "[online][n=2^18][wan]") {
    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 2.0;
        size_t INPUT_SET_SIZE = 1 << 18;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8;
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        std::string ip = "127.0.0.1:1212";
		
		boost::asio::io_context ioc;

		std::vector<std::thread> thrds(4);

        boost::optional<boost::asio::io_context::work> w(ioc);

		for (auto& t : thrds)
			t = std::thread([&] {ioc.run(); });

		AsioAcceptor connectionAcceptor(ip, ioc);
		AsioConnect connector(ip, ioc);

        auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

        AsioSocket
			sender_socket = std::get<0>(sockets).result(),
			receiver_socket = std::get<1>(sockets).result();

        //std::cout << "Sleeping for 10 seconds..." << std::endl;
        //std::this_thread::sleep_for(std::chrono::seconds(10));

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

       sender_socket.setExecutor(pool0);
       receiver_socket.setExecutor(pool1);

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE + 1);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender.wan_setup(sender_socket, sender_in_set);
        auto p1 = receiver.wan_setup(receiver_socket, receiver_in_set);

        sync_wait(when_all_ready(std::move(p0), std::move(p1)));

        p0 = sender.send(sender_socket, sender_pld_els);
        p1 = receiver.recv(receiver_socket, receiver_pld_els);

        //auto p0 = sender_exec(sockets[0], sender, sender_iblt, sender_in_set_vec_vec, receiver_in_set_vec.size(), sender_pld_els);
        //auto p1 = recvr_exec(sockets[1], receiver, recvr_iblt, receiver_in_set_vec, sender_in_set_vec_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        w.reset();

		for (auto& t : thrds)
			t.join();

    };
}

TEST_CASE("setup and online phase for n=2^20 set sizes using asio sockets", "[full][n=2^20][wan]") {
    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    std::cout << "Warming up sockets... (This may take some time)" << std::endl;

    const size_t warmup_byte_transfer_per_iteration = 1 << 24;
    const size_t num_warmup_iterations = 1;

    warmup_sockets(sender_socket, receiver_socket, pool0, pool1, warmup_byte_transfer_per_iteration, num_warmup_iterations);
    warmup_sockets(receiver_socket, sender_socket, pool1, pool0, warmup_byte_transfer_per_iteration, num_warmup_iterations);

    std::cout << "Warming up done, starting benchmark..." << std::endl;
    
    
    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 20;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8;
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE*0.9);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();
}

TEST_CASE("setup and online phase for n=2^22 set sizes using asio sockets", "[full][n=2^22][wan]") {
     std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    std::cout << "Warming up sockets... (This may take some time)" << std::endl;

    const size_t warmup_byte_transfer_per_iteration = 1 << 24;
    const size_t num_warmup_iterations = 1;

    warmup_sockets(sender_socket, receiver_socket, pool0, pool1, warmup_byte_transfer_per_iteration, num_warmup_iterations);
    warmup_sockets(receiver_socket, sender_socket, pool1, pool0, warmup_byte_transfer_per_iteration, num_warmup_iterations);

    std::cout << "Warming up done, starting benchmark..." << std::endl;
    
    BENCHMARK_ADVANCED("n=2^22")(Catch::Benchmark::Chronometer meter) {
        const double IBLT_MULT_FAC = 1.5;
        size_t INPUT_SET_SIZE = 1 << 22;
        const size_t WAN_SOFTSPOKEN_OT_FIELD_SIZE = 8;
        const bool OPRF_REDUCED_ROUNDS = true;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

        const block SENDER_SEED(block(distrib(gen), distrib(gen)));
        const block RECVR_SEED(block(distrib(gen), distrib(gen)));
        const block IBLT_SEED(block(distrib(gen), distrib(gen)));

        vector<uint64_t> sender_in_set_vec;
        vector<uint64_t> receiver_in_set_vec;
        gen_input_sets(sender_in_set_vec, INPUT_SET_SIZE, 1);
        gen_input_sets(receiver_in_set_vec, INPUT_SET_SIZE, INPUT_SET_SIZE * 0.9);

        ankerl::unordered_dense::set<uint64_t> sender_in_set(sender_in_set_vec.begin(), sender_in_set_vec.end());
        ankerl::unordered_dense::set<uint64_t> receiver_in_set(receiver_in_set_vec.begin(), receiver_in_set_vec.end());

        Sender sender(SENDER_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);
        Receiver receiver(RECVR_SEED, INPUT_SET_SIZE, INPUT_SET_SIZE, IBLT_SEED, IBLT_MULT_FAC, WAN_SOFTSPOKEN_OT_FIELD_SIZE, OPRF_REDUCED_ROUNDS);

        ankerl::unordered_dense::set<uint64_t> sender_pld_els;
        ankerl::unordered_dense::set<uint64_t> receiver_pld_els;

        auto p0 = sender_exec(sender_socket, sender, sender_in_set, receiver_in_set_vec.size(), sender_pld_els);
        auto p1 = recvr_exec(receiver_socket, receiver, receiver_in_set, sender_in_set_vec.size(), receiver_pld_els);

       meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        ankerl::unordered_dense::set<uint64_t> expected_union;

        for (auto& el : sender_in_set)
            expected_union.insert(el);
        for (auto& el : receiver_in_set)
            expected_union.insert(el);

        REQUIRE(expected_union.size() == sender_pld_els.size());
        REQUIRE(expected_union == sender_pld_els);
        REQUIRE(sender_pld_els == receiver_pld_els);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();
}