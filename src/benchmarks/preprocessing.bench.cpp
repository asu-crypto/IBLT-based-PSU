#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVole.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "libOTe/Tools/RepetitionCode.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"
#include <array>

using namespace osuCrypto;
//using namespace volePSI;
using namespace coproto;
using std::array;
using macoro::sync_wait;
using macoro::when_all_ready;
/*

TEST_CASE("Preprocessing Benchmark", "[preprocessing]") {
    BENCHMARK_ADVANCED("Preprocessing Benchmark")(Catch::Benchmark::Chronometer meter) {
        const size_t VOLE_COUNT = 1 << 16; // 2^16 queries
        const size_t OT_COUNT1 = 1 << 20; // 2^20 OT count
        const size_t OT_COUNT2 = 1 << 20; // 2^20 OT count
        const size_t FIELD_BITS = 2;
        PRNG prng(block(0x1234567890abcdef, 0xfedcba0987654321));
        PRNG sprng(block(0x1234567890abcdef, 0xfedcba0987654321));
        PRNG rprng(block(0x1234567890abcdef, 0xfedcba0987654321));

        auto sockets = LocalAsyncSocket::makePair();

        RsOprfSender mOprfSender;
        RsOprfReceiver mOprfReceiver;

        auto otSender1 = new osuCrypto::SoftSpokenShOtSender<>();
        auto otReceiver1 = new osuCrypto::SoftSpokenShOtReceiver<>();
        auto otSender2 = new osuCrypto::SoftSpokenShOtSender<>();
        auto otReceiver2 = new osuCrypto::SoftSpokenShOtReceiver<>();
        otSender1->init(FIELD_BITS, true);
        otReceiver1->init(FIELD_BITS, true);
        otSender2->init(FIELD_BITS, true);
        otReceiver2->init(FIELD_BITS, true);
        
        size_t voleBaseOtCount = mVoleSender.silentBaseOtCount();
        size_t otBaseOtCount = otSender1->baseOtCount();

        //std::cout << "voleBaseOtCount = " << voleBaseOtCount << std::endl;

        //std::cout << mVoleSender.mGen.baseOtCount() << " base OTs for VOLE" << std::endl;

        BitVector choices(OT_COUNT1 + otBaseOtCount);
        AlignedVector<array<block, 2>> sendMsgs(OT_COUNT1 + voleBaseOtCount + otBaseOtCount);
        AlignedVector<block> recvMsgs(OT_COUNT1 + voleBaseOtCount + otBaseOtCount);

        BitVector choices2(OT_COUNT2);
        AlignedVector<array<block, 2>> sendMsgs2(OT_COUNT2);
        AlignedVector<block> recvMsgs2(OT_COUNT2);

        
        meter.measure([&]() {
            choices.randomize(rprng);
            choices.append(mVoleReceiver.sampleBaseChoiceBits(rprng));

            auto p0 = otSender1->send(sendMsgs, sprng, sockets[0]);
            auto p1 = otReceiver1->receive(choices, recvMsgs, rprng, sockets[1]);
            sync_wait(when_all_ready(std::move(p0), std::move(p1)));

            BitVector baseChoices(choices.data(), otBaseOtCount, OT_COUNT1); 

            otSender2->setBaseOts(recvMsgs.subspan(OT_COUNT1, otBaseOtCount), baseChoices);
            otReceiver2->setBaseOts(sendMsgs.subspan(OT_COUNT1, otBaseOtCount));

            auto p2 = otSender2->send(sendMsgs2, sprng, sockets[0]);
            auto p3 = otReceiver2->receive(choices2, recvMsgs2, rprng, sockets[1]);
            sync_wait(when_all_ready(std::move(p2), std::move(p3)));

            

        });

    };

}*/

TEST_CASE("Concurrent OTs with recersed roles", "[preprocessing][ot]") {
    BENCHMARK_ADVANCED("Concurrent OTs with reversed roles")(Catch::Benchmark::Chronometer meter) {
        const size_t OT_COUNT = 11534336*3; // 2^16 OTs
        const size_t FIELD_BITS = 2;
        PRNG prng(block(0x1234567890abcdef, 0xfedcba0987654321));
        PRNG sprng(block(0x1234567890abcdef, 0xfedcba0987654321));
        PRNG rprng(block(0x1234567890abcdef, 0xfedcba0987654321));

        auto sockets = LocalAsyncSocket::makePair();

        auto otSender1 = new osuCrypto::SoftSpokenShOtSender<>();
        auto otReceiver1 = new osuCrypto::SoftSpokenShOtReceiver<>();
        auto otSender2 = new osuCrypto::SoftSpokenShOtSender<>();
        auto otReceiver2 = new osuCrypto::SoftSpokenShOtReceiver<>();
        otSender1->init(FIELD_BITS, true);
        otReceiver1->init(FIELD_BITS, true);
        otSender2->init(FIELD_BITS, true);
        otReceiver2->init(FIELD_BITS, true);

        BitVector choices1(OT_COUNT), choices2(OT_COUNT);
        AlignedVector<array<block, 2>> sendMsgs1(OT_COUNT), sendMsgs2(OT_COUNT);
        AlignedVector<block> recvMsgs(OT_COUNT), recvMsgs2(OT_COUNT);

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);

        meter.measure([&]() {
            choices1.randomize(rprng);
            choices2.randomize(sprng);
            
            auto p0 = otSender1->send(sendMsgs1, sprng, sockets[0]);
            auto p1 = otReceiver1->receive(choices1, recvMsgs, rprng, sockets[1]);
            //sync_wait(when_all_ready(std::move(p0), std::move(p1)));
            auto p2 = otSender2->send(sendMsgs2, rprng, sockets[1]);
            auto p3 = otReceiver2->receive(choices2, recvMsgs2, sprng, sockets[0]);
            //sync_wait(when_all_ready(std::move(p2), std::move(p3)));

            coproto::sync_wait(macoro::when_all_ready(
                std::move(p0) | macoro::start_on(pool0),
                std::move(p1) | macoro::start_on(pool1),
                std::move(p2) | macoro::start_on(pool1),
                std::move(p3) | macoro::start_on(pool0)));

        });

    };
}

TEST_CASE("Single SoftSpoken OT Extension", "[preprocessing][ot][single]") {
    BENCHMARK_ADVANCED("Single SoftSpoken OT Extension")(Catch::Benchmark::Chronometer meter) {
        const size_t OT_COUNT = 11534336*3; // 2^16 OTs
        const size_t FIELD_BITS = 2;
        PRNG prng(block(0x1234567890abcdef, 0xfedcba0987654321));
        PRNG sprng(block(0x1234567890abcdef, 0xfedcba0987654321));
        PRNG rprng(block(0x1234567890abcdef, 0xfedcba0987654321));

        auto sockets = LocalAsyncSocket::makePair();

        auto otSender = new osuCrypto::SoftSpokenShOtSender<>();
        auto otReceiver = new osuCrypto::SoftSpokenShOtReceiver<>();
        otSender->init(FIELD_BITS, true);
        otReceiver->init(FIELD_BITS, true);

        BitVector choices(OT_COUNT);
        AlignedVector<array<block, 2>> sendMsgs(OT_COUNT);
        AlignedVector<block> recvMsgs(OT_COUNT);

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        sockets[0].setExecutor(pool0);
        sockets[1].setExecutor(pool1);

        meter.measure([&]() {
            choices.randomize(rprng);
            
            auto p0 = otSender->send(sendMsgs, sprng, sockets[0]);
            auto p1 = otReceiver->receive(choices, recvMsgs, rprng, sockets[1]);
            coproto::sync_wait(macoro::when_all_ready(
                std::move(p0) | macoro::start_on(pool0),
                std::move(p1) | macoro::start_on(pool1)));
        });

    };
}