// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <deque>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header.GetPoWHash(), starting_header.nBits, GlobParams().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(GlobParams().GenesisBlock().GetHash()));
    const arith_uint256 chain_work = chain_start->nChainWork + GetBlockProof(*chain_start) * (target_blocks - 1);

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, GlobParams().GenesisBlock().GetHash(),
            GlobParams().GenesisBlock().nVersion, GlobParams().GenesisBlock().nTime,
            ArithToUint256(0), GlobParams().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, GlobParams().GenesisBlock().GetHash(),
            GlobParams().GenesisBlock().nVersion, GlobParams().GenesisBlock().nTime,
            ArithToUint256(1), GlobParams().GenesisBlock().nBits);

    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, GlobParams().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, GlobParams().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);

    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, GlobParams().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

namespace {

/** Generate linked histories using the consensus difficulty calculation as the
 * oracle. These unit tests exercise target/MTP handling, not mining: hashes are
 * not solved, since HeadersSyncState requires its caller to check actual PoW.
 * Hash storage is allocated up front and indices use a deque to keep pprev
 * and phashBlock pointers stable.
 */
struct RetargetHistory {
    std::vector<CBlockHeader> headers;
    std::vector<uint256> hashes;
    std::deque<CBlockIndex> indices;

    RetargetHistory(const Consensus::Params& params, int count, uint64_t seed, int pattern)
        : headers(count), hashes(count)
    {
        FastRandomContext rng{ArithToUint256(arith_uint256{seed})};
        for (int h = 0; h < count; ++h) {
            auto& header = headers[h];
            header.nVersion = 4;
            header.hashMerkleRoot = ArithToUint256(arith_uint256{static_cast<uint64_t>(h)});
            if (h == 0) {
                header.nTime = 1700000000;
                header.nBits = UintToArith256(params.powLimit).GetCompact();
            } else {
                const auto& prev = indices[h - 1];
                header.hashPrevBlock = hashes[h - 1];
                int64_t delta = params.PoWTargetSpacing().count();
                // Keep the long legacy prefix regular; vary the per-block era.
                if (h > params.nNewPowDiffHeight) {
                    if (pattern == 1) delta = rng.randrange(601) - int64_t{180};
                    if (pattern == 2) delta = (h / 64) % 2 ? 1 : 600;
                    if (pattern == 3) {
                        // Equal/backward raw timestamps and both sides of the
                        // optional six-spacing minimum-difficulty boundary.
                        const int64_t deltas[]{-120, 0, 1, 60, 360, 361, 720};
                        delta = deltas[h % 7];
                    }
                }
                header.nTime = std::max(prev.GetMedianTimePast() + 1, prev.GetBlockTime() + delta);
                header.nBits = GetNextWorkRequired(&prev, &header, params);
                BOOST_REQUIRE_GT(header.nTime, prev.GetMedianTimePast());
                BOOST_REQUIRE(CheckProofOfWork(uint256{}, header.nBits, params)); // valid target encoding/range
            }
            hashes[h] = header.GetHash();
            indices.emplace_back(header);
            auto& index = indices[h];
            index.phashBlock = &hashes[h];
            index.pprev = h ? &indices[h - 1] : nullptr;
            index.nHeight = h;
            index.BuildSkip();
            index.nChainWork = (h ? indices[h - 1].nChainWork : arith_uint256{}) + GetBlockProof(index);
        }
    }
};

/** Exercise different message boundaries in the two passes. Starting a new
 * object at an interior fork point tests seeding after a sync restart too. */
void CheckRetargetHistory(const Consensus::Params& params, const RetargetHistory& history, int start)
{
    BOOST_TEST_CONTEXT("start=" << start << " switch=" << params.nNewPowDiffHeight) {
        HeadersSyncState sync{0, params, &history.indices[start], history.indices.back().nChainWork};
        const size_t batch_sizes[]{1, 10, 17, 29, 599, 2000};
        size_t released{static_cast<size_t>(start + 1)};
        bool released_before_tip{false};
        for (int pass = 0; pass < 2; ++pass) {
            size_t offset{static_cast<size_t>(start + 1)};
            size_t batch_index{0};
            while (offset < history.headers.size()) {
                const size_t batch_size = batch_sizes[(batch_index++ + pass * 3) % std::size(batch_sizes)];
                const size_t end = std::min(offset + batch_size, history.headers.size());
                const std::vector<CBlockHeader> batch{history.headers.begin() + offset, history.headers.begin() + end};
                auto result = sync.ProcessNextHeaders(batch, end < history.headers.size());
                BOOST_TEST_CONTEXT("pass=" << pass << " first=" << offset << " last=" << end - 1) {
                    BOOST_REQUIRE(result.success);
                    if (pass == 0) {
                        BOOST_CHECK(result.pow_validated_headers.empty());
                        BOOST_CHECK(result.request_more);
                        BOOST_CHECK_EQUAL(sync.GetPresyncHeight(), end - 1);
                        BOOST_CHECK(sync.GetPresyncWork() == history.indices[end - 1].nChainWork);
                    } else {
                        if (end < history.headers.size() && !result.pow_validated_headers.empty()) released_before_tip = true;
                        for (const auto& header : result.pow_validated_headers) {
                            BOOST_REQUIRE_LT(released, history.hashes.size());
                            BOOST_CHECK(header.GetHash() == history.hashes[released++]);
                        }
                        BOOST_CHECK_EQUAL(result.request_more, end < history.headers.size());
                    }
                }
                offset = end;
            }
            BOOST_CHECK(sync.GetState() == (pass == 0 ? HeadersSyncState::State::REDOWNLOAD : HeadersSyncState::State::FINAL));
        }
        BOOST_CHECK_EQUAL(released, history.headers.size());
        // The long case also exercises eviction from the redownload buffer.
        if (history.headers.size() - start > 15000) BOOST_CHECK(released_before_tip);
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(headers_sync_mainnet_retarget_history)
{
    const auto chainparams = CChainParams::Main();
    const auto& params = chainparams->GetConsensus();
    const int activation = params.nNewPowDiffHeight;
    const RetargetHistory history{params, activation + 16000, 1, 1};
    // Genesis, partial MTP/window history, and both sides of the switch and
    // the filter's transition grace window. Every run includes both passes.
    for (const int start : {0, 1, 10, 16, 17, 18, 28, 29, activation - 1,
                           activation, activation + 1, activation + 16,
                           activation + 17, activation + 18, activation + 15900}) {
        CheckRetargetHistory(params, history, start);
    }
}

BOOST_AUTO_TEST_CASE(headers_sync_retarget_timestamp_patterns)
{
    const auto chainparams = CChainParams::TestNet();
    const auto& params = chainparams->GetConsensus();
    for (int pattern = 0; pattern < 4; ++pattern) {
        for (uint64_t seed = 1; seed <= 4; ++seed) {
            BOOST_TEST_CONTEXT("pattern=" << pattern << " seed=" << seed) {
                const RetargetHistory history{params, 800, seed, pattern};
                for (const int start : {0, 10, 16, 17, 20, 21, 36, 37, 38, 100, 700}) {
                    CheckRetargetHistory(params, history, start);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(headers_sync_optional_min_difficulty)
{
    auto params = CChainParams::TestNet()->GetConsensus();
    params.nPowAllowMinDifficultyBlocksAfterHeight = 60;
    const RetargetHistory history{params, 800, 1, 3};
    for (const int start : {0, 37, 59, 60, 61, 100, 700}) {
        CheckRetargetHistory(params, history, start);
    }
}

BOOST_AUTO_TEST_CASE(headers_sync_rejects_invalid_retarget)
{
    const auto chainparams = CChainParams::TestNet();
    const auto& params = chainparams->GetConsensus();
    const RetargetHistory history{params, 200, 1, 0};
    const int start{100};
    auto bad = history.headers[start + 1];
    arith_uint256 target;
    target.SetCompact(bad.nBits);
    target /= 16;
    bad.nBits = target.GetCompact();
    BOOST_REQUIRE_NE(bad.nBits, GetNextWorkRequired(&history.indices[start], &bad, params));
    BOOST_REQUIRE(CheckProofOfWork(uint256{}, bad.nBits, params));

    // A large, invalid difficulty increase must still be rejected in either
    // pass. This ensures the positive tests cannot pass with a disabled filter.
    for (const bool redownload : {false, true}) {
        HeadersSyncState sync{0, params, &history.indices[start], history.indices.back().nChainWork};
        if (redownload) {
            const std::vector<CBlockHeader> batch{history.headers.begin() + start + 1, history.headers.end()};
            BOOST_REQUIRE(sync.ProcessNextHeaders(batch, false).success);
            BOOST_REQUIRE(sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
        }
        const auto result = sync.ProcessNextHeaders({bad}, true);
        BOOST_CHECK(!result.success);
        BOOST_CHECK(!result.request_more);
        BOOST_CHECK(result.pow_validated_headers.empty());
        BOOST_CHECK(sync.GetState() == HeadersSyncState::State::FINAL);
    }
}

BOOST_AUTO_TEST_SUITE_END()
