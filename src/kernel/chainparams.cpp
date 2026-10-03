// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include <arith_uint256.h>
// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

// This will figure out a valid hash and Nonce if you're
// creating a different genesis block:
// static void GenerateGenesisBlock(CBlockHeader &genesisBlock, uint256 &phash, uint32_t& nonce)
// {
//     arith_uint256 bnTarget;
//     bnTarget.SetCompact(genesisBlock.nBits);
//     while (true) {
//         genesisBlock.nNonce = nonce;
//         uint256 hash = genesisBlock.GetPoWHash();
//         if (UintToArith256(hash) <= bnTarget) {
//             phash = hash;
//             break;
//         }
//         nonce++;
//     }

//     tfm::format(std::cout,"------------------------------\n");
//         tfm::format(std::cout,"nbits = %u\n", genesisBlock.nBits);
//         tfm::format(std::cout,"nonce = %u\n", genesisBlock.nNonce);
//         tfm::format(std::cout,"Generate hash = %s\n", phash.ToString().c_str());
//         tfm::format(std::cout,"genesis hash = %s\n", genesisBlock.GetHash().ToString().c_str());
//         tfm::format(std::cout,"genesis POWhash = %s\n", genesisBlock.GetPoWHash().ToString().c_str());
//     tfm::format(std::cout,"------------------------------\n");
// }

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Nintondo";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));


/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.enforce_opcat_header_format = true;
        consensus.signet_challenge.clear();
        // Not used in Bells, but left here for completeness.
        consensus.nSubsidyHalvingInterval = 100000;

        consensus.BIP34Height = 40240;
        consensus.BIP34Hash = uint256S("0xc1490b4fe653745dc8638dfbb594d7a1e6138585fa689943835366d5fd842699");
        consensus.BIP65Height = 40240;
        consensus.BIP66Height = 40240;
        consensus.CSVHeight = 40240;
        consensus.nLegacyBlocksBefore = 120456; // we have v1 blocks 94100, 96100, 97524, 97962, 99213, 99677, 105400, 105497, 112774, 120455 mined during the dawn that have to be accepted
        consensus.SegwitHeight = 144000; // segwit activation height
        consensus.MinBIP9WarningHeight = 191520; // taproot activation height + miner confirmation window
        consensus.nNewPowDiffHeight = 144000;
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 60; // 1 min
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.fStrictChainId = true;
        consensus.nAuxpowChainId = 16;
        consensus.nAuxpowStartHeight = 144000;
        consensus.nBlockAfterAuxpowRewardThreshold = 1000;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POW_TARGET_SPACING;


        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up

        consensus.nRuleChangeActivationThreshold = 9576; // 95% of 10,080
        consensus.nMinerConfirmationWindow = 10080; // 60 * 24 * 7 = 10,080 blocks, or one week

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of OP_CAT, OP_CHECKTEMPLATEVERIFY, OP_INTERNALKEY, OP_CHECKSIGFROMSTACK
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].bit = 2;
        // Retain bit 2 and count signaling under the corrected deployment schedule.
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nStartTime = 1790812800; // 2026-10-01 00:00:00 UTC
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nTimeout = 1806537600; // 2027-04-01 00:00:00 UTC
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].min_activation_height = 1300320; // 129 * 10,080; a period boundary


        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000fba441d3034461e8eb4");
        consensus.defaultAssumeValid = uint256S("0xce239a6ef11816534978c769e0a308e4fb1dd2a35257c9766e9e8833b7c923bc"); // 781888

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc0;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xc0;
        nDefaultPort = 19919;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 420;
        m_assumed_chain_state_size = 35;

        genesis = CreateGenesisBlock(1383509530, 44481, 0x1e0ffff0, 1, 88 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xe5be24df57c43a82d15c2f06bda961296948f8f8eb48501bed1efb929afe0698"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("bdnsseeder.quark.blue.");
        vSeeds.emplace_back("seed.letitring.lol.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,30);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0xfa, 0xca, 0xfd};
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0xfa, 0xc3, 0x98};

        bech32_hrp = "bel";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {10000, uint256S("0x2c05ea6918e28ca2d216c6518940c8782c09bebfe705d792155465662e275351")},
                {100000, uint256S("0xa68c0093873f2b4f056be2c09afb021f15209a272f7c15a60d06aa680138cc6f")},
                {250000, uint256S("0x6ddb13850ae6b0f45b4eac4bb628ec6781402d0c6b54e5be2e45c81e1854cff1")},
                {550000, uint256S("0xf5f8b98bfd8ad9293e588b04bc030e75eab5f7aafe956c10e165d06c8277ebcd")},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 781'902,
                .hash_serialized = AssumeutxoHash{uint256{"8850a1faf8bc3d9b242b474d77c37e2f78a2eb4529860805f74735192956931a"}},
                .m_chain_tx_count = 1'406'382'686,
                .blockhash = consteval_ctor(uint256{"9f127e2b3d6ed4d66437456346d633947c51afdbe04a785ce7a7139d90b899eb"}),
            },
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 40320 7aba31517c58595373faf8b6baf51c6f74845a4cdbd8fa25b1c8b820a2d7e73b
            .nTime    = 1762358636,
            .tx_count = 1406382673,
            .dTxRate  = 45.33270639016964,
        };
    }
};

/**
 * Testnet (v1): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 100000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x122a09a8adfe47e0789226e54e5076b1235185ef6f55331825bf8ef594cf2434");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.nLegacyBlocksBefore = consensus.BIP34Height;
        consensus.SegwitHeight = 20;
        consensus.MinBIP9WarningHeight = 720; // taproot activation height + miner confirmation window
        consensus.nAuxpowStartHeight = 15;
        consensus.nBlockAfterAuxpowRewardThreshold = 5;
        consensus.nNewPowDiffHeight = 20;
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 60;
        consensus.nAuxpowChainId = 16;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.fStrictChainId = true;
        consensus.nRuleChangeActivationThreshold = 180; // 75% for testchains
        consensus.nMinerConfirmationWindow = 240;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POW_TARGET_SPACING;
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up        

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of OP_CAT, OP_CHECKTEMPLATEVERIFY, OP_INTERNALKEY, OP_CHECKSIGFROMSTACK
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nStartTime = 1747267200; // 2025-05-15 00:00:00        
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nTimeout = 1772658000; // 2026-06-15 00:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].min_activation_height = 360000;


        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000081344733b462c7");
        consensus.defaultAssumeValid = uint256S("0x45b5f584778036f9c7c2ea44f7a09e1dd7df0dc07ba61f47ab79065e03012975"); // 532646

        pchMessageStart[0] = 0xc3;
        pchMessageStart[1] = 0xc3;
        pchMessageStart[2] = 0xc3;
        pchMessageStart[3] = 0xc3;
        nDefaultPort = 29919;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 2;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1383509530, 44481, 0x1e0ffff0, 1, 88 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xe5be24df57c43a82d15c2f06bda961296948f8f8eb48501bed1efb929afe0698"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,33);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,22);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,158);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0xfa, 0xca, 0xfd};
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0xfa, 0xc3, 0x98};

        bech32_hrp = "tbel";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {546, uint256S("6957c03b49190a7c703d20e21cf05a4c34a0937072f27f5e1074f33e360f362c")},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 532'658,
                .hash_serialized = AssumeutxoHash{uint256{"30867ade42553d4542a4e5d3bb79defac894e1592e1095e7d5d81d5ce54df94c"}},
                .m_chain_tx_count = 760'649,
                .blockhash = consteval_ctor(uint256{"26d7f174e3a70398f38bfe15f245a8791493080d3bed0e34024d65c1152b47e6"}),
            },
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 40320 45b5f584778036f9c7c2ea44f7a09e1dd7df0dc07ba61f47ab79065e03012975
            .nTime    = 1762364260,
            .tx_count = 760637,
            .dTxRate  = 0.009960166201399528,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            vSeeds.emplace_back("seed.signet.bitcoin.sprovoost.nl.");
            vSeeds.emplace_back("seed.signet.achownodes.xyz."); // Ava Chow, only supports x1, x5, x9, x49, x809, x849, xd, x400, x404, x408, x448, xc08, xc48, x40c

            // Hardcoded nodes can be removed once there are more DNS seeds
            vSeeds.emplace_back("178.128.221.177");
            vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000000025dbd66e58f"};
            consensus.defaultAssumeValid = uint256{"0000014aad1d58dddcb964dd749b073374c6306e716b22f573a2efe68d414539"}; // 208800
            m_assumed_blockchain_size = 2;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 0000014aad1d58dddcb964dd749b073374c6306e716b22f573a2efe68d414539
                .nTime    = 1723655233,
                .tx_count = 5507045,
                .dTxRate  = 0.06271073277261494,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nAuxpowChainId = 16;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 1;
        consensus.fStrictChainId = true;
        consensus.nNewPowDiffHeight = 999999999;
        consensus.powLimit = uint256S("00000377ae000000000000000000000000000000000000000000000000000000");
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POW_TARGET_SPACING;
        consensus.nPowAveragingWindow = 17;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of OP_CAT, OP_CHECKTEMPLATEVERIFY, OP_INTERNALKEY, OP_CHECKSIGFROMSTACK
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nStartTime = 1747267200; // 2025-05-15 00:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nTimeout = 1772658000; // 2026-06-15 00:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].min_activation_height = 360000;

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1383509530, 44481, 0x1e0ffff0, 1, 88 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xe5be24df57c43a82d15c2f06bda961296948f8f8eb48501bed1efb929afe0698"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

        vFixedSeeds.clear();

        m_assumeutxo_data = {
            {
                .height = 160'000,
                .hash_serialized = AssumeutxoHash{uint256{"fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a"}},
                .m_chain_tx_count = 2289496,
                .blockhash = consteval_ctor(uint256{"0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c"}),
            }
        };

        // base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        // base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        // base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xfd};
        // base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,30);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,22);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,158);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0xfa, 0xca, 0xfd};
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0xfa, 0xc3, 0x98};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.nLegacyBlocksBefore = consensus.BIP34Height;
        consensus.SegwitHeight = 1; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 1;
        consensus.nNewPowDiffHeight = 0;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"); // if this is any larger, the for loop in GetNextWorkRequired can overflow bnTot
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowTargetTimespan = 4 * 60 * 60;
        consensus.nPowTargetSpacing = 60; // 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = true;
        consensus.fStrictChainId = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POW_TARGET_SPACING;
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of OP_CAT/CHECK_TEMPLATE_VERIFY
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_OP_CAT].min_activation_height = 0;
        
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");
        consensus.nAuxpowStartHeight = 0;
        consensus.nBlockAfterAuxpowRewardThreshold = 5;
        consensus.nAuxpowChainId = 16;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;


        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }
        consensus.nLegacyBlocksBefore = consensus.BIP34Height;

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            // Preserve the default regtest deployment and its existing fixtures.
            // Explicit OP_CAT deployment tests exercise the rescheduled mainnet rules.
            if (deployment_pos == Consensus::DEPLOYMENT_OP_CAT) {
                consensus.enforce_opcat_header_format = true;
            }
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        //uint256 hash;
        //uint32_t nonce = 0;
        //CBlockHeader genesisHeader = genesis.GetBlockHeader();
        //GenerateGenesisBlock(genesisHeader, hash, nonce);

        

        genesis = CreateGenesisBlock(1383509530, 105, 0x200f0f0f, 1, 88 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xf97be01b640a39ac10c75da8d749bed0b065f25d9b28f51fe8070a6cdf976e1a")); 
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");


        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x060d055c3433a00135205c4326590389b4a5196788f5810d02a74e2cd5fb221b")},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256{"acf5b20d7372e4180b6858d5e564d89d5147d7cb64b2320e1a52237c5c0e117a"}},
                .m_chain_tx_count = 111,
                .blockhash = consteval_ctor(uint256{"6c8ca461bebaa0f9d28f70eec69bdb4c788d52d889cf9e0ffcb9bc184241e181"}),
            },
            {
                .height = 200,
                .hash_serialized = AssumeutxoHash{uint256{"83a66265d71b1ecea3542a47da38895b72bc8fda7fd0e0c0492c6bf2134d6451"}},
                .m_chain_tx_count = 201,
                .blockhash = consteval_ctor(uint256{"5653c55b52ea27f00c5a26a01218d118a3a2f77e2984d8e8d5607d56041189f7"}),
            },            
            {
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256{"4899f07889bedd831b34cf83464303d99fe3c5b4ed88f43ae10c3ea3e974d34d"}},
                .m_chain_tx_count = 334,
                .blockhash = consteval_ctor(uint256{"67626c7385240a9cf7228fae5ca76a20057f3bc6fdace25afa6d68f3ee0e8dd4"}),
            },

        };

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0.001, // Set a non-zero rate to make it testable
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::equal(message.begin(), message.end(), mainnet_msg.data())) {
        return ChainType::MAIN;
    } else if (std::equal(message.begin(), message.end(), testnet_msg.data())) {
        return ChainType::TESTNET;
    } else if (std::equal(message.begin(), message.end(), regtest_msg.data())) {
        return ChainType::REGTEST;
    } else if (std::equal(message.begin(), message.end(), signet_msg.data())) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
