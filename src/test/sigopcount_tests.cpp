// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <key.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <vector>

#include <boost/test/unit_test.hpp>

// Helpers:
static std::vector<unsigned char>
Serialize(const CScript& s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(sigopcount_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(GetSigOpCount)
{
    // Test CScript::GetSigOpCount()
    CScript s1;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 0U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 0U);

    uint160 dummy;
    s1 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 2U);
    s1 << OP_IF << OP_CHECKSIG << OP_ENDIF;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 21U);

    CScript p2sh = GetScriptForDestination(ScriptHash(s1));
    CScript scriptSig;
    scriptSig << OP_0 << Serialize(s1);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);

    std::vector<CPubKey> keys;
    for (int i = 0; i < 3; i++)
    {
        CKey k = GenerateRandomKey();
        keys.push_back(k.GetPubKey());
    }
    CScript s2 = GetScriptForMultisig(1, keys);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(false), 20U);

    p2sh = GetScriptForDestination(ScriptHash(s2));
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(true), 0U);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(false), 0U);
    CScript scriptSig2;
    scriptSig2 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << Serialize(s2);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig2), 3U);
}

/**
 * Verifies script execution of the zeroth scriptPubKey of tx output and
 * zeroth scriptSig and witness of tx input.
 */
static ScriptError VerifyWithFlag(const CTransaction& output, const CMutableTransaction& input, uint32_t flags)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output.vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &error);
    BOOST_CHECK((ret == true) == (error == SCRIPT_ERR_OK));

    return error;
}

/**
 * Builds a creationTx from scriptPubKey and a spendingTx from scriptSig
 * and witness such that spendingTx spends output zero of creationTx.
 * Also inserts creationTx's output into the coins view.
 */
static void BuildTxs(CMutableTransaction& spendingTx, CCoinsViewCache& coins, CMutableTransaction& creationTx, const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& witness)
{
    creationTx.nVersion = 1;
    creationTx.vin.resize(1);
    creationTx.vin[0].prevout.SetNull();
    creationTx.vin[0].scriptSig = CScript();
    creationTx.vout.resize(1);
    creationTx.vout[0].nValue = 1;
    creationTx.vout[0].scriptPubKey = scriptPubKey;

    spendingTx.nVersion = 1;
    spendingTx.vin.resize(1);
    spendingTx.vin[0].prevout.hash = creationTx.GetHash();
    spendingTx.vin[0].prevout.n = 0;
    spendingTx.vin[0].scriptSig = scriptSig;
    spendingTx.vin[0].scriptWitness = witness;
    spendingTx.vout.resize(1);
    spendingTx.vout[0].nValue = 1;
    spendingTx.vout[0].scriptPubKey = CScript();

    AddCoins(coins, CTransaction(creationTx), 0);
}

BOOST_AUTO_TEST_CASE(GetTxSigOpCost)
{
    // Transaction creates outputs
    CMutableTransaction creationTx;
    // Transaction that spends outputs and whose
    // sig op cost is going to be tested
    CMutableTransaction spendingTx;

    // Create utxo set
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    // Create key
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();
    // Default flags
    const uint32_t flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH};

    // Multisig script (legacy counting)
    {
        CScript scriptPubKey = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        // Do not use a valid signature to avoid using wallet operations.
        CScript scriptSig = CScript() << OP_0 << OP_0;

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        // Legacy counting only includes signature operations in scriptSigs and scriptPubKeys
        // of a transaction and does not take the actual executed sig operations into account.
        // spendingTx in itself does not contain a signature operation.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        // creationTx contains two signature operations in its scriptPubKey, but legacy counting
        // is not accurate.
        assert(GetTransactionSigOpCost(CTransaction(creationTx), coins, flags) == MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR);
        // Sanity check: script verification fails because of an invalid signature.
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // Multisig nested in P2SH
    {
        CScript redeemScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));
        CScript scriptSig = CScript() << OP_0 << OP_0 << ToByteVector(redeemScript);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2 * WITNESS_SCALE_FACTOR);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // P2WPKH witness program
    {
        CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);


        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        // No signature operations if we don't verify the witness.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);

        // The sig op cost for witness version != 0 is zero.
        assert(scriptPubKey[0] == 0x00);
        scriptPubKey[0] = 0x51;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        scriptPubKey[0] = 0x00;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);

        // The witness of a coinbase transaction is not taken into account.
        spendingTx.vin[0].prevout.SetNull();
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
    }

    // P2WPKH nested in P2SH
    {
        CScript scriptSig = GetScriptForDestination(WitnessV0KeyHash(pubkey));
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(scriptSig));
        scriptSig = CScript() << ToByteVector(scriptSig);
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);
    }

    // P2WSH witness program
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(witnessScript.begin(), witnessScript.end());

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // P2WSH nested in P2SH
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript redeemScript = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));
        CScript scriptSig = CScript() << ToByteVector(redeemScript);
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(witnessScript.begin(), witnessScript.end());

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }
}

BOOST_AUTO_TEST_CASE(p2sh_csfs_standardness_limit)
{
    // Standardness counts CSFSVERIFY even before deployment. Consensus costs
    // still follow the activation flags. Use unexecuted opcodes so both
    // sides of the policy boundary remain valid scripts under either rule set.
    struct Counts { unsigned int csfs; unsigned int checksig; };
    for (const auto counts : {Counts{15, 0}, Counts{16, 0}, Counts{1, 14},
                              Counts{2, 14}, Counts{0, 15}, Counts{0, 16}}) {
        BOOST_TEST_CONTEXT("CSFSVERIFY=" << counts.csfs << " CHECKSIG=" << counts.checksig) {
            CScript redeem = CScript() << OP_0 << OP_IF;
            for (unsigned int i = 0; i < counts.csfs; ++i) redeem << OP_CHECKSIGFROMSTACKVERIFY;
            for (unsigned int i = 0; i < counts.checksig; ++i) redeem << OP_CHECKSIG;
            redeem << OP_ENDIF << OP_TRUE;

            CCoinsView dummy;
            CCoinsViewCache coins(&dummy);
            CMutableTransaction funding, spending;
            BuildTxs(spending, coins, funding, GetScriptForDestination(ScriptHash(redeem)),
                     CScript() << ToByteVector(redeem), CScriptWitness());
            const CTransaction tx{spending};
            const auto total = counts.csfs + counts.checksig;
            BOOST_CHECK_EQUAL(AreInputsStandard(tx, coins), total <= MAX_P2SH_SIGOPS);

            const uint32_t before = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
            const uint32_t after = before | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
            BOOST_CHECK_EQUAL(GetTransactionSigOpCost(tx, coins, before), counts.checksig * WITNESS_SCALE_FACTOR);
            BOOST_CHECK_EQUAL(GetTransactionSigOpCost(tx, coins, after), total * WITNESS_SCALE_FACTOR);
            BOOST_CHECK_EQUAL(VerifyWithFlag(CTransaction(funding), spending, before), SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(VerifyWithFlag(CTransaction(funding), spending, after), SCRIPT_ERR_OK);
        }
    }
}

BOOST_AUTO_TEST_CASE(csfs_sigops_follow_activation)
{
    const uint32_t before = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    const uint32_t after = before | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
    // Even unexecuted NOP5s must keep their historical cost before activation.
    const CScript script = CScript() << OP_0 << OP_IF << OP_NOP5 << OP_ENDIF << OP_TRUE;
    BOOST_CHECK_EQUAL(script.GetSigOpCount(false), 0U);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true, true), 1U);

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    CMutableTransaction funding, spending;

    BuildTxs(spending, coins, funding, script, CScript(), CScriptWitness());
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(CTransaction(funding)), 0U);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(funding), coins, before), 0);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(funding), coins, after), 4);

    const CScript p2sh = GetScriptForDestination(ScriptHash(script));
    BuildTxs(spending, coins, funding, p2sh, CScript() << ToByteVector(script), CScriptWitness());
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(CTransaction(spending), coins), 0U);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, before), 0);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, after), 4);
    BOOST_CHECK_EQUAL(VerifyWithFlag(CTransaction(funding), spending, before), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerifyWithFlag(CTransaction(funding), spending, after), SCRIPT_ERR_OK);

    const CScript p2wsh = GetScriptForDestination(WitnessV0ScriptHash(script));
    CScriptWitness witness;
    witness.stack.emplace_back(script.begin(), script.end());
    BuildTxs(spending, coins, funding, p2wsh, CScript(), witness);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, before), 0);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, after), 1);
    BOOST_CHECK_EQUAL(VerifyWithFlag(CTransaction(funding), spending, before), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerifyWithFlag(CTransaction(funding), spending, after), SCRIPT_ERR_OK);

    const CScript nested = GetScriptForDestination(ScriptHash(p2wsh));
    BuildTxs(spending, coins, funding, nested, CScript() << ToByteVector(p2wsh), witness);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, before), 0);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, after), 1);

    // Regression: a zero-value, unspendable output could split main and dev
    // without executing any new opcode or reaching a BIP9 activation boundary.
    CScript oversized = CScript() << OP_RETURN;
    for (unsigned i = 0; i <= MAX_BLOCK_SIGOPS_COST / WITNESS_SCALE_FACTOR; ++i) oversized << OP_NOP5;
    BuildTxs(spending, coins, funding, oversized, CScript(), CScriptWitness());
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(funding), coins, before), 0);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(funding), coins, after), MAX_BLOCK_SIGOPS_COST + WITNESS_SCALE_FACTOR);
}

BOOST_AUTO_TEST_SUITE_END()
