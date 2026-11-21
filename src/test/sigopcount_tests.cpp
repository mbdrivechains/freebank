// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <pubkey.h>
#include <key.h>
#include <script/script.h>
#include <script/standard.h>
#include <uint256.h>
#include <test/test_bitcoin.h>

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

    CScript p2sh = GetScriptForDestination(CScriptID(s1));
    CScript scriptSig;
    scriptSig << OP_0 << Serialize(s1);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);

    std::vector<CPubKey> keys;
    for (int i = 0; i < 3; i++)
    {
        CKey k;
        k.MakeNewKey(true);
        keys.push_back(k.GetPubKey());
    }
    CScript s2 = GetScriptForMultisig(1, keys);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(false), 20U);

    p2sh = GetScriptForDestination(CScriptID(s2));
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
ScriptError VerifyWithFlag(const CTransaction& output, const CMutableTransaction& input, int flags)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output.vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output.vout[0].nValue), &error);
    BOOST_CHECK((ret == true) == (error == SCRIPT_ERR_OK));

    return error;
}

/**
 * Builds a creationTx from scriptPubKey and a spendingTx from scriptSig
 * and witness such that spendingTx spends output zero of creationTx.
 * Also inserts creationTx's output into the coins view.
 */
void BuildTxs(CMutableTransaction& spendingTx, CCoinsViewCache& coins, CMutableTransaction& creationTx, const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& witness)
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

    AddCoins(coins, creationTx, 0);
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
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    // Default flags
    int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;

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
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // Multisig nested in P2SH
    {
        CScript redeemScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
        CScript scriptSig = CScript() << OP_0 << OP_0 << ToByteVector(redeemScript);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2 * WITNESS_SCALE_FACTOR);
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // P2WPKH witness program
    {
        CScript p2pk = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
        CScript scriptPubKey = GetScriptForWitness(p2pk);
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));


        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        // No signature operations if we don't verify the witness.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);

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
        CScript p2pk = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
        CScript scriptSig = GetScriptForWitness(p2pk);
        CScript scriptPubKey = GetScriptForDestination(CScriptID(scriptSig));
        scriptSig = CScript() << ToByteVector(scriptSig);
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);
    }

    // P2WSH witness program
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForWitness(witnessScript);
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // P2WSH nested in P2SH
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript redeemScript = GetScriptForWitness(witnessScript);
        CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
        CScript scriptSig = CScript() << ToByteVector(redeemScript);
        CScriptWitness scriptWitness;
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(0));
        scriptWitness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }
}

// S5X-1 (switch-on consensus, from genesis; Michael 2026-11-19): an unspendable output carries no signature checks, so
// GetLegacySigOpCount leaves it out - whatever bytes follow the OP_RETURN. A spendable output still counts as before,
// and so does every scriptSig.
BOOST_AUTO_TEST_CASE(s5x_1_unspendable_outputs_count_no_sigops)
{
    CMutableTransaction m;
    m.vin.resize(1);
    m.vin[0].scriptSig = CScript() << OP_CHECKSIG;                               // scriptSigs still count: 1
    // Data after OP_RETURN that reads as 3 x CHECKMULTISIG (60) + CHECKSIG (1) if parsed as opcodes
    CScript data;
    data << OP_RETURN;
    data.push_back(OP_CHECKMULTISIG); data.push_back(OP_CHECKMULTISIG); data.push_back(OP_CHECKMULTISIG);
    data.push_back(OP_CHECKSIG);
    BOOST_CHECK_EQUAL(data.GetSigOpCount(false), 61U);                            // what it used to count
    m.vout.push_back(CTxOut(0, data));
    // A sidechain-object style header (OP_RETURN AC DC F6 6F): the 0xAC is OP_CHECKSIG if parsed
    CScript obj;
    obj.resize(5);
    obj[0] = OP_RETURN; obj[1] = 0xAC; obj[2] = 0xDC; obj[3] = 0xF6; obj[4] = 0x6F;
    m.vout.push_back(CTxOut(0, obj));
    // A spendable P2PKH output still counts its CHECKSIG
    CKey key;
    key.MakeNewKey(true);
    m.vout.push_back(CTxOut(1000, GetScriptForDestination(key.GetPubKey().GetID())));
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(CTransaction(m)), 2U);                 // scriptSig 1 + P2PKH 1; OP_RETURNs 0
    // An oversized script is unspendable too
    const std::vector<unsigned char> vBig(MAX_SCRIPT_SIZE + 1, OP_CHECKSIG);
    CScript big(vBig.begin(), vBig.end());
    BOOST_CHECK(big.IsUnspendable());
    m.vout.push_back(CTxOut(0, big));
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(CTransaction(m)), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
