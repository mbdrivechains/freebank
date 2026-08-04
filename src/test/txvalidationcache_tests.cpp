// Copyright (c) 2011-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <coins.h>
#include <key.h>
#include <keystore.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/standard.h>
#include <test/test_bitcoin.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks);

// FreeBank adaptation (NEXT.md C2b, 2026-08-01; full reasoning in
// docs-local/TEST_BASELINE.md C2b). The stock suite funded these tests from a
// TestChain100Setup coinbase chain, but a FreeBank unit test cannot connect
// blocks (CheckBlock requires a live mainchain via CheckMainchainConnection())
// and GetBlockSubsidy()==0 makes coinbase outputs valueless. CheckInputs itself
// is pure script verification against a coins view (no value checks, no chain
// access), so this suite now injects real-valued coins directly into a local
// CCoinsViewCache - the same pattern as the credit-primitive suites
// (deposit_tests/pool_tests). The stock tx_mempool_block_doublespend case is
// REMOVED as structural: its essence is block connection, unreachable in a
// unit test without the option-B CheckBlock seam (restorable if that lands).

BOOST_AUTO_TEST_SUITE(tx_validationcache_tests)

// Run CheckInputs (using the given coins view) on the given transaction, for
// all script flags. Test that CheckInputs passes for all flags that don't
// overlap with the failing_flags argument, but otherwise fails.
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY (and future NOP codes that may
// get reassigned) have an interaction with DISCOURAGE_UPGRADABLE_NOPS: if
// the script flags used contain DISCOURAGE_UPGRADABLE_NOPS but don't contain
// CHECKLOCKTIMEVERIFY (or CHECKSEQUENCEVERIFY), but the script does contain
// OP_CHECKLOCKTIMEVERIFY (or OP_CHECKSEQUENCEVERIFY), then script execution
// should fail.
// Capture this interaction with the upgraded_nop argument: set it when evaluating
// any script flag that is implemented as an upgraded NOP code.
static void ValidateCheckInputsForAllFlags(CMutableTransaction &tx, uint32_t failing_flags, bool add_to_cache, const CCoinsViewCache& view)
{
    PrecomputedTransactionData txdata(tx);
    // If we add many more flags, this loop can get too expensive, but we can
    // rewrite in the future to randomly pick a set of flags to evaluate.
    for (uint32_t test_flags=0; test_flags < (1U << 16); test_flags += 1) {
        CValidationState state;
        // Filter out incompatible flag choices
        if ((test_flags & SCRIPT_VERIFY_CLEANSTACK)) {
            // CLEANSTACK requires P2SH and WITNESS, see VerifyScript() in
            // script/interpreter.cpp
            test_flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        }
        if ((test_flags & SCRIPT_VERIFY_WITNESS)) {
            // WITNESS requires P2SH
            test_flags |= SCRIPT_VERIFY_P2SH;
        }
        bool ret = CheckInputs(tx, state, view, true, test_flags, true, add_to_cache, txdata, nullptr);
        // CheckInputs should succeed iff test_flags doesn't intersect with
        // failing_flags
        bool expected_return_value = !(test_flags & failing_flags);
        BOOST_CHECK_EQUAL(ret, expected_return_value);

        // Test the caching
        if (ret && add_to_cache) {
            // Check that we get a cache hit if the tx was valid
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputs(tx, state, view, true, test_flags, true, add_to_cache, txdata, &scriptchecks));
            BOOST_CHECK(scriptchecks.empty());
        } else {
            // Check that we get script executions to check, if the transaction
            // was invalid, or we didn't add to cache.
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputs(tx, state, view, true, test_flags, true, add_to_cache, txdata, &scriptchecks));
            BOOST_CHECK_EQUAL(scriptchecks.size(), tx.vin.size());
        }
    }
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, BasicTestingSetup)
{
    // Test that passing CheckInputs with one set of script flags doesn't imply
    // that we would pass again with a different set of flags.
    LOCK(cs_main); // CheckInputs asserts cs_main for the script execution cache
    InitScriptExecutionCache();

    // The injected coins view standing in for the stock coinbase chain.
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);

    CKey fundingKey;
    fundingKey.MakeNewKey(true);

    CScript p2pk_scriptPubKey = CScript() << ToByteVector(fundingKey.GetPubKey()) << OP_CHECKSIG;
    CScript p2sh_scriptPubKey = GetScriptForDestination(CScriptID(p2pk_scriptPubKey));
    CScript p2pkh_scriptPubKey = GetScriptForDestination(fundingKey.GetPubKey().GetID());
    CScript p2wpkh_scriptPubKey = GetScriptForWitness(p2pkh_scriptPubKey);

    CBasicKeyStore keystore;
    keystore.AddKey(fundingKey);
    keystore.AddCScript(p2pk_scriptPubKey);

    // Inject the funding coin (replaces the stock mature coinbase): a plain
    // value-bearing p2pk coin. Non-coinbase, so no maturity interaction; real
    // value, so the BIP143 amounts the witness signatures commit to are honest.
    const COutPoint fundingOutpoint(uint256S("0xc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2bc2b"), 0);
    view.AddCoin(fundingOutpoint, Coin(CTxOut(50*CENT, p2pk_scriptPubKey), 1, false, false, false, 0), false);

    // flags to test: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCE_VERIFY, SCRIPT_VERIFY_NULLDUMMY, uncompressed pubkey thing

    // Create 4 outputs that match the scripts above, spending the funding coin.
    CMutableTransaction spend_tx;

    spend_tx.nVersion = 1;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout = fundingOutpoint;
    spend_tx.vout.resize(4);
    spend_tx.vout[0].nValue = 11*CENT;
    spend_tx.vout[0].scriptPubKey = p2sh_scriptPubKey;
    spend_tx.vout[1].nValue = 11*CENT;
    spend_tx.vout[1].scriptPubKey = p2wpkh_scriptPubKey;
    spend_tx.vout[2].nValue = 11*CENT;
    spend_tx.vout[2].scriptPubKey = CScript() << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(fundingKey.GetPubKey()) << OP_CHECKSIG;
    spend_tx.vout[3].nValue = 11*CENT;
    spend_tx.vout[3].scriptPubKey = CScript() << OP_CHECKSEQUENCEVERIFY << OP_DROP << ToByteVector(fundingKey.GetPubKey()) << OP_CHECKSIG;

    // Sign, with a non-DER signature
    {
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(p2pk_scriptPubKey, spend_tx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_CHECK(fundingKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char) 0); // padding byte makes this non-DER
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spend_tx.vin[0].scriptSig << vchSig;
    }

    // Test that invalidity under a set of flags doesn't preclude validity
    // under other (eg consensus) flags.
    // spend_tx is invalid according to DERSIG
    {
        CValidationState state;
        PrecomputedTransactionData ptd_spend_tx(spend_tx);

        BOOST_CHECK(!CheckInputs(spend_tx, state, view, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, true, true, ptd_spend_tx, nullptr));

        // If we call again asking for scriptchecks (as happens in
        // ConnectBlock), we should add a script check object for this -- we're
        // not caching invalidity (if that changes, delete this test case).
        std::vector<CScriptCheck> scriptchecks;
        BOOST_CHECK(CheckInputs(spend_tx, state, view, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, true, true, ptd_spend_tx, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1);

        // Test that CheckInputs returns true iff DERSIG-enforcing flags are
        // not present.  Don't add these checks to the cache, so that we can
        // test later that the absence of cached successes is handled (the
        // stock suite proved it via block validation; here the later
        // ValidateCheckInputsForAllFlags calls re-execute the scripts).
        ValidateCheckInputsForAllFlags(spend_tx, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC, false, view);
    }

    // Make spend_tx's outputs spendable: inject them as coins (the stock suite
    // connected a block here; blocks cannot connect in a FreeBank unit test).
    // spend_tx is nVersion=1, so AddCoins takes the plain (untagged) branch.
    AddCoins(view, CTransaction(spend_tx), 1, 0, 0, 0, 0, 0, 0);

    // Test P2SH: construct a transaction that is valid without P2SH, and
    // then test validity with P2SH.
    {
        CMutableTransaction invalid_under_p2sh_tx;
        invalid_under_p2sh_tx.nVersion = 1;
        invalid_under_p2sh_tx.vin.resize(1);
        invalid_under_p2sh_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_under_p2sh_tx.vin[0].prevout.n = 0;
        invalid_under_p2sh_tx.vout.resize(1);
        invalid_under_p2sh_tx.vout[0].nValue = 11*CENT;
        invalid_under_p2sh_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;
        std::vector<unsigned char> vchSig2(p2pk_scriptPubKey.begin(), p2pk_scriptPubKey.end());
        invalid_under_p2sh_tx.vin[0].scriptSig << vchSig2;

        ValidateCheckInputsForAllFlags(invalid_under_p2sh_tx, SCRIPT_VERIFY_P2SH, true, view);
    }

    // Test CHECKLOCKTIMEVERIFY
    {
        CMutableTransaction invalid_with_cltv_tx;
        invalid_with_cltv_tx.nVersion = 1;
        invalid_with_cltv_tx.nLockTime = 100;
        invalid_with_cltv_tx.vin.resize(1);
        invalid_with_cltv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_cltv_tx.vin[0].prevout.n = 2;
        invalid_with_cltv_tx.vin[0].nSequence = 0;
        invalid_with_cltv_tx.vout.resize(1);
        invalid_with_cltv_tx.vout[0].nValue = 11*CENT;
        invalid_with_cltv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[2].scriptPubKey, invalid_with_cltv_tx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_CHECK(fundingKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(invalid_with_cltv_tx, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, view);

        // Make it valid, and check again
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        CValidationState state;
        PrecomputedTransactionData txdata(invalid_with_cltv_tx);
        BOOST_CHECK(CheckInputs(invalid_with_cltv_tx, state, view, true, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, true, txdata, nullptr));
    }

    // TEST CHECKSEQUENCEVERIFY
    {
        CMutableTransaction invalid_with_csv_tx;
        invalid_with_csv_tx.nVersion = 2;
        invalid_with_csv_tx.vin.resize(1);
        invalid_with_csv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_csv_tx.vin[0].prevout.n = 3;
        invalid_with_csv_tx.vin[0].nSequence = 100;
        invalid_with_csv_tx.vout.resize(1);
        invalid_with_csv_tx.vout[0].nValue = 11*CENT;
        invalid_with_csv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[3].scriptPubKey, invalid_with_csv_tx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_CHECK(fundingKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(invalid_with_csv_tx, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, view);

        // Make it valid, and check again
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        CValidationState state;
        PrecomputedTransactionData txdata(invalid_with_csv_tx);
        BOOST_CHECK(CheckInputs(invalid_with_csv_tx, state, view, true, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, true, txdata, nullptr));
    }

    // TODO: add tests for remaining script flags

    // Test that passing CheckInputs with a valid witness doesn't imply success
    // for the same tx with a different witness.
    {
        CMutableTransaction valid_with_witness_tx;
        valid_with_witness_tx.nVersion = 1;
        valid_with_witness_tx.vin.resize(1);
        valid_with_witness_tx.vin[0].prevout.hash = spend_tx.GetHash();
        valid_with_witness_tx.vin[0].prevout.n = 1;
        valid_with_witness_tx.vout.resize(1);
        valid_with_witness_tx.vout[0].nValue = 11*CENT;
        valid_with_witness_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        SignatureData sigdata;
        ProduceSignature(MutableTransactionSignatureCreator(&keystore, &valid_with_witness_tx, 0, 11*CENT, SIGHASH_ALL), spend_tx.vout[1].scriptPubKey, sigdata);
        UpdateTransaction(valid_with_witness_tx, 0, sigdata);

        // This should be valid under all script flags.
        ValidateCheckInputsForAllFlags(valid_with_witness_tx, 0, true, view);

        // Remove the witness, and check that it is now invalid.
        valid_with_witness_tx.vin[0].scriptWitness.SetNull();
        ValidateCheckInputsForAllFlags(valid_with_witness_tx, SCRIPT_VERIFY_WITNESS, true, view);
    }

    {
        // Test a transaction with multiple inputs.
        CMutableTransaction tx;

        tx.nVersion = 1;
        tx.vin.resize(2);
        tx.vin[0].prevout.hash = spend_tx.GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[1].prevout.hash = spend_tx.GetHash();
        tx.vin[1].prevout.n = 1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 22*CENT;
        tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        for (int i=0; i<2; ++i) {
            SignatureData sigdata;
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &tx, i, 11*CENT, SIGHASH_ALL), spend_tx.vout[i].scriptPubKey, sigdata);
            UpdateTransaction(tx, i, sigdata);
        }

        // This should be valid under all script flags
        ValidateCheckInputsForAllFlags(tx, 0, true, view);

        // Check that if the second input is invalid, but the first input is
        // valid, the transaction is not cached.
        // Invalidate vin[1]
        tx.vin[1].scriptWitness.SetNull();

        CValidationState state;
        PrecomputedTransactionData txdata(tx);
        // This transaction is now invalid under segwit, because of the second input.
        BOOST_CHECK(!CheckInputs(tx, state, view, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, nullptr));

        std::vector<CScriptCheck> scriptchecks;
        // Make sure this transaction was not cached (ie because the first
        // input was valid)
        BOOST_CHECK(CheckInputs(tx, state, view, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, &scriptchecks));
        // Should get 2 script checks back -- caching is on a whole-transaction basis.
        BOOST_CHECK_EQUAL(scriptchecks.size(), 2);
    }
}

BOOST_AUTO_TEST_SUITE_END()
