// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <policy/policy.h>
#include <test/test_bitcoin.h>
#include <txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

// v0.2.19 (CVE-2025-46598): mempool acceptance caps the legacy signature
// operations a transaction runs (MAX_TX_LEGACY_SIGOPS, Core 30's policy) and its
// weight, whatever its version: this chain leaves standardness off.

BOOST_FIXTURE_TEST_SUITE(legacy_sigops_tests, TestChain100Setup)

// A coin locked by n bare OP_CHECKSIGs, injected into the UTXO set, and a tx that
// spends it (its scriptSig does not matter: the cap is checked before scripts run).
static CMutableTransaction SpendManySigOps(int i, unsigned int n)
{
    CScript script;
    for (unsigned int k = 0; k < n; k++)
        script << OP_CHECKSIG;
    const COutPoint outpoint(uint256S(strprintf("%064x", 0x2000 + i)), 0);
    {
        LOCK(cs_main);
        pcoinsTip->AddCoin(outpoint, Coin(CTxOut(COIN, script), 1, false, false, false, uint256()), false);
    }
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = outpoint;
    tx.vout.resize(1);
    tx.vout[0].nValue = COIN - 100000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

static std::string Accept(const CMutableTransaction& mtx)
{
    LOCK(cs_main);
    CValidationState state;
    AcceptToMemoryPool(mempool, state, MakeTransactionRef(mtx), nullptr, nullptr, true /* bypass_limits */, 0);
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(legacy_sigops_counted_in_spent_scripts)
{
    const CMutableTransaction tx = SpendManySigOps(0, 100);
    LOCK(cs_main);
    CCoinsViewCache view(pcoinsTip.get());
    BOOST_CHECK_EQUAL(GetSpentLegacySigOps(CTransaction(tx), view), 100U);
}

BOOST_AUTO_TEST_CASE(legacy_sigops_cap_in_mempool_acceptance)
{
    fRequireStandard = false;   // as on this chain's mainnet (the unit default is upstream's true)
    BOOST_CHECK_EQUAL(Accept(SpendManySigOps(1, MAX_TX_LEGACY_SIGOPS + 1)), "bad-txns-nonstandard-too-many-sigops");
    // At the cap the transaction passes this check and fails later, at its script
    const std::string strAtCap = Accept(SpendManySigOps(2, MAX_TX_LEGACY_SIGOPS));
    BOOST_CHECK(!strAtCap.empty() && strAtCap != "bad-txns-nonstandard-too-many-sigops");
    fRequireStandard = true;
}

BOOST_AUTO_TEST_SUITE_END()
