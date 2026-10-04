// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <key.h>
#include <script/interpreter.h>
#include <test/test_bitcoin.h>
#include <txmempool.h>
#include <util.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

// v0.2.19 (C6 demand-tag-zero-pool-brick): a pooled transaction the block cannot
// hold no longer stops block production. CreateNewBlock finds it, drops it from
// the mempool with its descendants and builds the template again; after
// MAX_TEMPLATE_EVICTIONS drops it builds the block from no mempool transactions.
// The block-invalid transactions here enter the pool past acceptance
// (addUnchecked), as only a mempool / ConnectBlock mismatch could put them there.

BOOST_FIXTURE_TEST_SUITE(template_evict_tests, TestChain100Setup)

static CScript CoinbaseScript(const CKey& key)
{
    return CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
}

// A valid spend of a coin injected into the UTXO set (this suite's chain has no
// spendable coinbase: FreeBank has no subsidy), paying FEE.
static const CAmount FEE = 10000;
static CMutableTransaction SpendInjectedCoin(int i, const CKey& key)
{
    const CScript script = CoinbaseScript(key);
    const COutPoint outpoint(uint256S(strprintf("%064x", 0x1000 + i)), 0);
    {
        LOCK(cs_main);
        pcoinsTip->AddCoin(outpoint, Coin(CTxOut(COIN, script), 1, false, false, false, uint256()), false);
    }
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = outpoint;
    tx.vout.resize(1);
    tx.vout[0].nValue = COIN - FEE;
    tx.vout[0].scriptPubKey = script;
    std::vector<unsigned char> vchSig;
    const uint256 hash = SignatureHash(script, CTransaction(tx), 0, SIGHASH_ALL, COIN, SIGVERSION_BASE);
    BOOST_REQUIRE(key.Sign(hash, vchSig));
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    tx.vin[0].scriptSig = CScript() << vchSig;
    return tx;
}

// No block can hold it: it spends an output that does not exist.
static CMutableTransaction SpendsNothing(int i)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S(strprintf("%064x", i + 1)), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

static void Pool(const CMutableTransaction& tx)
{
    LOCK2(cs_main, mempool.cs);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(tx.GetHash(), entry.Fee(FEE).Time(GetTime()).FromTx(tx));
}

static bool InBlock(const CBlock& block, const uint256& txid)
{
    for (const CTransactionRef& tx : block.vtx)
        if (tx->GetHash() == txid) return true;
    return false;
}

static CBlock Produce(const CScript& script)
{
    CBlock block;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
        std::vector<CMutableTransaction>(), uint256(), script), strError);
    return block;
}

BOOST_AUTO_TEST_CASE(template_drops_a_block_invalid_pooled_tx)
{
    const CMutableTransaction good = SpendInjectedCoin(0, coinbaseKey);
    const CMutableTransaction bad = SpendsNothing(0);
    Pool(bad);
    Pool(good);

    const CBlock block = Produce(CoinbaseScript(coinbaseKey));
    BOOST_CHECK(InBlock(block, good.GetHash()));
    BOOST_CHECK(!InBlock(block, bad.GetHash()));
    BOOST_CHECK(mempool.exists(good.GetHash()));
    BOOST_CHECK(!mempool.exists(bad.GetHash()));

    mempool.clear();
}

BOOST_AUTO_TEST_CASE(template_falls_back_to_no_mempool_txs)
{
    const CMutableTransaction good = SpendInjectedCoin(1, coinbaseKey);
    const int nBad = MAX_TEMPLATE_EVICTIONS + 2;
    for (int i = 0; i < nBad; i++)
        Pool(SpendsNothing(i));
    Pool(good);

    // MAX_TEMPLATE_EVICTIONS drops, then this block from no mempool transactions: production goes on.
    const CBlock first = Produce(CoinbaseScript(coinbaseKey));
    BOOST_CHECK_EQUAL(first.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(mempool.size(), 3U);   // 2 bad left + good
    // The next template drops the rest and carries the valid transaction.
    const CBlock second = Produce(CoinbaseScript(coinbaseKey));
    BOOST_CHECK(InBlock(second, good.GetHash()));
    BOOST_CHECK_EQUAL(second.vtx.size(), 2U);
    BOOST_CHECK_EQUAL(mempool.size(), 1U);

    mempool.clear();
}

BOOST_AUTO_TEST_SUITE_END()
