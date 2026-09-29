// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_SIDECHAIN_TEST_UTIL_H
#define BITCOIN_TEST_SIDECHAIN_TEST_UTIL_H

// Block-connect helpers shared by sidechain_tests.cpp and pegbind_tests.cpp
// (moved out of sidechain_tests.cpp unchanged, v0.2.17 P3 step 1).

#include "arith_uint256.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "miner.h"
#include "sidechain.h"
#include "txdb.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"
#include "validationinterface.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <memory>
#include <string>
#include <vector>

extern bool g_fMainchainMainFamily; // base58.cpp (A9)

namespace sidechain_test {

/** The L1 family matching this fixture's (regtest) params: -regtest on, so
 *  mainchain P2PKH uses prefix 111, and carriers use the regtest HRP fbkrt. */
struct RegtestFamilyScope {
    std::string strRegtest;
    bool fMain;
    RegtestFamilyScope() : strRegtest(gArgs.GetArg("-regtest", "0")), fMain(g_fMainchainMainFamily)
    {
        gArgs.ForceSetArg("-regtest", "1");
        g_fMainchainMainFamily = false;
    }
    ~RegtestFamilyScope()
    {
        gArgs.ForceSetArg("-regtest", strRegtest);
        g_fMainchainMainFamily = fMain;
    }
};

static const std::string L1_P2PKH_REGTEST = "mfcHP2WMCVLsVZA8yrovmhMgxNFW9r98xw"; // 76a914<01..14>88ac

/** A spendable coin in the chainstate, as a deposit would leave one: this
 *  chain's coinbases pay only fees, so TestChain100Setup has no funded coins. */
inline COutPoint FundCoinForTest(int n, CAmount nValue)
{
    const COutPoint out(ArithToUint256(arith_uint256(0xfb0000 + n)), 0);
    LOCK(cs_main);
    pcoinsTip->AddCoin(out, Coin(CTxOut(nValue, CScript() << OP_TRUE), 1, false, false, false, 0), false);
    return out;
}

/** A withdrawal transaction as CWallet::CreateWithdrawal lays it out: change
 *  (here OP_TRUE, so a child can spend it), the burn, the withdrawal object. */
inline CTransactionRef MakeWithdrawalTx(const COutPoint& in, CAmount nIn, const std::string& strDest,
                                 CAmount nPayout, CAmount nMainchainFee)
{
    const CAmount nTxFee = 20000;
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(in));
    mtx.vout.push_back(CTxOut(nIn - nPayout - nMainchainFee - nTxFee, CScript() << OP_TRUE));
    mtx.vout.push_back(CTxOut(nPayout + nMainchainFee, CScript() << OP_RETURN));
    SidechainWithdrawal wt;
    wt.nSidechain = THIS_SIDECHAIN;
    wt.strDestination = strDest;
    wt.strRefundDestination = "";
    wt.amount = nPayout + nMainchainFee;
    wt.mainchainFee = nMainchainFee;
    wt.hashBlindTx = CTransaction(mtx).GetHash();
    mtx.vout.push_back(CTxOut(0, wt.GetScript()));
    return MakeTransactionRef(std::move(mtx));
}

/** What the node reports through CMainSignals::BlockChecked, per block hash
 *  ("" = valid). ConnectTip calls it synchronously with ConnectBlock's verdict. */
struct BlockCheckedRecorder : public CValidationInterface {
    std::map<uint256, std::string> mapReason;
    BlockCheckedRecorder() { RegisterValidationInterface(this); }
    ~BlockCheckedRecorder()
    {
        UnregisterValidationInterface(this);
        SyncWithValidationInterfaceQueue(); // no in-flight callback outlives this object
    }
    std::string Reason(const uint256& hash) const
    {
        const auto it = mapReason.find(hash);
        return it == mapReason.end() ? "(never checked)" : it->second;
    }
protected:
    void BlockChecked(const CBlock& block, const CValidationState& state) override
    {
        mapReason[block.GetHash()] = state.IsValid() ? "" : state.GetRejectReason();
    }
};

/** In-memory house/bill/pool/asset DBs for one test. A real connect reads
 *  their best-block markers and flushes them; TestingSetup, under which no
 *  block ever connects, does not create them. */
struct SideDBScope {
    std::unique_ptr<BitAssetDB> asset;
    std::unique_ptr<BillDB> bill;
    std::unique_ptr<HouseDB> house;
    std::unique_ptr<PoolDB> pool;
    SideDBScope()
    {
        asset.swap(passettree);
        bill.swap(pbilltree);
        house.swap(phousetree);
        pool.swap(ppooltree);
        passettree.reset(new BitAssetDB(1 << 20, true /* fMemory */));
        pbilltree.reset(new BillDB(1 << 20, true /* fMemory */));
        phousetree.reset(new HouseDB(1 << 20, true /* fMemory */));
        ppooltree.reset(new PoolDB(1 << 20, true /* fMemory */));
    }
    ~SideDBScope()
    {
        passettree.swap(asset);
        pbilltree.swap(bill);
        phousetree.swap(house);
        ppooltree.swap(pool);
    }
};

/** The miner's own block on the current tip (coinbase with the height,
 *  prev-block and version commits, from GenerateBMMBlock), with `tx`
 *  appended by hand - past the template's skip of unpayable withdrawals. */
inline std::shared_ptr<const CBlock> BlockWithTx(const CTransactionRef& tx, const CScript& scriptCoinbase)
{
    CBlock block;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
        std::vector<CMutableTransaction>(), uint256(), scriptCoinbase), strError);
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U); // empty mempool: coinbase only
    {
        // The earliest valid timestamp: a current one would latch
        // IsInitialBlockDownload() to false for every later test in the process
        LOCK(cs_main);
        block.nTime = chainActive.Tip()->GetMedianTimePast() + 1;
    }
    block.vtx.push_back(tx);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return std::make_shared<const CBlock>(block);
}

/** Feeds a block to the node's own entry point, ProcessNewBlock -> AcceptBlock
 *  -> ActivateBestChain -> ConnectTip -> ConnectBlock(fJustCheck=false): the
 *  path every mined or relayed block takes. Returns ProcessNewBlock's result
 *  (true = stored and handed to ActivateBestChain; ConnectBlock's verdict
 *  arrives through BlockChecked).
 *
 *  There is no mainchain here. CheckBlock and AcceptBlockHeader open an L1
 *  RPC (CheckMainchainConnection) and verify BMM for every block except the
 *  genesis, and ConnectTip always passes fCheckBMM, which is why no block
 *  ever connects in this fixture (TestChain100Setup's tip stays at genesis).
 *  Both of those read the genesis hash from the global Params(), while
 *  ConnectBlock's genesis shortcut reads the chainparams the node is handed.
 *  So for this one call the global names THIS block as the genesis, which
 *  skips its L1, BMM and header checks and nothing else, and the node is
 *  handed an unmodified copy of the params (genesis intact, the test's H), so
 *  ConnectBlock runs in full: every tx, the sidechain-object loop with the
 *  poison-row guard, and the index writes. */
inline bool ProcessBlockWithoutMainchain(const std::shared_ptr<const CBlock>& pblock)
{
    const CChainParams paramsConnect(Params());
    struct GenesisScope {
        Consensus::Params& consensus;
        const uint256 hashSaved;
        explicit GenesisScope(const uint256& hash)
            : consensus(const_cast<Consensus::Params&>(Params().GetConsensus())),
              hashSaved(consensus.hashGenesisBlock)
        {
            consensus.hashGenesisBlock = hash;
        }
        ~GenesisScope() { consensus.hashGenesisBlock = hashSaved; }
    } genesis(pblock->GetHash());
    return ProcessNewBlock(paramsConnect, pblock, true /* fForceProcessing */, nullptr, true /* fUnitTest */);
}

inline const CBlockIndex* TipForTest()
{
    LOCK(cs_main);
    return chainActive.Tip();
}

inline bool BlockFailedForTest(const uint256& hash)
{
    LOCK(cs_main);
    const BlockMap::const_iterator it = mapBlockIndex.find(hash);
    return it != mapBlockIndex.end() && (it->second->nStatus & BLOCK_FAILED_VALID);
}

inline std::vector<SidechainWithdrawal> WithdrawalRows()
{
    return psidechaintree->GetWithdrawals(THIS_SIDECHAIN);
}

} // namespace sidechain_test

#endif // BITCOIN_TEST_SIDECHAIN_TEST_UTIL_H
