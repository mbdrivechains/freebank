// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// v0.2.18: remote crash / DoS fixes ported from upstream (SECURITY_RC_LIST items 1-2).
//  - CVE-2024-35202 (blocktxn refill assert): a second FillBlock on the same
//    PartiallyDownloadedBlock must return READ_STATUS_INVALID, not assert.
//    CBlockHeader::SetNull must clear hashWithdrawalBundle so IsNull() holds.
//  - getdata unknown inv type: an item ProcessGetData does not serve must be
//    dropped, so the peer's getdata queue drains (upstream v0.20, PR #18808).
// (upstream blockencodings_tests.cpp stays excluded: it sets CBlock::nBits.)

#include <blockencodings.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <l1client.h>
#include <net.h>
#include <net_processing.h>
#include <protocol.h>
#include <random.h>
#include <txmempool.h>

#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

namespace {

// Answers GetBlockCount so CheckBlock's CheckMainchainConnection() passes
// (FillBlock calls CheckBlock); everything else says no.
struct BlockCountL1Client : public L1Client {
    BlockCountL1Client() { SetL1ClientForTest(this); }
    ~BlockCountL1Client() { SetL1ClientForTest(nullptr); }
    bool GetBlockCount(int& nBlocks) override { nBlocks = 100; return true; }
    bool GetBlockHash(int, uint256&) override { return false; }
    bool GetAncestorHashes(const uint256&, int, uint32_t, std::vector<uint256>&) override { return false; }
    bool BroadcastWithdrawalBundle(const std::string&) override { return false; }
    std::vector<SidechainDeposit> UpdateDeposits(const uint256&, const uint32_t) override { return {}; }
    bool VerifyDeposit(const uint256&, const uint256&, const int) override { return false; }
    bool VerifyBMM(const uint256&, const uint256&, uint256&, uint32_t&) override { return false; }
    uint256 SendBMMRequest(const uint256&, const uint256&, int, CAmount, bool& fNotSent) override { fNotSent = true; return uint256(); }
    bool IsBehindItsNode(std::string&) override { return false; }
    bool GetCTIP(std::pair<uint256, uint32_t>&) override { return false; }
    bool GetAverageFees(int, int, CAmount&) override { return false; }
    bool GetWorkScore(const uint256&, int&) override { return false; }
    bool ListWithdrawalBundleStatus(std::vector<uint256>&) override { return false; }
    bool HaveSpentWithdrawalBundle(const uint256&) override { return false; }
    bool HaveFailedWithdrawalBundle(const uint256&) override { return false; }
};

CBlock BuildBlock(bool fWithdrawalBundle)
{
    CBlock block;
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(10);
    tx.vout.resize(1);
    tx.vout[0].nValue = 42;
    block.vtx.push_back(MakeTransactionRef(tx)); // coinbase-shaped (null prevout)

    for (int i = 0; i < 2; i++) {
        tx.vin[0].prevout.hash = InsecureRand256();
        tx.vin[0].prevout.n = 0;
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    block.nVersion = 42;
    block.hashPrevBlock = InsecureRand256();
    block.hashMainchainBlock = InsecureRand256(); // non-null: InitData refuses a null header
    if (fWithdrawalBundle)
        block.hashWithdrawalBundle = InsecureRand256();
    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);
    return block;
}

// cmpctblock, blocktxn with the wrong transactions (merkle mismatch), then a
// second blocktxn: the CVE-2024-35202 sequence at the PartiallyDownloadedBlock level.
void CheckRefillAfterFailed(bool fWithdrawalBundle)
{
    BlockCountL1Client l1;
    CTxMemPool pool;
    CBlock block = BuildBlock(fWithdrawalBundle);
    CBlockHeaderAndShortTxIDs cmpct(block, true);

    PartiallyDownloadedBlock partialBlock(&pool);
    std::vector<std::pair<uint256, CTransactionRef>> extra_txn;
    BOOST_REQUIRE(partialBlock.InitData(cmpct, extra_txn) == READ_STATUS_OK);
    BOOST_REQUIRE(partialBlock.IsTxAvailable(0));
    BOOST_REQUIRE(!partialBlock.IsTxAvailable(1));
    BOOST_REQUIRE(!partialBlock.IsTxAvailable(2));

    // Swapped order: right count, wrong merkle root => possible short-id collision
    CBlock filled;
    BOOST_CHECK(partialBlock.FillBlock(filled, {block.vtx[2], block.vtx[1]}) == READ_STATUS_FAILED);

    // The second blocktxn used to hit assert(!header.IsNull()) and abort the node
    CBlock again;
    BOOST_CHECK(partialBlock.FillBlock(again, {block.vtx[1], block.vtx[2]}) == READ_STATUS_INVALID);
    BOOST_CHECK(partialBlock.FillBlock(again, {}) == READ_STATUS_INVALID);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2p_dos_fixes_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(header_setnull_clears_withdrawal_bundle)
{
    CBlockHeader header;
    BOOST_CHECK(header.IsNull());
    header.hashWithdrawalBundle = InsecureRand256();
    BOOST_CHECK(!header.IsNull());
    header.SetNull();
    BOOST_CHECK(header.hashWithdrawalBundle.IsNull());
    BOOST_CHECK(header.IsNull());

    CBlock block = BuildBlock(true);
    const uint256 hash = block.GetHash();
    CBlock copy(block.GetBlockHeader()); // CBlock(header) calls SetNull first, then copies every field
    BOOST_CHECK(copy.GetHash() == hash);
    BOOST_CHECK(copy.hashWithdrawalBundle == block.hashWithdrawalBundle);
    block.SetNull();
    BOOST_CHECK(block.IsNull());
}

BOOST_AUTO_TEST_CASE(blocktxn_refill_after_failed_is_invalid)
{
    CheckRefillAfterFailed(/*fWithdrawalBundle=*/false);
    CheckRefillAfterFailed(/*fWithdrawalBundle=*/true);
}

BOOST_AUTO_TEST_CASE(fillblock_success_then_refill_is_invalid)
{
    BlockCountL1Client l1;
    CTxMemPool pool;
    CBlock block = BuildBlock(false);
    CBlockHeaderAndShortTxIDs cmpct(block, true);
    PartiallyDownloadedBlock partialBlock(&pool);
    std::vector<std::pair<uint256, CTransactionRef>> extra_txn;
    BOOST_REQUIRE(partialBlock.InitData(cmpct, extra_txn) == READ_STATUS_OK);
    CBlock filled;
    const ReadStatus status = partialBlock.FillBlock(filled, {block.vtx[1], block.vtx[2]});
    // CheckBlock may reject the toy block for non-merkle reasons; it must not be a merkle failure
    BOOST_CHECK(status == READ_STATUS_OK || status == READ_STATUS_CHECKBLOCK_FAILED);
    BOOST_CHECK(filled.GetHash() == block.GetHash());
    CBlock again;
    BOOST_CHECK(partialBlock.FillBlock(again, {block.vtx[1], block.vtx[2]}) == READ_STATUS_INVALID);
}

BOOST_AUTO_TEST_CASE(getdata_unknown_types_drain)
{
    CAddress addr(CService(CNetAddr(), Params().GetDefaultPort()), NODE_NONE);
    CNode node(0, ServiceFlags(NODE_NETWORK | NODE_WITNESS), 0, INVALID_SOCKET, addr, 0, 0, CAddress(), "", /*fInboundIn=*/true);
    node.SetSendVersion(PROTOCOL_VERSION);
    peerLogic->InitializeNode(&node);
    node.nVersion = PROTOCOL_VERSION;
    node.fSuccessfullyConnected = true;

    // Unknown hashes, so the block item is looked up and not served (nothing sent)
    const int types[] = {UNDEFINED, 5, MSG_FILTERED_WITNESS_BLOCK, MSG_BLOCK, 0x7fffffff, MSG_CMPCT_BLOCK, UNDEFINED};
    for (int type : types)
        node.vRecvGetData.push_back(CInv(type, InsecureRand256()));

    std::atomic<bool> interrupt(false);
    int nCalls = 0;
    while (!node.vRecvGetData.empty() && nCalls < 100) {
        peerLogic->ProcessMessages(&node, interrupt);
        nCalls++;
    }
    // One non-tx item per call: the queue drains in exactly as many calls as it had items
    BOOST_CHECK(node.vRecvGetData.empty());
    BOOST_CHECK_EQUAL(nCalls, (int)(sizeof(types) / sizeof(types[0])));
    BOOST_CHECK(!node.fDisconnect);

    bool fUpdateConnectionTime = false;
    peerLogic->FinalizeNode(node.GetId(), fUpdateConnectionTime);
}

BOOST_AUTO_TEST_SUITE_END()
