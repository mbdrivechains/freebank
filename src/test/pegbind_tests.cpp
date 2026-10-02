// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// v0.2.17 validation rules (docs-local/SOFTFORK_V0216_DESIGN_DRAFT.md, revision
// 4, section 6.1): block-level tests of the peg rules. Every block here is the
// miner's own template with its coinbase or transactions edited by hand (what a
// modified producer can send), fed through ProcessNewBlock -> ConnectTip ->
// ConnectBlock like any relayed block (sidechain_test::ProcessBlockWithoutMainchain).
//
// The L1 answers come from seams, never from a mainchain: TestL1Oracle
// (SetL1OracleForTest) answers the L1Oracle questions YES/NO/UNKNOWN as each
// case needs (the peg events of L1 blocks, BMM commitments; L1ListsDeposit
// puts a deposit on the enforcer's list), FakeL1Client (SetL1ClientForTest)
// plays the L1 client, and MainCacheScope sets our list of L1 blocks.
//
// Every case runs in both L1 layouts: LEGACY (default regtest: `b4 82`
// treasury, [OP_RETURN dest][burn]) and CUSF (-cusfbundleformat=1: the
// `<op> 01 82 51` treasury, [burn][OP_RETURN address]).

#include "arith_uint256.h"
#include "base58.h"
#include "bmmcache.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "key.h"
#include "l1client.h"
#include "miner.h"
#include "script/standard.h"
#include "sidechain.h"
#include "sidechainclient.h"
#include "txdb.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "test/test_bitcoin.h"
#include "test/sidechain_test_util.h"

#include <boost/test/unit_test.hpp>

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace sidechain_test;

namespace {

enum class Layout { LEGACY, CUSF };

const char* LayoutName(Layout layout) { return layout == Layout::CUSF ? "CUSF" : "LEGACY"; }

/** Forces the L1 layout for one test and restores the default however the
 *  test exits. -cusfbundleformat is honoured on regtest only, which this
 *  fixture is. */
struct LayoutScope {
    explicit LayoutScope(Layout layout)
    {
        gArgs.ForceSetArg("-cusfbundleformat", layout == Layout::CUSF ? "1" : "0");
        BOOST_REQUIRE_EQUAL(UseCUSFBundleFormat(), layout == Layout::CUSF);
    }
    ~LayoutScope() { gArgs.ForceSetArg("-cusfbundleformat", "0"); }
};

/** The template builder bundles one withdrawal (the default is 10). */
struct MinWithdrawalScope {
    MinWithdrawalScope() { gArgs.ForceSetArg("-minwithdrawal", "1"); }
    ~MinWithdrawalScope() { gArgs.ForceSetArg("-minwithdrawal", std::to_string(DEFAULT_MIN_WITHDRAWAL_CREATE_BUNDLE)); }
};

/** The L1Oracle seam: every answer is UNKNOWN unless the test set it. Installs
 *  itself for its lifetime. */
struct TestL1Oracle : public L1Oracle {
    std::map<std::pair<uint256, uint256>, std::pair<L1Answer, L1PegEvents>> mapWindowEvents;
    // Any window not in mapWindowEvents: answered YES with eventsAnyWindow
    // once fAnyWindow is set (test blocks name no L1 block), else UNKNOWN
    bool fAnyWindow = false;
    L1PegEvents eventsAnyWindow;
    int nWindowCalls = 0;
    std::map<std::pair<uint256, uint256>, L1Answer> mapBmm;

    TestL1Oracle() { SetL1OracleForTest(this); }
    ~TestL1Oracle() { SetL1OracleForTest(nullptr); }

    L1Answer BmmCommitment(const uint256& hashMainBlock, const uint256& hashBMM) override
    {
        const auto it = mapBmm.find(std::make_pair(hashMainBlock, hashBMM));
        return it == mapBmm.end() ? L1Answer::UNKNOWN : it->second;
    }
    L1Answer EventsInWindow(const uint256& hashStart, const uint256& hashEnd, L1PegEvents& events) override
    {
        nWindowCalls++;
        const auto it = mapWindowEvents.find(std::make_pair(hashStart, hashEnd));
        if (it == mapWindowEvents.end()) {
            if (!fAnyWindow)
                return L1Answer::UNKNOWN;
            events = eventsAnyWindow;
            return L1Answer::YES;
        }
        events = it->second.second;
        return it->second.first;
    }
};

/** This slot's treasury (CTIP) script in each layout. */
CScript TreasuryScript(Layout layout)
{
    if (layout == Layout::CUSF) // OP_NOP5 PUSH1 0x82 OP_TRUE (BIP300, alphanet, the regtest bench)
        return CScript() << OP_NOP5 << std::vector<unsigned char>{(unsigned char)THIS_SIDECHAIN} << OP_TRUE;
    CScript script; // BitcoinX: OP_DRIVECHAIN <slot byte>
    script.push_back(OP_NOP5);
    script.push_back((unsigned char)THIS_SIDECHAIN);
    return script;
}

CScript AddressScript(const std::string& strAddress)
{
    return CScript() << OP_RETURN << std::vector<unsigned char>(strAddress.begin(), strAddress.end());
}

/** An L1 deposit (M5): spends `vPrevout` (the previous CTIP first, if any)
 *  and leaves `nTreasury` in the treasury. Returns the dtx and its burn index. */
CMutableTransaction MakeDepositTx(Layout layout, const std::vector<COutPoint>& vPrevout, CAmount nTreasury,
                                  const std::string& strAddress, uint32_t& nBurnIndex)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    for (const COutPoint& out : vPrevout)
        mtx.vin.push_back(CTxIn(out));
    if (layout == Layout::CUSF) {
        mtx.vout.push_back(CTxOut(nTreasury, TreasuryScript(layout)));
        mtx.vout.push_back(CTxOut(0, AddressScript(strAddress)));
        nBurnIndex = 0;
    } else {
        mtx.vout.push_back(CTxOut(0, AddressScript(strAddress)));
        mtx.vout.push_back(CTxOut(nTreasury, TreasuryScript(layout)));
        nBurnIndex = 1;
    }
    return mtx;
}

/** The coinbase record of an L1 deposit (list it on the L1 with L1ListsDeposit). */
SidechainDeposit MakeDepositRecord(const CMutableTransaction& dtx, uint32_t nBurnIndex, const std::string& strDest,
                                   CAmount amt, const uint256& hashMainBlock, uint32_t nTx = 1)
{
    SidechainDeposit d;
    d.nSidechain = THIS_SIDECHAIN;
    d.strDest = strDest;
    d.amtUserPayout = amt;
    d.dtx = dtx;
    d.nBurnIndex = nBurnIndex;
    d.nTx = nTx;
    d.hashMainchainBlock = hashMainBlock;
    return d;
}

/** Appends a deposit record to a coinbase the way the builder does: the
 *  payout output (if one is owed) and the fee to vout[0], then the object. */
void AddDepositToCoinbase(CMutableTransaction& cb, const SidechainDeposit& d)
{
    CTxOut out;
    if (GetDepositPayoutOutput(d, out)) {
        cb.vout[0].nValue += SIDECHAIN_DEPOSIT_FEE;
        cb.vout.push_back(out);
    }
    cb.vout.push_back(CTxOut(0, d.GetScript()));
}

struct MainCacheScope {
    MainCacheScope(const std::deque<uint256>& deq) { bmmCache.ReplaceMainBlockCache(deq); }
    ~MainCacheScope() { bmmCache.ResetMainBlockCache(); }
};

/** v0.2.17 A1: the enforcer lists d as a deposit of its L1 block (adding
 *  nAdded to the treasury, the treasury's change number nSeq). */
void L1ListsDeposit(TestL1Oracle& oracle, const SidechainDeposit& d, CAmount nAdded, uint64_t nSeq,
                    const std::string& strAddress = "")
{
    auto& entry = oracle.mapWindowEvents[std::make_pair(d.hashMainchainBlock, d.hashMainchainBlock)];
    entry.first = L1Answer::YES;
    L1DepositEvent ev;
    ev.hashMainBlock = d.hashMainchainBlock;
    ev.outpoint = COutPoint(d.dtx.GetHash(), d.nBurnIndex);
    ev.nSequence = nSeq;
    ev.nValue = nAdded;
    const std::string& strDest = strAddress.empty() ? d.strDest : strAddress;
    ev.vchAddress.assign(strDest.begin(), strDest.end());
    entry.second.vDeposit.push_back(ev);
}

/** The block, with its own L1 block (its BMM) set to hashMain. */
std::shared_ptr<const CBlock> OnL1(const std::shared_ptr<const CBlock>& pblock, const uint256& hashMain)
{
    CBlock block = *pblock;
    block.hashMainchainBlock = hashMain;
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return std::make_shared<const CBlock>(block);
}

/** A spendable FreeBank key and its address. */
struct TestKey {
    CKey key;
    std::string strAddress;
    CScript script;
    TestKey()
    {
        key.MakeNewKey(true);
        strAddress = EncodeDestination(key.GetPubKey().GetID());
        script = GetScriptForDestination(key.GetPubKey().GetID());
    }
};

/** One chain under test: the side DBs, the verdict recorder, the oracle, the
 *  L1 family and the layout, all restored when it goes out of scope. */
struct PegChain {
    const Layout layout;
    LayoutScope layoutScope;
    RegtestFamilyScope family;
    MinWithdrawalScope minWithdrawal;
    SideDBScope sideDBs;
    BlockCheckedRecorder checked;
    TestL1Oracle oracle;
    const CScript scriptCoinbase;
    int nNextCoin = 0;
    int nNextCoinbaseTag = 0;

    PegChain(Layout layoutIn, const CScript& scriptCoinbaseIn)
        : layout(layoutIn), layoutScope(layoutIn), scriptCoinbase(scriptCoinbaseIn)
    {
        BOOST_REQUIRE(gArgs.GetArg("-rpcuser", "").empty() && gArgs.GetArg("-rpcpassword", "").empty());
    }

    /** The miner's template on the tip (its own bundle, commits and header),
     *  plus `vtx`, with `mutate` applied to the coinbase. fDistinct tags the
     *  coinbase so a sibling at the same height gets another hash. */
    std::shared_ptr<const CBlock> Block(const std::vector<CTransactionRef>& vtx = {},
                                        const std::function<void(CMutableTransaction&)>& mutate = nullptr,
                                        bool fDistinct = false)
    {
        CBlock block;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
            std::vector<CMutableTransaction>(), uint256(), scriptCoinbase), strError);
        {
            // The earliest valid timestamp (see sidechain_test::BlockWithTx)
            LOCK(cs_main);
            block.nTime = chainActive.Tip()->GetMedianTimePast() + 1;
        }
        for (const CTransactionRef& tx : vtx)
            block.vtx.push_back(tx);
        if (mutate || fDistinct) {
            CMutableTransaction cb(*block.vtx[0]);
            if (fDistinct)
                cb.vout.push_back(CTxOut(0, CScript() << OP_RETURN << ++nNextCoinbaseTag));
            if (mutate)
                mutate(cb);
            block.vtx[0] = MakeTransactionRef(std::move(cb));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        return std::make_shared<const CBlock>(block);
    }

    /** Re-seal a block whose header or coinbase a test edited. */
    static std::shared_ptr<const CBlock> Reseal(CBlock block)
    {
        block.hashMerkleRoot = BlockMerkleRoot(block);
        return std::make_shared<const CBlock>(block);
    }

    /** Feed a block to the node; returns ConnectBlock's verdict ("" = connected). */
    std::string Process(const std::shared_ptr<const CBlock>& pblock)
    {
        ProcessBlockWithoutMainchain(pblock);
        return checked.Reason(pblock->GetHash());
    }

    /** Feed a block that must connect. */
    void Connect(const std::shared_ptr<const CBlock>& pblock, const std::string& strLabel)
    {
        const std::string strReason = Process(pblock);
        BOOST_REQUIRE_MESSAGE(strReason.empty(), LayoutName(layout) << " " << strLabel << ": rejected: " << strReason);
        BOOST_REQUIRE_MESSAGE(TipForTest()->GetBlockHash() == pblock->GetHash(),
            LayoutName(layout) << " " << strLabel << ": did not become the tip");
    }

    /** Feed a block that must be rejected with strReason (and marked failed). */
    void Reject(const std::shared_ptr<const CBlock>& pblock, const std::string& strReason, const std::string& strLabel)
    {
        const CBlockIndex* const pindexTip = TipForTest();
        const std::string strGot = Process(pblock);
        BOOST_CHECK_MESSAGE(strGot == strReason, LayoutName(layout) << " " << strLabel << ": reason '" << strGot
            << "', expected '" << strReason << "'");
        BOOST_CHECK_MESSAGE(TipForTest() == pindexTip, LayoutName(layout) << " " << strLabel << ": tip moved");
        BOOST_CHECK_MESSAGE(BlockFailedForTest(pblock->GetHash()), LayoutName(layout) << " " << strLabel << ": not marked failed");
    }

    COutPoint Coin(CAmount nValue) { return FundCoinForTest(0x5000 + nNextCoin++, nValue); }

    /** The L1 records event `status` ('U' submitted, 'F' failed, 'S' paid)
     *  for the bundle whose tx hash is hashBundle, in every window asked. */
    void L1BundleEvent(const uint256& hashBundle, char status)
    {
        SidechainWithdrawalBundle bundle;
        BOOST_REQUIRE(psidechaintree->GetWithdrawalBundle(hashBundle, bundle));
        L1WithdrawalEvent ev;
        ev.m6id = BundleM6id(bundle.tx);
        ev.status = status;
        oracle.eventsAnyWindow.vWithdrawal.push_back(ev);
        oracle.fAnyWindow = true;
    }

    /** A payable withdrawal (to the regtest L1 P2PKH), refundable to `strRefund`. */
    CTransactionRef Withdrawal(CAmount nPayout, const std::string& strRefund = "")
    {
        const CAmount nFee = 5000;
        const COutPoint in = Coin(COIN);
        if (strRefund.empty())
            return MakeWithdrawalTx(in, COIN, L1_P2PKH_REGTEST, nPayout, nFee);
        const CAmount nTxFee = 20000;
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(in));
        mtx.vout.push_back(CTxOut(COIN - nPayout - nFee - nTxFee, CScript() << OP_TRUE));
        mtx.vout.push_back(CTxOut(nPayout + nFee, CScript() << OP_RETURN));
        SidechainWithdrawal wt;
        wt.nSidechain = THIS_SIDECHAIN;
        wt.strDestination = L1_P2PKH_REGTEST;
        wt.strRefundDestination = strRefund;
        wt.amount = nPayout + nFee;
        wt.mainchainFee = nFee;
        wt.hashBlindTx = CTransaction(mtx).GetHash();
        mtx.vout.push_back(CTxOut(0, wt.GetScript()));
        return MakeTransactionRef(std::move(mtx));
    }
};

/** Put exactly this mark in a coinbase, replacing any the builder added. */
void AddMark(CMutableTransaction& cb, const uint256& hashBundle, bool fFailed)
{
    std::vector<CTxOut> vout;
    for (const CTxOut& out : cb.vout) {
        uint256 hash;
        if (!out.scriptPubKey.IsWithdrawalBundleFailCommit(hash) && !out.scriptPubKey.IsWithdrawalBundleSpentCommit(hash))
            vout.push_back(out);
    }
    cb.vout = vout;
    cb.vout.push_back(CTxOut(0, fFailed ? GenerateWithdrawalBundleFailCommit(hashBundle) : GenerateWithdrawalBundleSpentCommit(hashBundle)));
}

/** The withdrawal object a withdrawal tx carries. */
SidechainWithdrawal WithdrawalOf(const CTransactionRef& tx)
{
    for (const CTxOut& out : tx->vout) {
        std::vector<unsigned char> vch;
        if (!out.scriptPubKey.IsSidechainObj(vch))
            continue;
        std::unique_ptr<SidechainObj> obj(ParseSidechainObj(vch));
        if (obj && obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP)
            return *static_cast<const SidechainWithdrawal*>(obj.get());
    }
    BOOST_FAIL("no withdrawal object");
    return SidechainWithdrawal();
}

/** The bundle object in a block's coinbase, if any. */
bool BundleOf(const CBlock& block, SidechainWithdrawalBundle& bundle)
{
    for (const CTxOut& out : block.vtx[0]->vout) {
        std::vector<unsigned char> vch;
        if (!out.scriptPubKey.IsSidechainObj(vch))
            continue;
        std::unique_ptr<SidechainObj> obj(ParseSidechainObj(vch));
        if (obj && obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP) {
            bundle = *static_cast<const SidechainWithdrawalBundle*>(obj.get());
            return true;
        }
    }
    return false;
}

uint256 LastBundleHash()
{
    uint256 hash;
    psidechaintree->GetLastWithdrawalBundleHash(hash);
    return hash;
}

char WithdrawalStatus(const SidechainWithdrawal& wt)
{
    SidechainWithdrawal row;
    BOOST_REQUIRE(psidechaintree->GetWithdrawal(wt.GetID(), row));
    return row.status;
}

/** Reads a whole leveldb key or value as raw bytes. */
struct RawBytes {
    std::vector<unsigned char> v;
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        v.resize(s.size());
        if (!v.empty())
            s.read((char*)v.data(), v.size());
    }
};

/** Every key and value of the sidechain DB, in key order: two dumps are equal
 *  iff the DB is byte-identical. */
std::vector<std::pair<std::vector<unsigned char>, std::vector<unsigned char>>> DumpSidechainDB()
{
    std::vector<std::pair<std::vector<unsigned char>, std::vector<unsigned char>>> vDump;
    std::unique_ptr<CDBIterator> it(psidechaintree->NewIterator());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        RawBytes key, value;
        BOOST_REQUIRE(it->GetKey(key));
        BOOST_REQUIRE(it->GetValue(value));
        vDump.emplace_back(key.v, value.v);
    }
    return vDump;
}

/** A refund request for `wt`, signed by its refund key, and the coinbase
 *  output that pays it. */
CTransactionRef RefundRequestTx(PegChain& chain, const SidechainWithdrawal& wt, const CKey& keyRefund, CTxOut& payout)
{
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyRefund.SignCompact(GetWithdrawalRefundMessageHash(wt.GetID()), vchSig));
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(chain.Coin(COIN)));
    mtx.vout.push_back(CTxOut(COIN - 20000, CScript() << OP_TRUE));
    mtx.vout.push_back(CTxOut(0, GenerateWithdrawalRefundRequest(wt.GetID(), vchSig)));
    payout = CTxOut(wt.amount, GetScriptForDestination(DecodeDestination(wt.strRefundDestination)));
    return MakeTransactionRef(std::move(mtx));
}

/** The 3b VerifyDB chain (design 6.1): a withdrawal (h1), its bundle (h2 =
 *  X), a fail commit for it (h3, the L1 says failed) and a refund of the
 *  withdrawal (h4), then empty blocks up to X+7. Returns the refunded
 *  withdrawal. */
SidechainWithdrawal BuildBundleFailRefundChain(PegChain& chain)
{
    const TestKey refunder;
    const CTransactionRef txW = chain.Withdrawal(COIN / 10, refunder.strAddress);
    const SidechainWithdrawal wt = WithdrawalOf(txW);
    chain.Connect(chain.Block({txW}), "withdrawal");

    const auto pblockX = chain.Block();
    SidechainWithdrawalBundle bundle;
    BOOST_REQUIRE_MESSAGE(BundleOf(*pblockX, bundle), "the template carries no bundle");
    chain.Connect(pblockX, "bundle");
    const uint256 hashB = bundle.tx.GetHash();

    chain.L1BundleEvent(hashB, 'F');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, hashB, true);
    }), "fail commit");
    BOOST_REQUIRE_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_UNSPENT);

    CTxOut payout;
    const CTransactionRef txRefund = RefundRequestTx(chain, wt, refunder.key, payout);
    chain.Connect(chain.Block({txRefund}, [&](CMutableTransaction& cb) { cb.vout.push_back(payout); }), "refund");
    BOOST_REQUIRE_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_SPENT);

    // Up to tip == X + 7 (X = 2, the bundle block): a node restarting there
    // with the default -checkblocks=6 verifies X+1..X+7
    while (TipForTest()->nHeight < 9)
        chain.Connect(chain.Block(), "empty");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(psidechaintree->GetWithdrawalBundle(hashB, row));
    BOOST_REQUIRE_EQUAL(row.status, WITHDRAWAL_BUNDLE_FAILED);
    BOOST_REQUIRE(LastBundleHash() == hashB);
    return wt;
}

/** CVerifyDB as init runs it (-checklevel, -checkblocks) and as
 *  `verifychain` does. */
bool VerifyDBForTest(int nLevel, int nDepth)
{
    LOCK(cs_main);
    return CVerifyDB().VerifyDB(Params(), pcoinsTip.get(), nLevel, nDepth);
}

/** Disconnect the tip block by block down to (and including) pindex, the
 *  way `invalidateblock` does (DisconnectTip -> DisconnectBlock, fSideDB). */
void InvalidateForTest(const CBlockIndex* pindex)
{
    CValidationState state;
    LOCK(cs_main);
    BOOST_REQUIRE(InvalidateBlock(state, Params(), const_cast<CBlockIndex*>(pindex)));
    BOOST_REQUIRE(chainActive.Tip() == pindex->pprev);
}

/** Is there a bundle row under either of its keys (GetID, tx hash)? */
bool HaveBundleRow(const SidechainWithdrawalBundle& bundle, SidechainWithdrawalBundle* pRow = nullptr)
{
    SidechainWithdrawalBundle row;
    const bool fByID = psidechaintree->GetWithdrawalBundle(bundle.GetID(), row);
    const bool fByTx = psidechaintree->GetWithdrawalBundle(bundle.tx.GetHash(), row);
    BOOST_CHECK_EQUAL(fByID, fByTx);
    if (pRow)
        *pRow = row;
    return fByID || fByTx;
}

/** Connects the template on the tip, which must carry a bundle. */
SidechainWithdrawalBundle ConnectBundleBlock(PegChain& chain, const std::string& strLabel, bool fDistinct = false)
{
    const auto pblock = chain.Block({}, nullptr, fDistinct);
    SidechainWithdrawalBundle bundle;
    BOOST_REQUIRE_MESSAGE(BundleOf(*pblock, bundle), LayoutName(chain.layout) << " " << strLabel << ": the template carries no bundle");
    chain.Connect(pblock, strLabel);
    return bundle;
}

/** Two bundles: W1, B1 = {W1}, B1 fails, W2, empty blocks until the fail wait
 *  is over, then B2 = {W1, W2} (X2). Tip = X2. */
struct TwoBundles {
    SidechainWithdrawal wt1, wt2;
    SidechainWithdrawalBundle b1, b2;
};
TwoBundles BuildTwoBundles(PegChain& chain)
{
    TwoBundles r;
    const CTransactionRef txW1 = chain.Withdrawal(COIN / 10);
    r.wt1 = WithdrawalOf(txW1);
    chain.Connect(chain.Block({txW1}), "W1");
    r.b1 = ConnectBundleBlock(chain, "B1");
    chain.L1BundleEvent(r.b1.tx.GetHash(), 'F');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, r.b1.tx.GetHash(), true);
    }), "B1 fail commit");
    const int nFailHeight = TipForTest()->nHeight;
    const CTransactionRef txW2 = chain.Withdrawal(COIN / 5);
    r.wt2 = WithdrawalOf(txW2);
    chain.Connect(chain.Block({txW2}), "W2");
    // The builder waits WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD blocks after a failure
    while (TipForTest()->nHeight + 1 - nFailHeight < WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD) {
        const auto pblock = chain.Block();
        SidechainWithdrawalBundle bundle;
        BOOST_REQUIRE(!BundleOf(*pblock, bundle));
        chain.Connect(pblock, "fail wait");
    }
    r.b2 = ConnectBundleBlock(chain, "B2");
    BOOST_REQUIRE(r.b2.tx.GetHash() != r.b1.tx.GetHash());
    BOOST_REQUIRE(LastBundleHash() == r.b2.tx.GetHash());
    return r;
}

} // namespace

// Runs one scenario in each layout, as its own test case (own fixture chain).
#define PEGBIND_BOTH_LAYOUTS(name)                                   \
    static void name(Layout layout, const CScript& scriptCoinbase); \
    BOOST_AUTO_TEST_CASE(name##_legacy) { name(Layout::LEGACY, GetCoinbaseScript()); } \
    BOOST_AUTO_TEST_CASE(name##_cusf) { name(Layout::CUSF, GetCoinbaseScript()); } \
    static void name(Layout layout, const CScript& scriptCoinbase)

BOOST_FIXTURE_TEST_SUITE(pegbind_tests, TestChain100Setup)

// ---------------------------------------------------------------------------
// P3 step 1: the seams. An honest deposit block connects in both layouts: the
// first deposit (no baseline) and a second one chained to it, each paid to
// the address its L1 tx names.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(honest_deposit_block)
{
    PegChain chain(layout, scriptCoinbase);
    BOOST_REQUIRE_EQUAL(TipForTest()->nHeight, 0);
    const TestKey alice, bob;
    const uint256 hashL1a = ArithToUint256(arith_uint256(0xa1));
    const uint256 hashL1b = ArithToUint256(arith_uint256(0xa2));
    const uint256 hashE1 = ArithToUint256(arith_uint256(0xe1)), hashE2 = ArithToUint256(arith_uint256(0xe2));
    MainCacheScope cache({ArithToUint256(arith_uint256(0xa0)), hashL1a, hashL1b, hashE1, hashE2});

    // The slot's first deposit: 5 COIN into an empty treasury
    uint32_t nBurn1 = 0;
    const CMutableTransaction dtx1 = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd1)), 0)},
                                                   5 * COIN, alice.strAddress, nBurn1);
    const SidechainDeposit d1 = MakeDepositRecord(dtx1, nBurn1, alice.strAddress, 5 * COIN, hashL1a);
    L1ListsDeposit(chain.oracle, d1, 5 * COIN, 0);
    const auto pblock1 = OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d1); }), hashE1);
    chain.Connect(pblock1, "first deposit");
    BOOST_CHECK(pblock1->vtx[0]->vout.size() > 2);

    // The next deposit spends the CTIP and adds 2 COIN for bob
    uint32_t nBurn2 = 0;
    const CMutableTransaction dtx2 = MakeDepositTx(layout,
        {COutPoint(CTransaction(dtx1).GetHash(), nBurn1), COutPoint(ArithToUint256(arith_uint256(0xd2)), 0)},
        7 * COIN, bob.strAddress, nBurn2);
    const SidechainDeposit d2 = MakeDepositRecord(dtx2, nBurn2, bob.strAddress, 2 * COIN, hashL1b);
    L1ListsDeposit(chain.oracle, d2, 2 * COIN, 1);
    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d2); }), hashE2), "second deposit");

    // Both rows, and the baseline is the second
    SidechainDeposit ctip;
    BOOST_REQUIRE(psidechaintree->GetLastDeposit(ctip));
    BOOST_CHECK(ctip.GetID() == d2.GetID());
    BOOST_CHECK_EQUAL(psidechaintree->GetDeposits(THIS_SIDECHAIN).size(), 2U);
    BOOST_CHECK(TipForTest()->hashLastDeposit == d2.GetID());
    BOOST_CHECK_EQUAL(TipForTest()->nHeight, 2);
}

// P3 step 1: an honest bundle block connects in both layouts, and the next
// block commits to it in its header and coinbase. The fail commit that ends
// it goes through the L1Oracle seam: UNKNOWN is a state.Error (not marked,
// retried), exactly as the transport's "no" was; YES connects it.
PEGBIND_BOTH_LAYOUTS(honest_bundle_block)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    chain.Connect(chain.Block({txW}), "withdrawal");
    BOOST_CHECK_EQUAL(WithdrawalStatus(WithdrawalOf(txW)), WITHDRAWAL_UNSPENT);

    // The template bundles it
    const auto pblockX = chain.Block();
    SidechainWithdrawalBundle bundle;
    BOOST_REQUIRE_MESSAGE(BundleOf(*pblockX, bundle), "the template carries no bundle");
    BOOST_CHECK(pblockX->hashWithdrawalBundle.IsNull()); // DB_LAST before X is null
    CAmount nBundleFee = 0;
    BOOST_CHECK_EQUAL(DecodeWithdrawalFeesCUSF(bundle.tx.vout[0].scriptPubKey, nBundleFee), layout == Layout::CUSF);
    chain.Connect(pblockX, "bundle");
    BOOST_CHECK_EQUAL(TipForTest()->nHeight, 2);
    const uint256 hashB = bundle.tx.GetHash();
    BOOST_CHECK(LastBundleHash() == hashB);
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(psidechaintree->GetWithdrawalBundle(hashB, row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
    BOOST_CHECK_EQUAL(row.nHeight, TipForTest()->nHeight);
    BOOST_CHECK_EQUAL(WithdrawalStatus(WithdrawalOf(txW)), WITHDRAWAL_IN_BUNDLE);

    // X+1 names the bundle in its header and coinbase
    const auto pblockX1 = chain.Block();
    BOOST_CHECK(pblockX1->hashWithdrawalBundle == hashB);
    chain.Connect(pblockX1, "X+1");

    // A fail commit: the L1 says UNKNOWN, then YES
    const auto pblockFail = chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, hashB, true);
    });
    const CBlockIndex* const pindexTip = TipForTest();
    BOOST_CHECK_MESSAGE(!chain.Process(pblockFail).empty(), "fail commit connected without an L1 answer");
    BOOST_CHECK(TipForTest() == pindexTip);
    BOOST_CHECK(!BlockFailedForTest(pblockFail->GetHash()));
    BOOST_CHECK(chain.oracle.nWindowCalls > 0);
    chain.L1BundleEvent(hashB, 'F');
    chain.Connect(pblockFail, "fail commit");
    BOOST_REQUIRE(psidechaintree->GetWithdrawalBundle(hashB, row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_FAILED);
    BOOST_CHECK_EQUAL(row.nFailHeight, TipForTest()->nHeight);
    BOOST_CHECK_EQUAL(WithdrawalStatus(WithdrawalOf(txW)), WITHDRAWAL_UNSPENT);
}

// ---------------------------------------------------------------------------
// P3 step 2, N2: VerifyDB never touches the sidechain DB. Its level 3
// disconnects the last blocks on a throwaway coins view, and below level 4
// (-checklevel=3, `verifychain 3`) never reconnects them; before N2 those
// disconnects still reverted the REAL sidechain DB (the bundle create, the
// fail commit, the refund and the DB_LAST pointer), and level 4's reconnect
// did not restore the pointer when the window starts after the bundle block.
// With a bundle, a fail commit and a refund in the window, the DB is
// byte-identical after VerifyDB at levels 3 and 4, and VerifyDB returns true.
// Level 4 reconnects the refund block without its UNSPENT requirement (the row
// stays SPENT). Windows: 6 = X+1..X+7 (a restart at tip X+7 with the default
// -checkblocks), 7 = X..X+7 (the bundle block too), 10 = the whole chain.
// ---------------------------------------------------------------------------
static void CheckVerifyDBLeavesSideDB(Layout layout, const CScript& scriptCoinbase, int nLevel, int nDepth)
{
    PegChain chain(layout, scriptCoinbase);
    const SidechainWithdrawal wt = BuildBundleFailRefundChain(chain);
    const auto vDumpBefore = DumpSidechainDB();
    const uint256 hashLast = LastBundleHash();
    for (int nRun = 1; nRun <= 2; nRun++) { // every restart runs it again
        BOOST_CHECK_MESSAGE(VerifyDBForTest(nLevel, nDepth),
            LayoutName(layout) << ": VerifyDB level " << nLevel << " depth " << nDepth << " failed (run " << nRun << ")");
        BOOST_CHECK_MESSAGE(DumpSidechainDB() == vDumpBefore,
            LayoutName(layout) << ": VerifyDB level " << nLevel << " depth " << nDepth << " changed the sidechain DB (run " << nRun << ")");
        BOOST_CHECK(LastBundleHash() == hashLast);
        BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_SPENT);
    }
    BOOST_CHECK_EQUAL(TipForTest()->nHeight, 9);
}

PEGBIND_BOTH_LAYOUTS(n2_verifydb_level3_depth6) { CheckVerifyDBLeavesSideDB(layout, scriptCoinbase, 3, 6); }
PEGBIND_BOTH_LAYOUTS(n2_verifydb_level3_depth10) { CheckVerifyDBLeavesSideDB(layout, scriptCoinbase, 3, 10); }
PEGBIND_BOTH_LAYOUTS(n2_verifydb_level4_depth6) { CheckVerifyDBLeavesSideDB(layout, scriptCoinbase, 4, 6); }
PEGBIND_BOTH_LAYOUTS(n2_verifydb_level4_depth7) { CheckVerifyDBLeavesSideDB(layout, scriptCoinbase, 4, 7); }
PEGBIND_BOTH_LAYOUTS(n2_verifydb_level4_depth10) { CheckVerifyDBLeavesSideDB(layout, scriptCoinbase, 4, 10); }


// ---------------------------------------------------------------------------
// v0.2.17 B8: while no bundle exists (the bundle pointer is null) a block's
// header bundle field must be empty. Before, the header was checked only while
// a bundle existed, so junk there connected, and B6's undo restores the
// pointer from that field. Honest: an empty field with no bundle; the field
// equal to the pointer once a bundle exists; anything else then is still
// CryptAxe's bad-header-withdrawal-bundle-commit.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(b8_header_bundle_field_empty_while_no_bundle)
{
    PegChain chain(layout, scriptCoinbase);
    BOOST_REQUIRE(LastBundleHash().IsNull());
    const uint256 hashJunk = ArithToUint256(arith_uint256(0xbad));

    {
        CBlock block = *chain.Block();
        BOOST_REQUIRE(block.hashWithdrawalBundle.IsNull());
        block.hashWithdrawalBundle = hashJunk;
        chain.Reject(PegChain::Reseal(block), "bad-header-withdrawal-bundle-nonnull", "junk header, no bundle");
    }
    BOOST_CHECK(LastBundleHash().IsNull());

    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    chain.Connect(chain.Block({txW}, nullptr, true), "empty header");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    const auto pblock = chain.Block();
    BOOST_CHECK(pblock->hashWithdrawalBundle == bundle.tx.GetHash());
    chain.Connect(pblock, "header == pointer");
    CBlock block = *chain.Block();
    block.hashWithdrawalBundle = hashJunk;
    chain.Reject(PegChain::Reseal(block), "bad-header-withdrawal-bundle-commit", "header != pointer");
}

// ---------------------------------------------------------------------------
// v0.2.17 B6: undo of a bundle on a reorg.
//  - Connect X (bundle B) and X+1, disconnect X+1: the pointer stays B (the
//    old code restored the parent's header field, one block off, so it went
//    null) and B's row is untouched.
//  - Disconnect X: B's row is gone under both keys (the old code wrote it
//    back as FAILED, a leftover row), the pointer is null, the withdrawal
//    UNSPENT.
//  - The builder re-bundles the same withdrawal on the new branch, with the
//    same bundle hash (the leftover row made it refuse: not unique).
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(b6_bundle_undo)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    const SidechainWithdrawal wt = WithdrawalOf(txW);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "X");
    const CBlockIndex* const pindexX = TipForTest();
    chain.Connect(chain.Block(), "X+1");
    const CBlockIndex* const pindexX1 = TipForTest();
    BOOST_REQUIRE(LastBundleHash() == bundle.tx.GetHash());

    InvalidateForTest(pindexX1);
    BOOST_CHECK_MESSAGE(LastBundleHash() == bundle.tx.GetHash(),
        LayoutName(layout) << ": disconnect X+1 moved the pointer to " << LastBundleHash().ToString());
    SidechainWithdrawalBundle row;
    BOOST_CHECK(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_IN_BUNDLE);

    InvalidateForTest(pindexX);
    BOOST_CHECK_MESSAGE(!HaveBundleRow(bundle, &row),
        LayoutName(layout) << ": disconnect X left the bundle row (status " << row.status << ")");
    BOOST_CHECK(LastBundleHash().IsNull());
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_UNSPENT);

    const auto pblock = chain.Block({}, nullptr, true /* fDistinct: not the invalidated X */);
    SidechainWithdrawalBundle bundleAgain;
    BOOST_CHECK_MESSAGE(BundleOf(*pblock, bundleAgain), LayoutName(layout) << ": the builder did not re-bundle");
    if (bundleAgain.tx.vout.size()) {
        BOOST_CHECK(bundleAgain.tx.GetHash() == bundle.tx.GetHash());
        chain.Connect(pblock, "X' (same bundle)");
        BOOST_CHECK(LastBundleHash() == bundle.tx.GetHash());
        BOOST_CHECK(HaveBundleRow(bundle, &row));
        BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
    }
}

// B6 with a previous bundle: disconnecting X2+1 keeps the pointer at B2, and
// disconnecting X2 restores B1, erases B2's row and resets B2's withdrawals
// (W1, W2) to UNSPENT, leaving B1's FAILED row alone.
PEGBIND_BOTH_LAYOUTS(b6_bundle_undo_previous_bundle)
{
    PegChain chain(layout, scriptCoinbase);
    const TwoBundles r = BuildTwoBundles(chain);
    const CBlockIndex* const pindexX2 = TipForTest();
    chain.Connect(chain.Block(), "X2+1");

    InvalidateForTest(TipForTest());
    BOOST_CHECK_MESSAGE(LastBundleHash() == r.b2.tx.GetHash(),
        LayoutName(layout) << ": disconnect X2+1 moved the pointer to " << LastBundleHash().ToString());

    InvalidateForTest(pindexX2);
    BOOST_CHECK(LastBundleHash() == r.b1.tx.GetHash());
    BOOST_CHECK(!HaveBundleRow(r.b2));
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(r.b1, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_FAILED);
    BOOST_CHECK_EQUAL(WithdrawalStatus(r.wt1), WITHDRAWAL_UNSPENT);
    BOOST_CHECK_EQUAL(WithdrawalStatus(r.wt2), WITHDRAWAL_UNSPENT);
}


// ---------------------------------------------------------------------------
// v0.2.17 B5: no database change until the whole block has passed. Before,
// a refund was written before the coinbase-amount and later checks, and a
// bundle "failed"/"paid" mark before the checks on the block's other objects,
// so a rejected block left them behind on the nodes that saw it: those nodes
// then rejected the honest refund or mark (a split).
// ---------------------------------------------------------------------------

/** A withdrawal whose L1 destination cannot be paid (bad-withdrawal-unpayable). */
CTransactionRef UnpayableWithdrawal(PegChain& chain)
{
    const CAmount nPayout = COIN / 10, nFee = 5000, nTxFee = 20000;
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(chain.Coin(COIN)));
    mtx.vout.push_back(CTxOut(COIN - nPayout - nFee - nTxFee, CScript() << OP_TRUE));
    mtx.vout.push_back(CTxOut(nPayout + nFee, CScript() << OP_RETURN));
    SidechainWithdrawal wt;
    wt.nSidechain = THIS_SIDECHAIN;
    wt.strDestination = "not-an-address";
    wt.amount = nPayout + nFee;
    wt.mainchainFee = nFee;
    wt.hashBlindTx = CTransaction(mtx).GetHash();
    mtx.vout.push_back(CTxOut(0, wt.GetScript()));
    return MakeTransactionRef(std::move(mtx));
}

PEGBIND_BOTH_LAYOUTS(b5_rejected_refund_leaves_no_change)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey refunder;
    const CTransactionRef txW = chain.Withdrawal(COIN / 10, refunder.strAddress);
    const SidechainWithdrawal wt = WithdrawalOf(txW);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    chain.L1BundleEvent(bundle.tx.GetHash(), 'F');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, bundle.tx.GetHash(), true);
    }), "fail commit");
    BOOST_REQUIRE_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_UNSPENT);

    CTxOut payout;
    const CTransactionRef txRefund = RefundRequestTx(chain, wt, refunder.key, payout);
    // The refund, with a coinbase that pays a coin too much
    chain.Reject(chain.Block({txRefund}, [&](CMutableTransaction& cb) {
        cb.vout.push_back(payout);
        cb.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    }), "bad-cb-amount", "refund + coinbase pays too much");
    BOOST_CHECK_MESSAGE(WithdrawalStatus(wt) == WITHDRAWAL_UNSPENT,
        LayoutName(layout) << ": the rejected block left the refund written (status " << WithdrawalStatus(wt) << ")");

    // The honest refund still connects
    chain.Connect(chain.Block({txRefund}, [&](CMutableTransaction& cb) { cb.vout.push_back(payout); }, true),
                  "honest refund");
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_SPENT);
}

PEGBIND_BOTH_LAYOUTS(b5_rejected_mark_leaves_no_change)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    const SidechainWithdrawal wt = WithdrawalOf(txW);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    chain.L1BundleEvent(bundle.tx.GetHash(), 'F');

    // The fail mark, in a block that also carries an unpayable withdrawal
    chain.Reject(chain.Block({UnpayableWithdrawal(chain)}, [&](CMutableTransaction& cb) {
        AddMark(cb, bundle.tx.GetHash(), true);
    }), "bad-withdrawal-unpayable", "fail mark + unpayable withdrawal");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_MESSAGE(row.status == WITHDRAWAL_BUNDLE_CREATED,
        LayoutName(layout) << ": the rejected block left the mark written (status " << row.status << ")");
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_IN_BUNDLE);

    // The honest mark still connects
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, bundle.tx.GetHash(), true);
    }, true), "honest fail mark");
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_FAILED);
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_UNSPENT);
}

// Decision 2 (2026-09-29): a block that creates a bundle carries no bundle
// mark and no refund (CryptAxe's builder already never does either).
PEGBIND_BOTH_LAYOUTS(b5_bundle_block_carries_no_mark)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW1 = chain.Withdrawal(COIN / 10);
    chain.Connect(chain.Block({txW1}), "W1");
    const CTransactionRef txW2 = chain.Withdrawal(COIN / 5);
    const auto pblockX = chain.Block({txW2});
    SidechainWithdrawalBundle b1;
    BOOST_REQUIRE(BundleOf(*pblockX, b1));
    chain.Connect(pblockX, "X: B1 + W2");

    // X+1: B1 paid out on the L1, and B2 = {W2} in the same block
    CTransactionRef txB2, txB2Data;
    BOOST_REQUIRE(CreateWithdrawalBundleTx(TipForTest()->nHeight + 1, txB2, txB2Data,
                                           true /* fReplicationCheck */, false /* fCheckUnique */));
    chain.L1BundleEvent(b1.tx.GetHash(), 'S');
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, b1.tx.GetHash(), false);
        for (const CTxOut& out : txB2Data->vout)
            cb.vout.push_back(out);
    }), "bad-bundle-block-mark", "B1 paid mark + B2");
    BOOST_CHECK(LastBundleHash() == b1.tx.GetHash());
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(b1, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
    BOOST_CHECK(!psidechaintree->GetWithdrawalBundle(txB2->GetHash(), row));

    // The honest mark alone connects
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, b1.tx.GetHash(), false);
    }, true), "honest paid mark");
    BOOST_REQUIRE(HaveBundleRow(b1, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_SPENT);
}

PEGBIND_BOTH_LAYOUTS(b5_bundle_block_carries_no_refund)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey refunder;
    const CTransactionRef txW1 = chain.Withdrawal(COIN / 10, refunder.strAddress);
    const SidechainWithdrawal wt1 = WithdrawalOf(txW1);
    chain.Connect(chain.Block({txW1}), "W1");
    const SidechainWithdrawalBundle b1 = ConnectBundleBlock(chain, "B1");
    chain.L1BundleEvent(b1.tx.GetHash(), 'F');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, b1.tx.GetHash(), true);
    }), "B1 fail commit");
    const int nFailHeight = TipForTest()->nHeight;
    const CTransactionRef txW2 = chain.Withdrawal(COIN / 5);
    chain.Connect(chain.Block({txW2}), "W2");
    while (TipForTest()->nHeight + 1 - nFailHeight < WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD)
        chain.Connect(chain.Block(), "fail wait");

    // The builder's bundle block, plus a refund of W1
    CTxOut payout;
    const CTransactionRef txRefund = RefundRequestTx(chain, wt1, refunder.key, payout);
    const auto pblock = chain.Block({txRefund}, [&](CMutableTransaction& cb) { cb.vout.push_back(payout); });
    SidechainWithdrawalBundle b2;
    BOOST_REQUIRE(BundleOf(*pblock, b2));
    chain.Reject(pblock, "bad-bundle-block-refund", "B2 + refund of W1");
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt1), WITHDRAWAL_UNSPENT);
    BOOST_CHECK(LastBundleHash() == b1.tx.GetHash());

    // The honest bundle block connects
    ConnectBundleBlock(chain, "honest B2", true);
}


// ---------------------------------------------------------------------------
// v0.2.17 builder: a refund request with a child in the mempool. The builder
// skipped a refund only when it met the refund itself; the child's package
// pulled it in as an ancestor. In a block that creates a bundle the coinbase
// then had no refund payout, the template failed its own check, and no block
// could be built while the pair sat in the mempool.
// ---------------------------------------------------------------------------
static bool ToMempool(const CTransactionRef& tx, std::string& strReason)
{
    LOCK(cs_main);
    CValidationState state;
    const bool fOk = AcceptToMemoryPool(mempool, state, tx, nullptr /* pfMissingInputs */,
                                        nullptr /* plTxnReplaced */, true /* bypass_limits */, 0 /* nAbsurdFee */);
    strReason = state.GetRejectReason();
    return fOk;
}

PEGBIND_BOTH_LAYOUTS(builder_bundle_block_skips_refund_pulled_in_by_child)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey refunder;
    const CTransactionRef txW1 = chain.Withdrawal(COIN / 10, refunder.strAddress);
    const SidechainWithdrawal wt1 = WithdrawalOf(txW1);
    chain.Connect(chain.Block({txW1}), "W1");
    const SidechainWithdrawalBundle b1 = ConnectBundleBlock(chain, "B1");
    chain.L1BundleEvent(b1.tx.GetHash(), 'F');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, b1.tx.GetHash(), true);
    }), "B1 fail commit");
    const int nFailHeight = TipForTest()->nHeight;
    chain.Connect(chain.Block({chain.Withdrawal(COIN / 5)}), "W2");
    while (TipForTest()->nHeight + 1 - nFailHeight < WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD)
        chain.Connect(chain.Block(), "fail wait");

    // A refund of W1 and a child spending its change, both in the mempool
    CTxOut payout;
    const CTransactionRef txRefund = RefundRequestTx(chain, wt1, refunder.key, payout);
    CMutableTransaction mtxChild;
    mtxChild.vin.push_back(CTxIn(COutPoint(txRefund->GetHash(), 0)));
    mtxChild.vout.push_back(CTxOut(txRefund->vout[0].nValue - 100000, CScript() << OP_TRUE));
    const CTransactionRef txChild = MakeTransactionRef(std::move(mtxChild));
    // The node's standardness as regtest sets it (the fixture leaves it on);
    // restored, and the mempool emptied, however the case ends
    struct Scope {
        const bool fSaved = fRequireStandard;
        Scope() { fRequireStandard = Params().RequireStandard(); }
        ~Scope() { fRequireStandard = fSaved; LOCK(cs_main); mempool.clear(); }
    } scope;
    std::string strReason;
    BOOST_REQUIRE_MESSAGE(ToMempool(txRefund, strReason), "refund: " << strReason);
    BOOST_REQUIRE_MESSAGE(ToMempool(txChild, strReason), "child: " << strReason);

    // The next block creates B2: the builder must still build it, without the refund
    CBlock block;
    std::string strError;
    const bool fBuilt = BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
        std::vector<CMutableTransaction>(), uint256(), scriptCoinbase);
    BOOST_CHECK_MESSAGE(fBuilt, LayoutName(layout) << ": no block template: " << strError);
    if (fBuilt) {
        SidechainWithdrawalBundle b2;
        BOOST_CHECK(BundleOf(block, b2));
        for (const CTransactionRef& tx : block.vtx)
            BOOST_CHECK_MESSAGE(tx->GetHash() != txRefund->GetHash() && tx->GetHash() != txChild->GetHash(),
                                LayoutName(layout) << ": the bundle block carries the refund or its child");
    }
}


// ---------------------------------------------------------------------------
// v0.2.17 B1: a "failed" or "paid" mark only for the bundle that is pending
// (the pointer's bundle, status CREATED), and one mark per block. Before, a
// mark could name any bundle we hold: an old failed bundle marked failed again
// reset its withdrawals to UNSPENT while they sat in the pending bundle, so
// they could be refunded or bundled again: paid twice.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(b1_mark_only_for_pending_bundle)
{
    PegChain chain(layout, scriptCoinbase);
    const TwoBundles r = BuildTwoBundles(chain);   // B1 failed, B2 = {W1, W2} pending
    BOOST_REQUIRE_EQUAL(WithdrawalStatus(r.wt1), WITHDRAWAL_IN_BUNDLE);

    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, r.b1.tx.GetHash(), true);
    }), "bad-bundle-mark-not-pending", "B1 marked failed again");
    BOOST_CHECK_MESSAGE(WithdrawalStatus(r.wt1) == WITHDRAWAL_IN_BUNDLE,
        LayoutName(layout) << ": W1 left the pending bundle (status " << WithdrawalStatus(r.wt1) << ")");
    chain.L1BundleEvent(r.b1.tx.GetHash(), 'S');
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, r.b1.tx.GetHash(), false);
    }, true), "bad-bundle-mark-not-pending", "B1 marked paid");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(r.b1, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_FAILED);

    // B2 paid; a second mark for it is not for a pending bundle either
    chain.L1BundleEvent(r.b2.tx.GetHash(), 'S');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, r.b2.tx.GetHash(), false);
    }, true), "B2 paid");
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, r.b2.tx.GetHash(), true);
    }, true), "bad-bundle-mark-not-pending", "B2 marked failed after paid");
    BOOST_REQUIRE(HaveBundleRow(r.b2, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_SPENT);
    BOOST_CHECK_EQUAL(WithdrawalStatus(r.wt1), WITHDRAWAL_SPENT);
}

PEGBIND_BOTH_LAYOUTS(b1_one_mark_per_block)
{
    PegChain chain(layout, scriptCoinbase);
    chain.Connect(chain.Block({chain.Withdrawal(COIN / 10)}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    chain.L1BundleEvent(bundle.tx.GetHash(), 'F');
    chain.L1BundleEvent(bundle.tx.GetHash(), 'S');
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, bundle.tx.GetHash(), true);
        cb.vout.push_back(CTxOut(0, GenerateWithdrawalBundleSpentCommit(bundle.tx.GetHash())));
    }), "bad-bundle-mark-duplicate", "failed and paid in one block");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
}

// ---------------------------------------------------------------------------
// v0.2.17 B2: a bundle must be new. Only the builder refused a bundle whose
// tx hash we already hold; the checking code accepted it and overwrote the
// old row (a failed or paid bundle) under both keys.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(b2_bundle_must_be_new)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    const SidechainWithdrawal wt = WithdrawalOf(txW);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "X");
    chain.L1BundleEvent(bundle.tx.GetHash(), 'F');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, bundle.tx.GetHash(), true);
    }), "X failed");
    const int nFailHeight = TipForTest()->nHeight;
    while (TipForTest()->nHeight + 1 - nFailHeight < WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD) {
        const auto pblock = chain.Block();
        SidechainWithdrawalBundle none;
        BOOST_REQUIRE(!BundleOf(*pblock, none)); // the builder will not repeat X
        chain.Connect(pblock, "fail wait");
    }

    // X again, made the way a block maker without the builder's check would
    CTransactionRef txAgain, txAgainData;
    BOOST_REQUIRE(CreateWithdrawalBundleTx(TipForTest()->nHeight + 1, txAgain, txAgainData,
                                           true /* fReplicationCheck */, false /* fCheckUnique */));
    BOOST_REQUIRE(txAgain->GetHash() == bundle.tx.GetHash());
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) {
        for (const CTxOut& out : txAgainData->vout)
            cb.vout.push_back(out);
    }), "bad-bundle-not-new", "X again");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_FAILED);
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_UNSPENT);
}

// ---------------------------------------------------------------------------
// v0.2.17 B3 + D1: a mark is checked with the L1 as of the block's own L1
// block, from the L1 block of the FreeBank block that created the bundle. The
// bundle's outcome is its LAST event there. Three answers: the events say so
// (accept), they say otherwise (reject for good, no penalty), no answer (wait:
// not accepted, not marked failed; the same block connects once the L1 can
// answer). Before, the node asked "has this ever failed / been paid" as of its
// own L1 tip, and "no answer" was retried like a bad block.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(b3_mark_checked_as_of_block_l1)
{
    PegChain chain(layout, scriptCoinbase);
    chain.Connect(chain.Block({chain.Withdrawal(COIN / 10)}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    const uint256 hashStart = TipForTest()->hashMainBlock; // the bundle block's L1 block
    L1WithdrawalEvent ev;
    ev.m6id = BundleM6id(bundle.tx);

    // A block whose own L1 block is hashE, carrying a mark
    auto Marked = [&](bool fFailed, int nE) {
        CBlock block = *chain.Block({}, [&](CMutableTransaction& cb) {
            cb.vout.push_back(CTxOut(0, fFailed ? GenerateWithdrawalBundleFailCommit(bundle.tx.GetHash())
                                                : GenerateWithdrawalBundleSpentCommit(bundle.tx.GetHash())));
        }, true);
        block.hashMainchainBlock = ArithToUint256(arith_uint256(0xe000 + nE));
        return PegChain::Reseal(block);
    };
    auto Window = [&](int nE, const std::string& strEvents) {
        L1PegEvents events;
        for (char c : strEvents) { ev.status = c; events.vWithdrawal.push_back(ev); }
        chain.oracle.mapWindowEvents[std::make_pair(hashStart, ArithToUint256(arith_uint256(0xe000 + nE)))] =
            std::make_pair(L1Answer::YES, events);
    };

    // Proposed only: neither mark
    Window(1, "U");
    chain.Reject(Marked(true, 1), "bad-bundle-mark-l1", "failed, L1 says proposed");
    Window(2, "U");
    chain.Reject(Marked(false, 2), "bad-bundle-mark-l1", "paid, L1 says proposed");
    // D1: failed, proposed again, paid: the last event decides
    Window(3, "UFUS");
    chain.Reject(Marked(true, 3), "bad-bundle-mark-l1", "failed, L1's last event is paid");
    // No answer yet: wait
    const auto pblockWait = Marked(true, 4);
    const CBlockIndex* const pindexTip = TipForTest();
    BOOST_CHECK(!chain.Process(pblockWait).empty());
    BOOST_CHECK(TipForTest() == pindexTip);
    BOOST_CHECK_MESSAGE(!BlockFailedForTest(pblockWait->GetHash()), LayoutName(layout) << ": no answer marked the block failed");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
    // The L1 answers "failed": the same block connects
    Window(4, "UF");
    chain.Connect(pblockWait, "failed, L1 says failed");
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_FAILED);
}

PEGBIND_BOTH_LAYOUTS(b3_paid_mark_last_event)
{
    PegChain chain(layout, scriptCoinbase);
    chain.Connect(chain.Block({chain.Withdrawal(COIN / 10)}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    L1WithdrawalEvent ev;
    ev.m6id = BundleM6id(bundle.tx);
    L1PegEvents events;
    for (char c : std::string("UFUS")) { ev.status = c; events.vWithdrawal.push_back(ev); }
    CBlock block = *chain.Block({}, [&](CMutableTransaction& cb) {
        AddMark(cb, bundle.tx.GetHash(), false);
    });
    block.hashMainchainBlock = ArithToUint256(arith_uint256(0xe0e0));
    chain.oracle.mapWindowEvents[std::make_pair(TipForTest()->hashMainBlock, block.hashMainchainBlock)] =
        std::make_pair(L1Answer::YES, events);
    chain.Connect(PegChain::Reseal(block), "paid, L1's last event is paid");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_SPENT);
}

// ---------------------------------------------------------------------------
// v0.2.17 B4: blocks that are bad in the bundle section are rejected (marked
// failed), not retried forever as if the node had a database error.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(b4_bad_bundle_blocks_rejected)
{
    PegChain chain(layout, scriptCoinbase);

    // A withdrawal with no burn behind it
    {
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(chain.Coin(COIN)));
        mtx.vout.push_back(CTxOut(COIN - 20000, CScript() << OP_TRUE));
        SidechainWithdrawal wt;
        wt.nSidechain = THIS_SIDECHAIN;
        wt.strDestination = L1_P2PKH_REGTEST;
        wt.amount = COIN / 10;
        wt.mainchainFee = 5000;
        wt.hashBlindTx = CTransaction(mtx).GetHash();
        mtx.vout.push_back(CTxOut(0, wt.GetScript()));
        chain.Reject(chain.Block({MakeTransactionRef(std::move(mtx))}), "bad-withdrawal-burn", "withdrawal without a burn");
    }

    // A second copy of the pending bundle while it is pending
    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const auto pblockX = chain.Block();
    SidechainWithdrawalBundle bundle;
    BOOST_REQUIRE(BundleOf(*pblockX, bundle));
    chain.Connect(pblockX, "X");
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) {
        for (size_t i = 0; i < pblockX->vtx[0]->vout.size(); i++) {
            std::vector<unsigned char> vch;
            if (pblockX->vtx[0]->vout[i].scriptPubKey.IsSidechainObj(vch))
                cb.vout.push_back(pblockX->vtx[0]->vout[i]);
        }
    }), "bad-bundle-still-pending", "a bundle while one is pending");
    BOOST_CHECK(LastBundleHash() == bundle.tx.GetHash());
}


// ---------------------------------------------------------------------------
// v0.2.17 C1: the BMM check has three answers. Yes: E carries the bid, E is on
// the L1's main chain (our list of L1 blocks) and the coinbase names E's
// parent. No: the L1 has processed E and it carries no bid or another one, or
// the coinbase names another parent: the block is invalid for good, with
// CryptAxe's scores. Can't tell: the enforcer has not processed E or does not
// answer, or E is not (yet) in our list: state.Error, so the block is neither
// stored nor marked and the peer is not penalised. Before, "can't tell" from
// the enforcer cost the peer a point each time, and E missing from our list
// marked an honest block invalid for good (bad-mc-prev, 25 points).
// ---------------------------------------------------------------------------

static std::string BmmVerdict(const CBlock& block)
{
    CValidationState state;
    if (CheckBlockBMM(block, state))
        return "yes";
    int nDoS = 0;
    if (state.IsInvalid(nDoS))
        return strprintf("no:%s:%d%s", state.GetRejectReason(), nDoS, state.CorruptionPossible() ? ":corruption" : "");
    return "cant-tell";
}

BOOST_AUTO_TEST_CASE(c1_bmm_three_answers)
{
    TestL1Oracle oracle;
    const uint256 hashG = ArithToUint256(arith_uint256(0xa0)), hashP = ArithToUint256(arith_uint256(0xa1)),
                  hashE = ArithToUint256(arith_uint256(0xa2)), hashE2 = ArithToUint256(arith_uint256(0xa3));
    MainCacheScope cache({hashG, hashP, hashE});

    int nBlock = 0;
    auto Block = [&](const uint256& hashMain, const uint256& hashPrevMain) {
        CBlock block;
        block.hashPrevBlock = ArithToUint256(arith_uint256(0x5c));
        block.hashMainchainBlock = hashMain;
        block.hashMerkleRoot = ArithToUint256(arith_uint256(0xb000 + ++nBlock)); // h*, and a fresh block hash
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vin[0].prevout.SetNull();
        cb.vout.push_back(CTxOut(0, GeneratePrevBlockCommit(hashPrevMain, block.hashPrevBlock)));
        block.vtx.push_back(MakeTransactionRef(std::move(cb)));
        return block;
    };

    // Yes
    CBlock block = Block(hashE, hashP);
    oracle.mapBmm[std::make_pair(hashE, block.hashMerkleRoot)] = L1Answer::YES;
    BOOST_CHECK_EQUAL(BmmVerdict(block), "yes");

    // No: E carries no bid or another one
    block = Block(hashE, hashP);
    oracle.mapBmm[std::make_pair(hashE, block.hashMerkleRoot)] = L1Answer::NO;
    BOOST_CHECK_EQUAL(BmmVerdict(block), "no:bad-bmm:1");

    // No: the coinbase names another parent of E
    block = Block(hashE, hashG);
    oracle.mapBmm[std::make_pair(hashE, block.hashMerkleRoot)] = L1Answer::YES;
    BOOST_CHECK_EQUAL(BmmVerdict(block), "no:bad-mc-prev:25");

    // Can't tell: the enforcer has not processed E, or does not answer
    block = Block(hashE, hashP);
    oracle.mapBmm[std::make_pair(hashE, block.hashMerkleRoot)] = L1Answer::UNKNOWN;
    BOOST_CHECK_EQUAL(BmmVerdict(block), "cant-tell");

    // Can't tell: E carries the bid but is not in our list yet
    block = Block(hashE2, hashE);
    oracle.mapBmm[std::make_pair(hashE2, block.hashMerkleRoot)] = L1Answer::YES;
    BOOST_CHECK_EQUAL(BmmVerdict(block), "cant-tell");
    // ... and passes once the list has it
    bmmCache.ReplaceMainBlockCache({hashG, hashP, hashE, hashE2});
    BOOST_CHECK_EQUAL(BmmVerdict(block), "yes");

    // No: the prevBlock commit is missing (wrong in itself)
    block = Block(hashE, hashP);
    oracle.mapBmm[std::make_pair(hashE, block.hashMerkleRoot)] = L1Answer::YES;
    {
        CMutableTransaction cb(*block.vtx[0]);
        cb.vout.clear();
        block.vtx[0] = MakeTransactionRef(std::move(cb));
    }
    BOOST_CHECK_EQUAL(BmmVerdict(block), "no:no-prev-commit:100");

    // During -reindex / -loadblock / replay the list is filled to the
    // enforcer's tip first: an L1 block missing from it is off the L1's main
    // chain, a definite no (the import reader stops a file at a state.Error)
    block = Block(ArithToUint256(arith_uint256(0xa9)), hashE);
    const bool fReindexSaved = fReindex;
    fReindex = true;
    BOOST_CHECK_EQUAL(BmmVerdict(block), "no:bad-mc-prev:0");
    fReindex = fReindexSaved;
}


// ---------------------------------------------------------------------------
// v0.2.17, decisions 2026-09-29 after the area-2 review. A payment on the L1
// is final: submitted, paid, proposed again, failed still counts as paid (the
// "last event" rule counted it failed: its withdrawals spendable again after
// the L1 paid them). The builder decides marks exactly as the check does.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(d1_paid_is_final_and_builder_agrees)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    const uint256 hashB = bundle.tx.GetHash();
    auto MarkIn = [](const CBlock& block, uint256& hash, bool& fFailed) {
        for (const CTxOut& out : block.vtx[0]->vout) {
            if (out.scriptPubKey.IsWithdrawalBundleFailCommit(hash)) { fFailed = true; return true; }
            if (out.scriptPubKey.IsWithdrawalBundleSpentCommit(hash)) { fFailed = false; return true; }
        }
        return false;
    };
    uint256 hash;
    bool fFailed = false;

    // Failed, then proposed again: neither mark from the builder
    chain.L1BundleEvent(hashB, 'U');
    chain.L1BundleEvent(hashB, 'F');
    chain.L1BundleEvent(hashB, 'U');
    BOOST_CHECK_MESSAGE(!MarkIn(*chain.Block(), hash, fFailed), LayoutName(layout) << ": the builder marked a bundle proposed again");
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) { AddMark(cb, hashB, true); }),
                 "bad-bundle-mark-l1", "failed mark, last event proposed again");

    // Paid, then proposed again and failed: paid
    chain.L1BundleEvent(hashB, 'S');
    chain.L1BundleEvent(hashB, 'U');
    chain.L1BundleEvent(hashB, 'F');
    chain.Reject(chain.Block({}, [&](CMutableTransaction& cb) { AddMark(cb, hashB, true); }, true),
                 "bad-bundle-mark-l1", "failed mark after the L1 paid");
    const auto pblock = chain.Block({}, nullptr, true);
    BOOST_REQUIRE_MESSAGE(MarkIn(*pblock, hash, fFailed), LayoutName(layout) << ": the builder did not mark the paid bundle");
    BOOST_CHECK(hash == hashB && !fFailed);
    chain.Connect(pblock, "the builder's paid mark");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_SPENT);
    BOOST_CHECK_EQUAL(WithdrawalStatus(WithdrawalOf(txW)), WITHDRAWAL_SPENT);
}

// If the L1 block of the bundle's own block is not an ancestor of the mark's
// L1 block, the whole L1 history is asked instead of waiting for ever.
PEGBIND_BOTH_LAYOUTS(b3_window_falls_back_to_whole_history)
{
    PegChain chain(layout, scriptCoinbase);
    chain.Connect(chain.Block({chain.Withdrawal(COIN / 10)}), "withdrawal");
    // The bundle's block names L1 block S
    const uint256 hashS = ArithToUint256(arith_uint256(0xc0));
    CBlock blockX = *chain.Block();
    SidechainWithdrawalBundle bundle;
    BOOST_REQUIRE(BundleOf(blockX, bundle));
    blockX.hashMainchainBlock = hashS;
    chain.Connect(PegChain::Reseal(blockX), "bundle, L1 block S");

    CBlock block = *chain.Block({}, [&](CMutableTransaction& cb) { AddMark(cb, bundle.tx.GetHash(), true); });
    block.hashMainchainBlock = ArithToUint256(arith_uint256(0xe0f0));
    L1PegEvents events;
    L1WithdrawalEvent ev;
    ev.m6id = BundleM6id(bundle.tx);
    ev.status = 'F';
    events.vWithdrawal.push_back(ev);
    // S is not an ancestor of the mark's L1 block; the whole history says failed
    chain.oracle.mapWindowEvents[std::make_pair(hashS, block.hashMainchainBlock)] = std::make_pair(L1Answer::NO, L1PegEvents());
    chain.oracle.mapWindowEvents[std::make_pair(uint256(), block.hashMainchainBlock)] = std::make_pair(L1Answer::YES, events);
    // v0.2.18 L1-order rule: the mark's L1 block must sit above S in our list
    // of L1 main-chain blocks.
    MainCacheScope l1({hashS, block.hashMainchainBlock});
    chain.Connect(PegChain::Reseal(block), "failed mark via the whole history");
}

// ---------------------------------------------------------------------------
// v0.2.17, decision 2026-09-29: a new bundle's record must be the one the node
// builds itself. Only the tx was compared: a record listing W1 twice and
// leaving out W2 (equal L1 fees, so the encoded fee still adds up) connected;
// the L1 would pay W2 while W2 stayed spendable here. Junk in the record's last
// bytes (status, heights; producers before v0.2.15) is still accepted and the
// bundle stored as pending.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(bundle_record_must_match_replica)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW1 = chain.Withdrawal(COIN / 10), txW2 = chain.Withdrawal(COIN / 5);
    const SidechainWithdrawal wt1 = WithdrawalOf(txW1), wt2 = WithdrawalOf(txW2);
    BOOST_REQUIRE_EQUAL(wt1.mainchainFee, wt2.mainchainFee);
    chain.Connect(chain.Block({txW1, txW2}), "W1 + W2");
    const auto pblock = chain.Block();
    SidechainWithdrawalBundle bundle;
    BOOST_REQUIRE(BundleOf(*pblock, bundle));
    BOOST_REQUIRE_EQUAL(bundle.vWithdrawalID.size(), 2U);

    auto WithRecord = [&](const SidechainWithdrawalBundle& record, bool fDistinct) {
        CBlock block = *chain.Block({}, nullptr, fDistinct);
        CMutableTransaction cb(*block.vtx[0]);
        for (CTxOut& out : cb.vout) {
            std::vector<unsigned char> vch;
            if (out.scriptPubKey.IsSidechainObj(vch))
                out.scriptPubKey = record.GetScript();
        }
        block.vtx[0] = MakeTransactionRef(std::move(cb));
        return PegChain::Reseal(block);
    };

    SidechainWithdrawalBundle twice = bundle;
    const uint256 idKeep = twice.vWithdrawalID[0];
    twice.vWithdrawalID = {idKeep, idKeep};
    chain.Reject(WithRecord(twice, false), "bad-bundle-invalid", "a record listing one withdrawal twice");
    BOOST_CHECK(LastBundleHash().IsNull());

    SidechainWithdrawalBundle junk = bundle;
    junk.status = WITHDRAWAL_BUNDLE_FAILED;
    junk.nFailHeight = 12345;
    const auto pblockJunk = WithRecord(junk, true);
    chain.Connect(pblockJunk, "a record with junk in its last bytes");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
    BOOST_CHECK_EQUAL(row.nFailHeight, 0);
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt1), WITHDRAWAL_IN_BUNDLE);
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt2), WITHDRAWAL_IN_BUNDLE);
}


// ---------------------------------------------------------------------------
// v0.2.17 C3: the BMM scan records an L1 block as checked only after a
// definite answer for every bid. It recorded it after every scan, so a bid won
// while the enforcer did not answer was never connected: paid, no block.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(c3_scan_marks_checked_only_on_an_answer)
{
    TestL1Oracle oracle;
    const uint256 hashT = ArithToUint256(arith_uint256(0xc30)), hashU = ArithToUint256(arith_uint256(0xc31));
    // Our bid was made on L1 tip T; U, T's child and the new L1 tip, may carry it
    MainCacheScope cache({hashT, hashU});
    CBlock bid;
    bid.vtx.push_back(MakeTransactionRef(CMutableTransaction()));
    bid.hashMerkleRoot = ArithToUint256(arith_uint256(0xc3b));
    BOOST_REQUIRE(bmmCache.StoreBMMBlock(bid));
    bmmCache.StorePrevBlockBMMCreated(hashT);
    oracle.mapBmm[std::make_pair(hashT, bid.hashMerkleRoot)] = L1Answer::NO;

    auto Scan = [&]() {
        SidechainClient client;
        std::string strError;
        uint256 hashCreated, hashConnected, hashConnectedRoot, txid;
        int nTxn = 0;
        CAmount nFees = 0;
        client.RefreshBMM(0, strError, hashCreated, hashConnected, hashConnectedRoot, txid, nTxn, nFees,
                          false /* fCreateNew */, uint256());
    };

    // The L1 cannot answer about U: U is not recorded as checked, and the bid
    // block is kept for the next scan
    oracle.mapBmm[std::make_pair(hashU, bid.hashMerkleRoot)] = L1Answer::UNKNOWN;
    Scan();
    BOOST_CHECK(bmmCache.MainBlockChecked(hashT));
    BOOST_CHECK_MESSAGE(!bmmCache.MainBlockChecked(hashU), "an unanswered L1 block was recorded as checked");
    CBlock kept;
    BOOST_CHECK_MESSAGE(bmmCache.GetBMMBlock(bid.hashMerkleRoot, kept), "the bid block was dropped before the L1 answered");

    // The L1 answers no: U is checked, and the bids made on T go
    oracle.mapBmm[std::make_pair(hashU, bid.hashMerkleRoot)] = L1Answer::NO;
    Scan();
    BOOST_CHECK(bmmCache.MainBlockChecked(hashU));
    BOOST_CHECK(!bmmCache.GetBMMBlock(bid.hashMerkleRoot, kept));
    bmmCache.ClearBMMBlocks();
}


// ---------------------------------------------------------------------------
// v0.2.17 C2: an L1 that reports a lower tip on the same chain (a restored or
// resyncing enforcer) is behind, not reorged: the cache of L1 blocks is kept.
// It was handled as a reorg: the cached blocks above were popped and the
// FreeBank blocks anchored in them thrown away.
// ---------------------------------------------------------------------------
struct FakeL1Client : public L1Client {
    std::vector<uint256> vChain; // the L1 chain from genesis, as this client reports it
    FakeL1Client() { SetL1ClientForTest(this); }
    ~FakeL1Client() { SetL1ClientForTest(nullptr); }
    bool GetBlockCount(int& nBlocks) override { nBlocks = (int)vChain.size() - 1; return !vChain.empty(); }
    bool GetBlockHash(int nHeight, uint256& hashBlock) override
    {
        if (nHeight < 0 || nHeight >= (int)vChain.size()) return false;
        hashBlock = vChain[nHeight];
        return true;
    }
    bool GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash) override
    {
        vHash.clear();
        if (nHeight < 0 || nHeight >= (int)vChain.size() || vChain[nHeight] != hashBlock) return false;
        for (int h = nHeight; h >= 0 && vHash.size() < nMax; h--)
            vHash.push_back(vChain[h]);
        return true;
    }
    bool BroadcastWithdrawalBundle(const std::string&) override { return false; }
    std::vector<SidechainDeposit> UpdateDeposits(const uint256&, const uint32_t) override { return vDepositsToReport; }
    bool VerifyDeposit(const uint256&, const uint256&, const int) override { return false; }
    bool VerifyBMM(const uint256&, const uint256&, uint256&, uint32_t&) override { return false; }
    int nBids = 0;
    bool fBehind = false;
    uint256 SendBMMRequest(const uint256&, const uint256&, int, CAmount, bool& fNotSent) override { nBids++; fNotSent = true; return uint256(); }
    std::vector<SidechainDeposit> vDepositsToReport;
    bool IsBehindItsNode(std::string& strWhy) override { if (fBehind) strWhy = "behind"; return fBehind; }
    bool GetCTIP(std::pair<uint256, uint32_t>&) override { return false; }
    bool GetAverageFees(int, int, CAmount&) override { return false; }
    bool GetWorkScore(const uint256&, int&) override { return false; }
    bool ListWithdrawalBundleStatus(std::vector<uint256>&) override { return false; }
    bool HaveSpentWithdrawalBundle(const uint256&) override { return false; }
    bool HaveFailedWithdrawalBundle(const uint256&) override { return false; }
};

BOOST_AUTO_TEST_CASE(c2_lower_l1_tip_on_same_chain_is_not_a_reorg)
{
    FakeL1Client l1;
    std::deque<uint256> deqChain;
    for (int h = 0; h <= 8; h++) {
        l1.vChain.push_back(ArithToUint256(arith_uint256(0xc2000 + h)));
        deqChain.push_back(l1.vChain.back());
    }
    MainCacheScope cache(deqChain);
    bool fReorg = false;
    std::vector<uint256> vDisconnected;
    BOOST_REQUIRE(UpdateMainBlockHashCache(fReorg, vDisconnected));
    BOOST_REQUIRE(!fReorg);

    // The L1 now reports height 5 of the same chain
    l1.vChain.resize(6);
    BOOST_CHECK(UpdateMainBlockHashCache(fReorg, vDisconnected));
    BOOST_CHECK_MESSAGE(!fReorg && vDisconnected.empty(), "a lower tip on the same chain was handled as a reorg");
    BOOST_CHECK_EQUAL(bmmCache.GetCachedBlockCount(), 9);
    BOOST_CHECK(bmmCache.GetLastMainBlockHash() == deqChain.back());

    // A real reorg (a different block at height 8) is still one
    l1.vChain = std::vector<uint256>(deqChain.begin(), deqChain.end());
    l1.vChain[8] = ArithToUint256(arith_uint256(0xc2f08));
    BOOST_CHECK(UpdateMainBlockHashCache(fReorg, vDisconnected));
    BOOST_CHECK(fReorg);
    BOOST_CHECK(bmmCache.GetLastMainBlockHash() == l1.vChain[8]);
}


// ---------------------------------------------------------------------------
// v0.2.17 C4: when an L1 block is orphaned, a stored FreeBank block anchored
// in it is marked failed even if it is not on the active chain. Only active
// blocks were: the stored one stayed a candidate the BMM check can never
// answer for, and the node kept retrying it instead of its siblings.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(c4_orphaned_l1_block_fails_stored_side_blocks)
{
    PegChain chain(layout, scriptCoinbase);
    FakeL1Client l1;
    std::deque<uint256> deqChain;
    for (int h = 0; h <= 4; h++) {
        l1.vChain.push_back(ArithToUint256(arith_uint256(0xc4000 + h)));
        deqChain.push_back(l1.vChain.back());
    }
    MainCacheScope cache(deqChain);

    // The tip A, and a stored sibling S anchored in L1 block Eorph
    const auto pblockSibling = chain.Block({}, nullptr, true);
    chain.Connect(chain.Block(), "A");
    CBlock blockS = *pblockSibling;
    const uint256 hashOrphan = ArithToUint256(arith_uint256(0xc4f0));
    blockS.hashMainchainBlock = hashOrphan;
    const auto pS = PegChain::Reseal(blockS);
    chain.Process(pS);
    const CBlockIndex* pindexS = nullptr;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(pS->GetHash()));
        pindexS = mapBlockIndex[pS->GetHash()];
        BOOST_REQUIRE(!chainActive.Contains(pindexS));
        BOOST_REQUIRE(pindexS->nStatus & BLOCK_HAVE_DATA);
    }

    HandleMainchainReorg({hashOrphan});
    BOOST_CHECK_MESSAGE(BlockFailedForTest(pS->GetHash()),
        LayoutName(layout) << ": a stored block anchored in an orphaned L1 block was not marked failed");
    BOOST_CHECK(!BlockFailedForTest(TipForTest()->GetBlockHash()));

    // The L1 flips back: Eorph is on the main chain again, and the mark goes
    deqChain.push_back(hashOrphan);
    bmmCache.ReplaceMainBlockCache(deqChain);
    ReconsiderSideBlocksOfReturnedL1Blocks();
    BOOST_CHECK_MESSAGE(!BlockFailedForTest(pS->GetHash()),
        LayoutName(layout) << ": the mark stayed after the L1 block returned");
}


// ---------------------------------------------------------------------------
// v0.2.17 D4: no new BMM bid while the L1 view (the enforcer) is behind its
// own node: the bid would name an L1 block that already has a child.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(d4_no_bid_while_l1_view_behind)
{
    FakeL1Client l1;
    TestL1Oracle oracle;
    for (int h = 0; h <= 3; h++)
        l1.vChain.push_back(ArithToUint256(arith_uint256(0xd4000 + h)));
    MainCacheScope cache(std::deque<uint256>(l1.vChain.begin(), l1.vChain.end()));
    auto Refresh = [&]() {
        SidechainClient client;
        std::string strError;
        uint256 hashCreated, hashConnected, hashConnectedRoot, txid;
        int nTxn = 0;
        CAmount nFees = 0;
        client.RefreshBMM(0, strError, hashCreated, hashConnected, hashConnectedRoot, txid, nTxn, nFees,
                          true /* fCreateNew */, uint256());
        return strError;
    };

    // Behind: refused before a bid block is even built
    l1.fBehind = true;
    BOOST_CHECK_EQUAL(Refresh(), "behind");
    BOOST_CHECK_MESSAGE(l1.nBids == 0, "a bid went out while the L1 view was behind");
    // Caught up: on to building the bid block (this fixture has no wallet to
    // build it with, so it stops there)
    l1.fBehind = false;
    BOOST_CHECK(Refresh() != "behind");
    bmmCache.ClearBMMBlocks();
}


// ---------------------------------------------------------------------------
// v0.2.17 A1 + A4: a deposit record must be on the enforcer's list of its L1
// block: the same outpoint, address and amount; the first ever is the
// treasury's first change; its L1 block on the L1's main chain at or below the
// block's own. Before, only "the tx is in that L1 block" was checked (a cache
// of txids): any tx there could be credited (money from nothing), to any
// address (a deposit redirected), and nothing tied the first to the treasury.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(a1_deposit_must_be_on_the_l1_list)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey alice, mallory;
    const uint256 hashL1a = ArithToUint256(arith_uint256(0xa1)), hashE1 = ArithToUint256(arith_uint256(0xe1));
    const uint256 hashStale = ArithToUint256(arith_uint256(0x5a1e));
    MainCacheScope cache({ArithToUint256(arith_uint256(0xa0)), hashL1a, hashE1});
    uint32_t nBurn = 0;
    const CMutableTransaction dtx = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd1)), 0)},
                                                  5 * COIN, alice.strAddress, nBurn);
    auto Try = [&](const SidechainDeposit& d, bool fDistinct) {
        return OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d); }, fDistinct), hashE1);
    };

    // An unrelated tx in that L1 block, recorded as a deposit: not on the list
    const SidechainDeposit dFake = MakeDepositRecord(dtx, nBurn, alice.strAddress, 5 * COIN, hashL1a);
    chain.oracle.mapWindowEvents[std::make_pair(hashL1a, hashL1a)] = std::make_pair(L1Answer::YES, L1PegEvents());
    chain.Reject(Try(dFake, false), "bad-deposit-l1", "money from nothing");

    // Listed for alice, recorded (and paid) to mallory
    L1ListsDeposit(chain.oracle, dFake, 5 * COIN, 0, alice.strAddress);
    const SidechainDeposit dRedirect = MakeDepositRecord(dtx, nBurn, mallory.strAddress, 5 * COIN, hashL1a);
    chain.Reject(Try(dRedirect, true), "bad-deposit-l1", "a deposit redirected");

    // The L1 recorded 4 COIN deposited, the record's treasury output adds 5
    chain.oracle.mapWindowEvents.clear();
    L1ListsDeposit(chain.oracle, dFake, 4 * COIN, 0);
    chain.Reject(Try(dFake, true), "bad-deposit-l1", "wrong amount");

    // The first record must be the treasury's first change
    chain.oracle.mapWindowEvents.clear();
    L1ListsDeposit(chain.oracle, dFake, 5 * COIN, 3);
    chain.Reject(Try(dFake, true), "bad-deposit-l1", "first record is not the treasury's first");

    // A4: its L1 block is not on the L1's main chain (ours)
    const SidechainDeposit dStale = MakeDepositRecord(dtx, nBurn, alice.strAddress, 5 * COIN, hashStale);
    L1ListsDeposit(chain.oracle, dStale, 5 * COIN, 0);
    chain.Reject(Try(dStale, true), "bad-deposit-l1", "L1 block off the main chain");

    // No answer yet: wait; the same block connects once the L1 answers
    chain.oracle.mapWindowEvents.clear();
    const auto pblock = Try(dFake, true);
    const CBlockIndex* const pindexTip = TipForTest();
    BOOST_CHECK(!chain.Process(pblock).empty());
    BOOST_CHECK(TipForTest() == pindexTip);
    BOOST_CHECK(!BlockFailedForTest(pblock->GetHash()));
    L1ListsDeposit(chain.oracle, dFake, 5 * COIN, 0);
    chain.Connect(pblock, "the real first deposit, once the L1 answers");
    BOOST_CHECK_EQUAL(psidechaintree->GetDeposits(THIS_SIDECHAIN).size(), 1U);
}


// ---------------------------------------------------------------------------
// v0.2.17 A2: deposit and bundle records only in the coinbase. One in an
// ordinary transaction was written to the database unchecked.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(a2_deposit_record_only_in_the_coinbase)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey alice;
    uint32_t nBurn = 0;
    const CMutableTransaction dtx = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd7)), 0)},
                                                  5 * COIN, alice.strAddress, nBurn);
    const SidechainDeposit d = MakeDepositRecord(dtx, nBurn, alice.strAddress, 5 * COIN, ArithToUint256(arith_uint256(0xa1)));
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(chain.Coin(COIN)));
    mtx.vout.push_back(CTxOut(COIN - 20000, CScript() << OP_TRUE));
    mtx.vout.push_back(CTxOut(0, d.GetScript()));
    chain.Reject(chain.Block({MakeTransactionRef(std::move(mtx))}), "bad-sidechain-obj-not-coinbase",
                 "a deposit record in an ordinary transaction");
    BOOST_CHECK(psidechaintree->GetDeposits(THIS_SIDECHAIN).empty());
}

// ---------------------------------------------------------------------------
// v0.2.17 A3 + A8: what the coinbase may pay. A refund and a deposit payout
// can't be settled by one output (the maker kept the other), and a deposit
// owed nothing adds nothing to the limit (the maker took it into vout[0]).
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(a3_a8_coinbase_payouts)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey refunder;
    const uint256 hashL1a = ArithToUint256(arith_uint256(0xa1)), hashL1b = ArithToUint256(arith_uint256(0xa2));
    const uint256 hashE1 = ArithToUint256(arith_uint256(0xe1)), hashE2 = ArithToUint256(arith_uint256(0xe2));
    MainCacheScope cache({ArithToUint256(arith_uint256(0xa0)), hashL1a, hashL1b, hashE1, hashE2});

    // A refundable withdrawal: bundled, the bundle failed
    const CTransactionRef txW = chain.Withdrawal(COIN / 10, refunder.strAddress);
    const SidechainWithdrawal wt = WithdrawalOf(txW);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "bundle");
    chain.L1BundleEvent(bundle.tx.GetHash(), 'F');
    chain.Connect(chain.Block({}, [&](CMutableTransaction& cb) { AddMark(cb, bundle.tx.GetHash(), true); }), "failed");

    // A8: a deposit to an address that does not decode is owed nothing; a
    // coinbase taking its amount into vout[0] pays too much
    uint32_t nBurn1 = 0;
    const CMutableTransaction dtx1 = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd8)), 0)},
                                                   3 * COIN, "not-an-address", nBurn1);
    const SidechainDeposit dUnowed = MakeDepositRecord(dtx1, nBurn1, "not-an-address", 3 * COIN, hashL1a);
    L1ListsDeposit(chain.oracle, dUnowed, 3 * COIN, 0);
    CTxOut owed;
    BOOST_REQUIRE(!GetDepositPayoutOutput(dUnowed, owed));
    chain.Reject(OnL1(chain.Block({}, [&](CMutableTransaction& cb) {
        AddDepositToCoinbase(cb, dUnowed);
        cb.vout[0].nValue += 3 * COIN;
    }), hashE1), "bad-cb-amount", "an unowed deposit taken into vout[0]");
    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, dUnowed); }, true), hashE1),
                  "the unowed deposit, recorded and paid to no one");

    // A3: a refund of the withdrawal and a deposit to the same address for the
    // same amount, settled by one output
    CTxOut refundPayout;
    const CTransactionRef txRefund = RefundRequestTx(chain, wt, refunder.key, refundPayout);
    const CAmount nAmt = refundPayout.nValue + SIDECHAIN_DEPOSIT_FEE;
    uint32_t nBurn2 = 0;
    const CMutableTransaction dtx2 = MakeDepositTx(layout,
        {COutPoint(CTransaction(dtx1).GetHash(), nBurn1), COutPoint(ArithToUint256(arith_uint256(0xd9)), 0)},
        3 * COIN + nAmt, refunder.strAddress, nBurn2);
    const SidechainDeposit dShared = MakeDepositRecord(dtx2, nBurn2, refunder.strAddress, nAmt, hashL1b);
    L1ListsDeposit(chain.oracle, dShared, nAmt, 1);
    BOOST_REQUIRE(GetDepositPayoutOutput(dShared, owed));
    BOOST_REQUIRE(owed == refundPayout);
    chain.Reject(OnL1(chain.Block({txRefund}, [&](CMutableTransaction& cb) {
        AddDepositToCoinbase(cb, dShared); // the one output both would claim
    }), hashE2), "verify-withdrawal-refund-missing-payout", "one output for a refund and a deposit");
    chain.Connect(OnL1(chain.Block({txRefund}, [&](CMutableTransaction& cb) {
        AddDepositToCoinbase(cb, dShared);
        cb.vout.push_back(refundPayout);
    }, true), hashE2), "a refund and a deposit, each paid");
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_SPENT);
}


// ---------------------------------------------------------------------------
// v0.2.17 A9: a problem with the new deposits leaves them out of the block; it
// no longer stops block making. Here the L1 client reports a deposit that does
// not spend the treasury output FreeBank recorded last (no CTIP found): the
// builder returned no template at all.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(a9_builder_builds_without_a_bad_deposit)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey alice, bob;
    const uint256 hashL1a = ArithToUint256(arith_uint256(0xa1)), hashE1 = ArithToUint256(arith_uint256(0xe1));
    MainCacheScope cache({ArithToUint256(arith_uint256(0xa0)), hashL1a, hashE1});
    uint32_t nBurn1 = 0;
    const CMutableTransaction dtx1 = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd1)), 0)},
                                                   5 * COIN, alice.strAddress, nBurn1);
    const SidechainDeposit d1 = MakeDepositRecord(dtx1, nBurn1, alice.strAddress, 5 * COIN, hashL1a);
    L1ListsDeposit(chain.oracle, d1, 5 * COIN, 0);
    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d1); }), hashE1), "first deposit");

    // A new deposit that spends something else than d1's treasury output
    uint32_t nBurn2 = 0;
    const CMutableTransaction dtx2 = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd2)), 0)},
                                                   7 * COIN, bob.strAddress, nBurn2);
    SidechainDeposit d2 = MakeDepositRecord(dtx2, nBurn2, bob.strAddress, 7 * COIN, hashL1a);
    FakeL1Client l1;
    l1.vDepositsToReport = {d2};
    CBlock block;
    std::string strError;
    const bool fBuilt = BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
        std::vector<CMutableTransaction>(), uint256(), scriptCoinbase);
    BOOST_REQUIRE_MESSAGE(fBuilt, LayoutName(layout) << ": no block template: " << strError);
    for (const CTxOut& out : block.vtx[0]->vout) {
        std::vector<unsigned char> vch;
        BOOST_CHECK_MESSAGE(!out.scriptPubKey.IsSidechainObj(vch), LayoutName(layout) << ": the bad deposit went in");
    }
}


// ---------------------------------------------------------------------------
// v0.2.17: crash replay. After an unclean stop the chainstate can be behind
// the sidechain DB (it is flushed now and then; the sidechain DB with every
// block): reconnecting such a block checked it against a DB it had already
// changed, and with the v0.2.17 rules rejected it for good (its bundle "not
// new"): the node forked itself off. The sidechain DB now carries a best-block
// marker written with each block's effects, and a block whose effects are
// already there is not checked or written again.
// Here: bundle block X connected; the chain goes back to X's parent while the
// sidechain DB keeps X's effects (the marker moved away for the disconnect, so
// its undo is skipped, then set back to X); X connects again.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(crash_replay_keeps_sidechain_effects)
{
    PegChain chain(layout, scriptCoinbase);
    const CTransactionRef txW = chain.Withdrawal(COIN / 10);
    const SidechainWithdrawal wt = WithdrawalOf(txW);
    chain.Connect(chain.Block({txW}), "withdrawal");
    const SidechainWithdrawalBundle bundle = ConnectBundleBlock(chain, "X");
    const CBlockIndex* const pindexX = TipForTest();
    uint256 hashMarker;
    BOOST_REQUIRE(psidechaintree->GetBestBlock(hashMarker));
    BOOST_CHECK(hashMarker == pindexX->GetBlockHash());

    // The crash state: the chain at X's parent, the sidechain DB still at X
    BOOST_REQUIRE(psidechaintree->WriteBestBlock(ArithToUint256(arith_uint256(0xdead))));
    InvalidateForTest(pindexX);
    BOOST_REQUIRE(psidechaintree->WriteBestBlock(pindexX->GetBlockHash()));
    BOOST_REQUIRE(HaveBundleRow(bundle));
    BOOST_REQUIRE(LastBundleHash() == bundle.tx.GetHash());

    // X connects again, as the chain replays it
    {
        LOCK(cs_main);
        ResetBlockFailureFlags(const_cast<CBlockIndex*>(pindexX));
    }
    CBlock blockX;
    BOOST_REQUIRE(ReadBlockFromDisk(blockX, pindexX, Params().GetConsensus()));
    chain.Process(std::make_shared<const CBlock>(blockX));
    BOOST_CHECK_MESSAGE(TipForTest() == pindexX, LayoutName(layout) << ": the replayed block did not reconnect ("
                        << (BlockFailedForTest(pindexX->GetBlockHash()) ? "marked failed" : "not failed") << ")");
    SidechainWithdrawalBundle row;
    BOOST_REQUIRE(HaveBundleRow(bundle, &row));
    BOOST_CHECK_EQUAL(row.status, WITHDRAWAL_BUNDLE_CREATED);
    BOOST_CHECK(LastBundleHash() == bundle.tx.GetHash());
    BOOST_CHECK_EQUAL(WithdrawalStatus(wt), WITHDRAWAL_IN_BUNDLE);
    // ... and the chain goes on from it
    chain.Connect(chain.Block(), "X+1");
    BOOST_REQUIRE(psidechaintree->GetBestBlock(hashMarker));
    BOOST_CHECK(hashMarker == TipForTest()->GetBlockHash());
}


// ---------------------------------------------------------------------------
// v0.2.17, from the deposit review: every record in a block spends the
// previous record's treasury output (only the first was checked); a deposit is
// what the enforcer lists as one, whatever its address says; a withdrawal
// return's treasury change is its output 0.
// ---------------------------------------------------------------------------
PEGBIND_BOTH_LAYOUTS(a1_every_record_chains_and_d_is_a_deposit)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey alice, bob;
    const uint256 hashL1a = ArithToUint256(arith_uint256(0xa1)), hashL1b = ArithToUint256(arith_uint256(0xa2));
    const uint256 hashE1 = ArithToUint256(arith_uint256(0xe1)), hashE2 = ArithToUint256(arith_uint256(0xe2));
    MainCacheScope cache({ArithToUint256(arith_uint256(0xa0)), hashL1a, hashL1b, hashE1, hashE2});
    uint32_t nBurn1 = 0;
    const CMutableTransaction dtx1 = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd1)), 0)},
                                                   5 * COIN, alice.strAddress, nBurn1);
    const SidechainDeposit d1 = MakeDepositRecord(dtx1, nBurn1, alice.strAddress, 5 * COIN, hashL1a);
    L1ListsDeposit(chain.oracle, d1, 5 * COIN, 0);
    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d1); }), hashE1), "first deposit");

    // A deposit to the address "D", listed as a deposit: recorded (owed nothing), not a failed return
    uint32_t nBurn2 = 0;
    const CMutableTransaction dtx2 = MakeDepositTx(layout,
        {COutPoint(CTransaction(dtx1).GetHash(), nBurn1), COutPoint(ArithToUint256(arith_uint256(0xd2)), 0)},
        7 * COIN, SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST, nBurn2);
    const SidechainDeposit dD = MakeDepositRecord(dtx2, nBurn2, SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST, 2 * COIN, hashL1b);
    L1ListsDeposit(chain.oracle, dD, 2 * COIN, 1);

    // The same record twice in one block: the second does not spend the first's treasury output
    SidechainDeposit dAgain = dD;
    dAgain.amtUserPayout = 0;
    chain.Reject(OnL1(chain.Block({}, [&](CMutableTransaction& cb) {
        AddDepositToCoinbase(cb, dD);
        AddDepositToCoinbase(cb, dAgain);
    }), hashE2), "invalid-deposit-input", "a record repeated in one block");

    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, dD); }, true), hashE2),
                  "a deposit to the address D");
    BOOST_CHECK_EQUAL(psidechaintree->GetDeposits(THIS_SIDECHAIN).size(), 2U);
}

// Withdrawal returns (the CUSF layout: an M6 has its treasury change at
// output 0). The treasury X (5 COIN) is paid down by bundle payout P (1 COIN
// out), then refilled by deposit D (1 COIN in). A block [P, D, P, D] credited D
// twice (P's m6id recomputes the same once D restores the treasury): each
// record now spends the previous one's treasury output.
BOOST_AUTO_TEST_CASE(a1_withdrawal_return_and_its_cycle)
{
    const Layout layout = Layout::CUSF;
    PegChain chain(layout, GetCoinbaseScript());
    const TestKey alice, bob;
    const uint256 hashL1a = ArithToUint256(arith_uint256(0xa1)), hashL1b = ArithToUint256(arith_uint256(0xa2));
    const uint256 hashE1 = ArithToUint256(arith_uint256(0xe1)), hashE2 = ArithToUint256(arith_uint256(0xe2));
    MainCacheScope cache({ArithToUint256(arith_uint256(0xa0)), hashL1a, hashL1b, hashE1, hashE2});
    uint32_t nBurn1 = 0;
    const CMutableTransaction dtx1 = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd1)), 0)},
                                                   5 * COIN, alice.strAddress, nBurn1);
    const SidechainDeposit d1 = MakeDepositRecord(dtx1, nBurn1, alice.strAddress, 5 * COIN, hashL1a);
    L1ListsDeposit(chain.oracle, d1, 5 * COIN, 0);
    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d1); }), hashE1), "X");

    // P: the M6 paying 1 COIN out of X
    const CAmount nFee = 1000;
    CMutableTransaction m6;
    m6.nVersion = 2;
    m6.vin.push_back(CTxIn(COutPoint(CTransaction(dtx1).GetHash(), nBurn1)));
    m6.vout.push_back(CTxOut(4 * COIN - nFee, TreasuryScript(layout)));
    m6.vout.push_back(CTxOut(COIN, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x42) << OP_EQUALVERIFY << OP_CHECKSIG));
    uint256 m6id;
    BOOST_REQUIRE(ComputeM6id(m6, 5 * COIN, THIS_SIDECHAIN, m6id));
    SidechainDeposit ret;
    ret.nSidechain = THIS_SIDECHAIN;
    ret.strDest = SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST;
    ret.dtx = m6;
    ret.nBurnIndex = 0;
    ret.amtUserPayout = 0;
    ret.hashMainchainBlock = hashL1b;
    {
        auto& entry = chain.oracle.mapWindowEvents[std::make_pair(hashL1b, hashL1b)];
        entry.first = L1Answer::YES;
        L1WithdrawalEvent ev;
        ev.m6id = m6id;
        ev.status = 'S';
        ev.hashMainBlock = hashL1b;
        ev.fHaveSequence = true;
        ev.nSequence = 1;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << L1MutableTransaction(m6);
        ev.vchTx.assign(ss.begin(), ss.end());
        entry.second.vWithdrawal.push_back(ev);
    }
    // D: bob deposits exactly what P took out (1 COIN and the fee), spending
    // P's treasury output: the treasury is back at 5 COIN
    uint32_t nBurn3 = 0;
    const CMutableTransaction dtx3 = MakeDepositTx(layout,
        {COutPoint(CTransaction(m6).GetHash(), 0), COutPoint(ArithToUint256(arith_uint256(0xd3)), 0)},
        5 * COIN, bob.strAddress, nBurn3);
    const SidechainDeposit d3 = MakeDepositRecord(dtx3, nBurn3, bob.strAddress, COIN + nFee, hashL1b);
    L1ListsDeposit(chain.oracle, d3, COIN + nFee, 2);

    // The cycle: [P, D, P, D]
    chain.Reject(OnL1(chain.Block({}, [&](CMutableTransaction& cb) {
        AddDepositToCoinbase(cb, ret);
        AddDepositToCoinbase(cb, d3);
        AddDepositToCoinbase(cb, ret);
        AddDepositToCoinbase(cb, d3);
    }), hashE2), "invalid-deposit-input", "a payout and a deposit repeated");

    // A copy of P with another input sequence: the same m6id, another txid
    SidechainDeposit retCopy = ret;
    retCopy.dtx.vin[0].nSequence = 0xfffffffe;
    BOOST_REQUIRE(retCopy.dtx.GetHash() != ret.dtx.GetHash());
    uint256 m6idCopy;
    BOOST_REQUIRE(ComputeM6id(retCopy.dtx, 5 * COIN, THIS_SIDECHAIN, m6idCopy) && m6idCopy == m6id);
    chain.Reject(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, retCopy); }, true), hashE2),
                 "bad-deposit-l1", "a copy of the payout with another input");

    // A return that names output 1 as its treasury change
    SidechainDeposit retBad = ret;
    retBad.nBurnIndex = 1;
    chain.Reject(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, retBad); }, true), hashE2),
                 "bad-deposit-l1", "a return with its treasury change at output 1");

    // The honest block: [P, D]
    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) {
        AddDepositToCoinbase(cb, ret);
        AddDepositToCoinbase(cb, d3);
    }, true), hashE2), "the payout, then the deposit");
    BOOST_CHECK_EQUAL(psidechaintree->GetDeposits(THIS_SIDECHAIN).size(), 3U);
}


// Crash replay of a deposit block: after the replay the DB's deposit pointer
// is the block's as-of value (checked when the last replayed block connects),
// and the next deposit chains on it.
PEGBIND_BOTH_LAYOUTS(crash_replay_of_a_deposit_block)
{
    PegChain chain(layout, scriptCoinbase);
    const TestKey alice, bob;
    const uint256 hashL1a = ArithToUint256(arith_uint256(0xa1)), hashL1b = ArithToUint256(arith_uint256(0xa2));
    const uint256 hashE1 = ArithToUint256(arith_uint256(0xe1)), hashE2 = ArithToUint256(arith_uint256(0xe2));
    MainCacheScope cache({ArithToUint256(arith_uint256(0xa0)), hashL1a, hashL1b, hashE1, hashE2});
    uint32_t nBurn1 = 0;
    const CMutableTransaction dtx1 = MakeDepositTx(layout, {COutPoint(ArithToUint256(arith_uint256(0xd1)), 0)},
                                                   5 * COIN, alice.strAddress, nBurn1);
    const SidechainDeposit d1 = MakeDepositRecord(dtx1, nBurn1, alice.strAddress, 5 * COIN, hashL1a);
    L1ListsDeposit(chain.oracle, d1, 5 * COIN, 0);
    const auto pblockX = OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d1); }), hashE1);
    chain.Connect(pblockX, "X: first deposit");
    const CBlockIndex* const pindexX = TipForTest();

    // The crash state, then X again
    BOOST_REQUIRE(psidechaintree->WriteBestBlock(ArithToUint256(arith_uint256(0xdead))));
    InvalidateForTest(pindexX);
    BOOST_REQUIRE(psidechaintree->WriteBestBlock(pindexX->GetBlockHash()));
    {
        LOCK(cs_main);
        ResetBlockFailureFlags(const_cast<CBlockIndex*>(pindexX));
    }
    chain.Process(pblockX);
    BOOST_REQUIRE_MESSAGE(TipForTest() == pindexX, LayoutName(layout) << ": the replayed deposit block did not reconnect");
    uint256 hashPtr;
    BOOST_REQUIRE(psidechaintree->GetLastDepositID(hashPtr));
    BOOST_CHECK(hashPtr == d1.GetID());
    BOOST_CHECK(pindexX->hashLastDeposit == d1.GetID());

    // The next deposit chains on it
    uint32_t nBurn2 = 0;
    const CMutableTransaction dtx2 = MakeDepositTx(layout,
        {COutPoint(CTransaction(dtx1).GetHash(), nBurn1), COutPoint(ArithToUint256(arith_uint256(0xd2)), 0)},
        7 * COIN, bob.strAddress, nBurn2);
    const SidechainDeposit d2 = MakeDepositRecord(dtx2, nBurn2, bob.strAddress, 2 * COIN, hashL1b);
    L1ListsDeposit(chain.oracle, d2, 2 * COIN, 1);
    chain.Connect(OnL1(chain.Block({}, [&](CMutableTransaction& cb) { AddDepositToCoinbase(cb, d2); }), hashE2), "the next deposit");
    BOOST_CHECK_EQUAL(psidechaintree->GetDeposits(THIS_SIDECHAIN).size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
