// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// testing (2026-11-26): Stage 0 family B (D-2026-11-26-1; security's rule B, inbox note
// 2026-11-26-from-security-family-rules: "a block's validity and effects don't depend on the order of non-dependent
// txs; reads go through block start unless the writer is an ancestor or a slot keeps the two apart").
//
// The harness: OrderChain mines the SAME transactions in two orders on the same parent, through the node's own entry
// point (ProcessNewBlock -> ConnectBlock, as pegbind_tests does; sidechain_test::ProcessBlockWithoutMainchain skips
// only the L1/BMM checks), with the side DBs in memory. Between the two it invalidates the first block, so the second
// order connects from the same state. A pair is order-independent when both orders get the same verdict and leave the
// same snapshot (the credit records the case names). A producer can order a block's transactions any way it likes,
// so every order counts, not only the ones an honest template makes.

#include <bill.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <house.h>
#include <houserate.h>
#include <issued.h>
#include <key.h>
#include <keystore.h>
#include <miner.h>
#include <note.h>
#include <script/sign.h>
#include <script/standard.h>
#include <test/sidechain_test_util.h>
#include <test/test_bitcoin.h>
#include <streams.h>
#include <txmempool.h>
#include <units.h>
#include <util.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <functional>

using namespace sidechain_test;

BOOST_FIXTURE_TEST_SUITE(order_permutation_tests, TestChain100Setup)

namespace {
struct OrderChain {
    RegtestFamilyScope family;
    SideDBScope sideDBs;
    BlockCheckedRecorder checked;
    const CScript scriptCoinbase = CScript() << OP_TRUE;

    /** The miner's own template on the tip (empty mempool: coinbase only), then vtx in the order given. */
    std::shared_ptr<const CBlock> Block(const std::vector<CTransactionRef>& vtx)
    {
        CBlock block;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
            std::vector<CMutableTransaction>(), uint256(), scriptCoinbase), strError);
        BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);
        {
            LOCK(cs_main);
            block.nTime = chainActive.Tip()->GetMedianTimePast() + 1;
        }
        for (const CTransactionRef& tx : vtx)
            block.vtx.push_back(tx);
        block.hashMerkleRoot = BlockMerkleRoot(block);
        return std::make_shared<const CBlock>(block);
    }

    /** Mine vtx in this order; "" = connected (and it stays the tip). */
    std::string Mine(const std::vector<CTransactionRef>& vtx)
    {
        const std::shared_ptr<const CBlock> pblock = Block(vtx);
        ProcessBlockWithoutMainchain(pblock);
        const std::string r = checked.Reason(pblock->GetHash());
        if (r.empty())
            BOOST_REQUIRE(TipForTest()->GetBlockHash() == pblock->GetHash());
        return r;
    }

    /** Back to the parent of the tip (invalidateblock's path: DisconnectTip -> DisconnectBlock). */
    void Undo()
    {
        CValidationState state;
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive.Tip();
        BOOST_REQUIRE_MESSAGE(InvalidateBlock(state, Params(), pindex), "Undo: InvalidateBlock failed: " + FormatStateMessage(state));
        BOOST_REQUIRE(chainActive.Tip() == pindex->pprev);
        mempool.clear();   // the disconnected txs come back to the pool; the next template must be coinbase-only
    }

    struct Outcome {
        std::string strVerdict;   // "" = connected
        std::string strSnapshot;  // the case's own snapshot, taken only when connected
    };

    /** Both orders of {a, b} from the same parent. fnSnapshot describes the state the case cares about. */
    std::pair<Outcome, Outcome> BothOrders(const CTransactionRef& a, const CTransactionRef& b,
                                           const std::function<std::string()>& fnSnapshot)
    {
        Outcome ab, ba;
        ab.strVerdict = Mine({a, b});
        if (ab.strVerdict.empty()) {
            ab.strSnapshot = fnSnapshot();
            Undo();
        }
        ba.strVerdict = Mine({b, a});
        if (ba.strVerdict.empty()) {
            ba.strSnapshot = fnSnapshot();
            Undo();
        }
        return {ab, ba};
    }
};

std::string Said(const std::string& r) { return r.empty() ? std::string("connected") : "refused (" + r + ")"; }

/** A spend of an OP_TRUE coin to `script`, paying `fee`. */
CTransactionRef Spend(const COutPoint& in, CAmount nIn, const CScript& script, CAmount fee = 10000)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(in));
    mtx.vout.push_back(CTxOut(nIn - fee, script));
    return MakeTransactionRef(std::move(mtx));
}

/** ORDER_TEST_LOG=1 prints the node log (ConnectBlock's reject lines) for one case. */
struct OrderTestLog {
    bool f;
    OrderTestLog() : f(fPrintToConsole) { fPrintToConsole = getenv("ORDER_TEST_LOG") != nullptr; }
    ~OrderTestLog() { fPrintToConsole = f; }
};

/** The till as consensus counts it (attested sECX at the 30-day high ask) for one case, not the suite's pre-gram
 *  emulation (test_bitcoin.cpp: reserves / 5). The rate override stays: every bid and ask is 1,000 sats a gram. */
struct RealCapitalScope {
    std::function<void(const CHouse&, int, CHouseCapital&)> f;
    RealCapitalScope() : f(g_fnCapitalForChecksTestOverride) { g_fnCapitalForChecksTestOverride = nullptr; }
    ~RealCapitalScope() { g_fnCapitalForChecksTestOverride = f; }
};

/** Units records written as a connected block leaves them: through a view, with the marker kept at the tip. */
void WriteUnitsAtTip(const std::function<void(CUnitsView&)>& fnWrite)
{
    LOCK(cs_main);
    CUnitsView v(punitsdb.get());
    fnWrite(v);
    std::map<UnitsKey, UnitsSlot> mapChange, mapBefore;
    v.GetChanges(mapChange, mapBefore);
    BOOST_REQUIRE(punitsdb->WriteBlock(mapChange, mapBefore, chainActive.Tip()->GetBlockHash()));
}

/** A Stressed house (an unpaid demand protested at nTip: the cure is running) with nMinted mg of notes out and
 *  amountTill sats attested at nTip. Registered at block 1. */
CHouse StressedHouseForTest(uint32_t nHouseID, const uint256& houseID, const std::string& strClassID, uint64_t nMinted,
                            CAmount amountTill, int nTip)
{
    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = houseID;
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = strClassID;
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1;
    house.nMintedUnits = nMinted;
    house.nLastAttestHeight = (uint32_t)nTip;
    house.amountLastAttestReserves = amountTill;
    house.nProtestOpen = 1;
    house.nProtestHeight = (uint32_t)nTip;
    house.nProtestDemandHeight = 1;
    return house;
}

/** A holder's undemanded note coin of nUnits on its P2PKH (height 1: undo needs a height above 0). */
COutPoint NoteCoinForTest(const uint256& hash, uint32_t nHouseID, uint64_t nUnits, const std::vector<unsigned char>& vchHolder)
{
    const COutPoint out(hash, 0);
    LOCK(cs_main);
    Coin c(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchHolder)), 1, false, false, false, uint256());
    c.SetNote(nHouseID, nUnits);
    pcoinsTip->AddCoin(out, std::move(c), false);
    return out;
}

// Stage 0 rule C1 (freebankd's mb/stage0-bc) moved these digests to the whole-tx helper (CreditTxSigHash: the op, the
// payload without its signature fields, every prevout, nSequence, nLockTime and output). The shims pick the form the tree
// has, so the cases build before and after; for the new form the payload must already be in the tx.
inline uint256 RedeemDigestAny(uint256 (*f)(const CTransaction&), uint32_t, uint64_t, const CMutableTransaction& mtx)
{
    return f(CTransaction(mtx));
}
inline uint256 RedeemDigestAny(uint256 (*f)(uint32_t, uint64_t, const uint256&), uint32_t nHouse, uint64_t nUnits,
                               const CMutableTransaction& mtx)
{
    return f(nHouse, nUnits, BillHashOutputs(CTransaction(mtx)));
}
inline uint256 DemandDigestAny(uint256 (*f)(const CTransaction&), uint32_t, const std::vector<uint64_t>&, const CMutableTransaction& mtx)
{
    return f(CTransaction(mtx));
}
inline uint256 DemandDigestAny(uint256 (*f)(uint32_t, const std::vector<uint64_t>&, const uint256&), uint32_t nHouse,
                               const std::vector<uint64_t>& vUnits, const CMutableTransaction& mtx)
{
    return f(nHouse, vUnits, BillHashOutputs(CTransaction(mtx)));
}
inline uint256 ClaimDigestAny(uint256 (*f)(const CTransaction&, const uint256&, bool, const uint256&), const uint256& billID,
                              const CMutableTransaction& mtx)
{
    return f(CTransaction(mtx), billID, false, uint256());   // op 4 names no house (R5-15 binds op 8's)
}
inline uint256 ClaimDigestAny(uint256 (*f)(const uint256&, const uint256&, const uint256&, bool), const uint256& billID,
                              const CMutableTransaction& mtx)
{
    const CTransaction tx(mtx);
    return f(billID, BillTxBindingHash(tx), BillHashOutputs(tx), false);
}
inline uint256 RecourseDigestAny(uint256 (*f)(const CTransaction&, const uint256&), const BillRecourse&, const uint256& billID,
                                 const CMutableTransaction& mtx)
{
    return f(CTransaction(mtx), billID);
}
inline uint256 RecourseDigestAny(uint256 (*f)(const BillRecourse&, const uint256&, const uint256&, const uint256&),
                                 const BillRecourse& x, const uint256& billID, const CMutableTransaction& mtx)
{
    const CTransaction tx(mtx);
    return f(x, billID, BillHashPrevouts(tx), BillHashOutputs(tx));
}

/** A holder-signed REDEEM of the note coin noteIn (nUnits) as CWallet::RedeemNote builds it, at the suite's 1,000 sats a
 *  gram: vout[0] the payout to the holder, vout[1] the spread to the escrow pot (when amountSpread > 0), then change from
 *  the 1-coin OP_TRUE fund. The note input is signed last (its digest binds the payload). */
CTransactionRef RedeemTxForTest(uint32_t nHouseID, const uint256& houseID, uint64_t nUnits, CAmount amountSpread,
                                const CKey& keyHolder, const COutPoint& noteIn, const COutPoint& fund)
{
    const CPubKey pub = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchHolder(pub.begin(), pub.end());
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vin.push_back(CTxIn(noteIn));
    mtx.vin.push_back(CTxIn(fund));
    mtx.vout.push_back(CTxOut((CAmount)nUnits, NoteScriptForPubKey(vchHolder)));
    if (amountSpread > 0)
        mtx.vout.push_back(CTxOut(amountSpread, HouseEscrowScript(houseID)));
    mtx.vout.push_back(CTxOut(1 * COIN + NOTE_DUST_VALUE - (CAmount)nUnits - amountSpread - 20000, CScript() << OP_TRUE));
    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = amountSpread > 0 ? 1 : 0;
    redeem.vchHolderPubKey = vchHolder;
    redeem.nRateNamed = 1000;
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
        mtx.vchNotePayload.assign(ss.begin(), ss.end());   // first: the whole-tx digest reads the payload
    }
    BOOST_REQUIRE(keyHolder.Sign(RedeemDigestAny(&NoteRedeemSigHash, nHouseID, nUnits, mtx), redeem.vchHolderSig));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload.assign(ss.begin(), ss.end());
    CBasicKeyStore keystore;
    keystore.AddKey(keyHolder);
    BOOST_REQUIRE(SignSignature(keystore, NoteScriptForPubKey(vchHolder), mtx, 0, NOTE_DUST_VALUE, SIGHASH_ALL));
    return MakeTransactionRef(std::move(mtx));
}

// testing/stage0 predates master's S1X-35 (the DEFER digest binds the prevouts) and S1X-42 (a pre-auth demand's id
// binds its unit vector and payout: NoteDemandId). These take whichever the tree has, so the cases build on both.
inline uint256 DeferSigHashAny(uint256 (*f)(const uint256&, uint32_t, const uint256&, const uint256&), const uint256& houseID,
                        uint32_t nPrev, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    return f(houseID, nPrev, hashPrevouts, hashOutputs);
}
inline uint256 DeferSigHashAny(uint256 (*f)(const uint256&, uint32_t, const uint256&), const uint256& houseID, uint32_t nPrev,
                        const uint256&, const uint256& hashOutputs)
{
    return f(houseID, nPrev, hashOutputs);
}
template <typename Tx>
auto DemandIdAny(const Tx& tx, const std::vector<uint64_t>& vUnits, const std::vector<unsigned char>& vchPayout, int)
    -> decltype(NoteDemandId(tx, vUnits, vchPayout))
{
    return NoteDemandId(tx, vUnits, vchPayout);
}
template <typename Tx>
uint256 DemandIdAny(const Tx& tx, const std::vector<uint64_t>&, const std::vector<unsigned char>&, long)
{
    return NoteHashPrevouts(tx);
}
} // namespace

// The harness itself: two independent plain spends connect in both orders and leave the same coins.
BOOST_AUTO_TEST_CASE(order_harness_control_independent_spends)
{
    OrderChain chain;
    const COutPoint c1 = FundCoinForTest(9001, 5 * COIN), c2 = FundCoinForTest(9002, 7 * COIN);
    const CTransactionRef a = Spend(c1, 5 * COIN, CScript() << OP_TRUE << OP_DROP << OP_TRUE);
    const CTransactionRef b = Spend(c2, 7 * COIN, CScript() << OP_TRUE << OP_DROP << OP_TRUE);
    auto snap = [&]() {
        LOCK(cs_main);
        std::string s;
        for (const CTransactionRef& tx : {a, b})
            s += pcoinsTip->HaveCoin(COutPoint(tx->GetHash(), 0)) ? "1" : "0";
        return s;
    };
    const auto r = chain.BothOrders(a, b, snap);
    BOOST_CHECK_MESSAGE(r.first.strVerdict.empty() && r.second.strVerdict.empty(),
                        "control: [a,b] " + Said(r.first.strVerdict) + ", [b,a] " + Said(r.second.strVerdict));
    BOOST_CHECK_EQUAL(r.first.strSnapshot, "11");
    BOOST_CHECK_EQUAL(r.first.strSnapshot, r.second.strSnapshot);
}

// B pair P4 (testing 2026-11-26, from the in-block read/write map on master 943d199): a bill's CLAIM (the holder takes
// the bond after the grace deadline) and a RECOURSE (an endorser or the drawer pays the holder max(face, bond) and takes
// the bill, escrow claim included). Mempool keeps them apart with the per-bill guard (validation.cpp ~2423-2492, whose
// comment says no two bill ops ride one block in either order), but consensus has no per-bill slot:
//   [RECOURSE, CLAIM]: the holder is now the payer, so the old holder's CLAIM fails its signature.
//   [CLAIM, RECOURSE]: the bill is DEFAULTED and the holder unchanged; the payer's RECOURSE, signed against the ACTIVE
//   bill, still clears the DEFAULTED floor (face - bond), so both connect: the holder keeps the bond AND the recourse
//   payment, and the payer pays face for a bill whose bond is gone.
// A holder who produces the block (BMM) picks the second order. Rule B: same verdict in both orders.
// FAILS on master (the orders differ: [CLAIM, RECOURSE] connects, [RECOURSE, CLAIM] is refused).
BOOST_AUTO_TEST_CASE(order_bill_claim_and_recourse)
{
    OrderChain chain;
    struct ConsoleLog { bool f; ConsoleLog() : f(fPrintToConsole) { fPrintToConsole = getenv("ORDER_TEST_LOG") != nullptr; } ~ConsoleLog() { fPrintToConsole = f; } } consoleLog;
    CKey keyDrawer, keyAcceptor, keyHolder;
    keyDrawer.MakeNewKey(true); keyAcceptor.MakeNewKey(true); keyHolder.MakeNewKey(true);
    auto pub = [](const CKey& k) { const CPubKey p = k.GetPubKey(); return std::vector<unsigned char>(p.begin(), p.end()); };

    const COutPoint escrow(uint256S("b4e0"), 0);
    CBill bill;
    bill.nBillID = 1;
    bill.billID = uint256S("b4b1");
    bill.amount = 10000;                // 10 g of face: 10,000 sats at the suite's 1,000 sats a gram
    bill.amountEscrow = 4000;           // the bond, below the face: a deficiency exists once defaulted
    bill.nIssuedHeight = 0;
    bill.nMaturityHeight = 0;
    bill.nGraceBlocks = 0;
    bill.vchDrawerPubKey = pub(keyDrawer);
    bill.vchAcceptorPubKey = pub(keyAcceptor);
    bill.vchHolderPubKey = pub(keyHolder);
    bill.nRefHouseID = 5;
    bill.nOwnerHouseID = 0;
    bill.status = BILL_STATUS_ACTIVE;
    bill.outEscrow = escrow;
    bill.outTitle = COutPoint(uint256S("b4f1"), 0);
    BOOST_REQUIRE(pbilltree->WriteBills({bill}));
    BOOST_REQUIRE(pbilltree->WriteLastBillID(1));
    {
        LOCK(cs_main);
        Coin c(CTxOut(bill.amountEscrow, BillEscrowScript(bill.billID)), 1, false, false, false, uint256());   // height > 0: undo needs it
        c.SetBill(true, bill.nBillID);
        pcoinsTip->AddCoin(escrow, std::move(c), false);
    }

    // The holder's CLAIM of the bond.
    BillClaim claim;
    claim.nBillID = 1;
    CMutableTransaction mtxClaim;
    mtxClaim.nVersion = TRANSACTION_BILL_VERSION;
    mtxClaim.nBillOp = BILL_OP_CLAIM;
    mtxClaim.vin.push_back(CTxIn(escrow));
    mtxClaim.vout.push_back(CTxOut(3000, BillScriptForPubKey(pub(keyHolder))));
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << claim;
        mtxClaim.vchBillPayload.assign(ss.begin(), ss.end());
    }
    BOOST_REQUIRE(keyHolder.Sign(ClaimDigestAny(&BillClaimSigHash, bill.billID, mtxClaim), claim.vchHolderSig));
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << claim;
        mtxClaim.vchBillPayload.assign(ss.begin(), ss.end());
    }

    // The drawer's RECOURSE, paying the holder max(face at the ask, bond) = 10,000 sats.
    const COutPoint fund = FundCoinForTest(9101, 1 * COIN);
    BillRecourse rec;
    rec.nBillID = 1;
    rec.vchPayerPubKey = pub(keyDrawer);
    rec.vchPrevHolderPubKey = pub(keyHolder);
    rec.nRateNamed = 1000;
    CMutableTransaction mtxRec;
    mtxRec.nVersion = TRANSACTION_BILL_VERSION;
    mtxRec.nBillOp = BILL_OP_RECOURSE;
    mtxRec.vin.push_back(CTxIn(fund));
    mtxRec.vout.push_back(CTxOut(10000, BillScriptForPubKey(pub(keyHolder))));
    mtxRec.vout.push_back(CTxOut(1 * COIN - 10000 - 20000, CScript() << OP_TRUE));
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << rec;
        mtxRec.vchBillPayload.assign(ss.begin(), ss.end());   // first: the whole-tx digest reads the payload
    }
    BOOST_REQUIRE(keyDrawer.Sign(RecourseDigestAny(&BillRecourseSigHash, rec, bill.billID, mtxRec), rec.vchPayerSig));
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << rec;
        mtxRec.vchBillPayload.assign(ss.begin(), ss.end());
    }

    const CTransactionRef txClaim = MakeTransactionRef(mtxClaim), txRec = MakeTransactionRef(mtxRec);
    auto snap = [&]() {
        CBill b;
        BOOST_REQUIRE(pbilltree->GetBill(1, b));
        return strprintf("status %c, holder %s", b.status, b.vchHolderPubKey == pub(keyDrawer) ? "drawer" : "holder");
    };
    // Each alone (controls): both are valid against the ACTIVE bill.
    BOOST_REQUIRE_MESSAGE(chain.Mine({txClaim}).empty(), "P4 setup: the CLAIM alone does not connect");
    chain.Undo();
    BOOST_REQUIRE_MESSAGE(chain.Mine({txRec}).empty(), "P4 setup: the RECOURSE alone does not connect");
    chain.Undo();
    const auto r = chain.BothOrders(txClaim, txRec, snap);
    BOOST_CHECK_MESSAGE(r.first.strVerdict.empty() == r.second.strVerdict.empty() &&
                            r.first.strSnapshot == r.second.strSnapshot,
                        "P4 (rule B): [CLAIM, RECOURSE] " + Said(r.first.strVerdict) +
                            (r.first.strVerdict.empty() ? " -> " + r.first.strSnapshot : std::string()) +
                            "; [RECOURSE, CLAIM] " + Said(r.second.strVerdict) +
                            (r.second.strVerdict.empty() ? " -> " + r.second.strSnapshot : std::string()) +
                            ". In the first order the holder keeps the bond and the recourse payment");
}

// B pair P1 (testing 2026-11-26, from the in-block map; S1X-33): a SWAP_DONE (anyone posts the swap's preimage; a note
// op that takes no house slot) and a holder's REDEEM at the same house. DONE takes the swap's units out of the house's
// pending swaps W (houserate.cpp SwapSettle), and the REDEEM's exact brassage spread reads W through the block-so-far
// units view (GoldBrassageAmount -> GoldTillRatioBps -> HouseOwedOutsideNotesMg). The house: Stressed (a live protest),
// 100 g of notes out, a 50 g swap pending, a 2 g till fresh at the suite's 1,000 sats a gram: 1.33% at block start, the
// 2% floor exactly once the swap is done. The REDEEM of 10 g is built as the wallet builds it, against block start:
// 10,000 sats to the holder and the 80 mg spread (80 sats) to the escrow pot.
//   [REDEEM, DONE]: the REDEEM sees W, owes the 80 mg and pays it; both connect.
//   [DONE, REDEEM]: W is gone when the REDEEM is checked, it owes no spread, and its escrow output is refused
//   (bad-note-redeem-brassage-unexpected): the block is invalid. A REDEEM built with no spread is the mirror (valid
//   only after the DONE).
// Mempool keeps the pair in the first order only by the template's last pass for DONE (73fd4a9, template only); a
// producer orders its own block. Rule B: same verdict in both orders.
// FAILS on master (the orders differ: [REDEEM, DONE] connects, [DONE, REDEEM] is refused).
BOOST_AUTO_TEST_CASE(order_swap_done_and_redeem)
{
    OrderChain chain;
    struct ConsoleLog { bool f; ConsoleLog() : f(fPrintToConsole) { fPrintToConsole = getenv("ORDER_TEST_LOG") != nullptr; } ~ConsoleLog() { fPrintToConsole = f; } } consoleLog;
    // The till as consensus counts it (attested sECX at the 30-day high ask), not the suite's pre-gram emulation
    // (test_bitcoin.cpp: reserves / 5). The rate override stays: every bid and ask is 1,000 sats a gram.
    struct RealCapital {
        std::function<void(const CHouse&, int, CHouseCapital&)> f;
        RealCapital() : f(g_fnCapitalForChecksTestOverride) { g_fnCapitalForChecksTestOverride = nullptr; }
        ~RealCapital() { g_fnCapitalForChecksTestOverride = f; }
    } realCapital;
    BOOST_REQUIRE_EQUAL(g_nHouseRateTestOverride, 1000U);

    // Two empty blocks first: the chain clock starts, and the attestation and protest can sit in the past.
    BOOST_REQUIRE_MESSAGE(chain.Mine({}).empty(), "P1 setup: empty block 1");
    BOOST_REQUIRE_MESSAGE(chain.Mine({}).empty(), "P1 setup: empty block 2");
    const int nTip = TipForTest()->nHeight, H = nTip + 1;   // the pair's block

    CKey keyHolder;
    keyHolder.MakeNewKey(true);
    const CPubKey pubHolder = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchHolder(pubHolder.begin(), pubHolder.end());
    CBasicKeyStore keystore;
    keystore.AddKey(keyHolder);

    const uint32_t nHouse = 7;
    const uint64_t N = 100000, W = 50000, U = 10000;   // mg: notes out, the pending swap, the redemption
    const CAmount amountTill = 2000;                   // sats attested: 2,000 mg at 1,000 sats a gram
    CHouse house;
    house.nHouseID = nHouse;
    house.houseID = uint256S("b1d0");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "orderp1";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1;
    house.nMintedUnits = N;
    house.nLastAttestHeight = (uint32_t)nTip;          // fresh: attested at the tip
    house.amountLastAttestReserves = amountTill;
    house.nProtestOpen = 1;                            // an unpaid demand protested: Stressed (the cure is running)
    house.nProtestHeight = (uint32_t)nTip;
    house.nProtestDemandHeight = 1;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(phousetree->WriteHouse(house));
        BOOST_REQUIRE(phousetree->WriteLastHouseID(nHouse));
    }

    // The pending swap of 50 g (opened while the house was Open: S1X-31 admits a swap only where no spread is owed).
    std::vector<unsigned char> vchPreimage(32, 0x5d);
    uint256 hashLock;
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(hashLock.begin());
    {
        LOCK(cs_main);
        CUnitsView v(punitsdb.get());
        CChainClock clock;
        BOOST_REQUIRE(GetChainClock(v, clock));
        CSwapRecord rec;
        rec.nHouseID = nHouse;
        rec.nUnits = W;
        rec.nChainID = 1;
        rec.vchContract.assign(20, 0xc0);
        rec.vchEthAddress.assign(20, 0xea);
        CKey keySwapper;
        keySwapper.MakeNewKey(true);
        const CScript scriptSwapPayout = GetScriptForDestination(keySwapper.GetPubKey().GetID());
        rec.vchPayoutScript.assign(scriptSwapPayout.begin(), scriptSwapPayout.end());
        rec.nBid0 = 1000;
        rec.nDemandHeight = 1;
        rec.nDeadlineActive = clock.nActiveTime + (int64_t)Params().GetConsensus().GramAt(H).nSwapDeadlineSecs;
        rec.nStatus = SWAP_PENDING;
        v.Put(SwapKey(hashLock), rec);
        v.Put(SwapPendingKey(nHouse), W);
        std::map<UnitsKey, UnitsSlot> mapChange, mapBefore;
        v.GetChanges(mapChange, mapBefore);
        BOOST_REQUIRE(punitsdb->WriteBlock(mapChange, mapBefore, TipForTest()->GetBlockHash()));   // marker stays at the tip
    }

    // The holder's note coin of 10 g.
    const COutPoint noteIn(uint256S("b1a7"), 0);
    {
        LOCK(cs_main);
        Coin c(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchHolder)), 1, false, false, false, uint256());   // height > 0: undo
        c.SetNote(nHouse, U);
        pcoinsTip->AddCoin(noteIn, std::move(c), false);
    }

    // Block start, as the wallet reads it: Stressed, 133 bps (2,000 / 150,000), 80 mg of spread on 10 g. With the swap
    // done (the view a REDEEM after the DONE sees): 200 bps (2,000 / 100,000), the floor, no spread.
    CAmount amountSpread = 0;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
        BOOST_REQUIRE_EQUAL(HousePendingSwapUnitsForChecks(nHouse), W);
        BOOST_REQUIRE_EQUAL(GoldTillRatioBps(house, H), 133U);
        amountSpread = GoldBrassageAmount(house, H, U);
        BOOST_REQUIRE_EQUAL(amountSpread, 80);
        CUnitsView vDone(punitsdb.get());
        SwapSettle(vDone, hashLock, SWAP_DONE, 0, 0);
        UnitsCheckScope scopeDone(&vDone);
        BOOST_REQUIRE_EQUAL(HousePendingSwapUnitsForChecks(nHouse), 0U);
        BOOST_REQUIRE_EQUAL(GoldTillRatioBps(house, H), 200U);
        BOOST_REQUIRE_EQUAL(GoldBrassageAmount(house, H, U), 0);
    }

    // The REDEEM, as CWallet::RedeemNote builds it: payout at the bid to the holder, the spread at vout[1], change.
    const COutPoint fundRedeem = FundCoinForTest(9201, 1 * COIN);
    CMutableTransaction mtxRedeem;
    mtxRedeem.nVersion = TRANSACTION_NOTE_VERSION;
    mtxRedeem.nNoteOp = NOTE_OP_REDEEM;
    mtxRedeem.vin.push_back(CTxIn(noteIn));
    mtxRedeem.vin.push_back(CTxIn(fundRedeem));
    mtxRedeem.vout.push_back(CTxOut((CAmount)U, NoteScriptForPubKey(vchHolder)));   // 10 g at 1,000 sats a gram
    mtxRedeem.vout.push_back(CTxOut(amountSpread, HouseEscrowScript(house.houseID)));
    mtxRedeem.vout.push_back(CTxOut(1 * COIN + NOTE_DUST_VALUE - (CAmount)U - amountSpread - 20000, CScript() << OP_TRUE));
    {
        NoteRedeem redeem;
        redeem.nHouseID = nHouse;
        redeem.fBrassage = 1;
        redeem.vchHolderPubKey = vchHolder;
        redeem.nRateNamed = 1000;
        {
            CDataStream ss0(SER_NETWORK, PROTOCOL_VERSION); ss0 << redeem;
            mtxRedeem.vchNotePayload.assign(ss0.begin(), ss0.end());   // first: the whole-tx digest reads the payload
        }
        BOOST_REQUIRE(keyHolder.Sign(RedeemDigestAny(&NoteRedeemSigHash, nHouse, U, mtxRedeem), redeem.vchHolderSig));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
        mtxRedeem.vchNotePayload.assign(ss.begin(), ss.end());
    }
    BOOST_REQUIRE(SignSignature(keystore, NoteScriptForPubKey(vchHolder), mtxRedeem, 0, NOTE_DUST_VALUE, SIGHASH_ALL));   // last: binds the payload

    // The SWAP_DONE: the preimage, posted by anyone, a plain fee coin.
    const COutPoint fundDone = FundCoinForTest(9202, 1 * COIN);
    CMutableTransaction mtxDone;
    mtxDone.nVersion = TRANSACTION_NOTE_VERSION;
    mtxDone.nNoteOp = NOTE_OP_SWAP_DONE;
    mtxDone.vin.push_back(CTxIn(fundDone));
    mtxDone.vout.push_back(CTxOut(1 * COIN - 20000, CScript() << OP_TRUE));
    {
        NoteSwapDone d;
        d.nHouseID = nHouse;
        d.hashLock = hashLock;
        d.vchPreimage = vchPreimage;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << d;
        mtxDone.vchNotePayload.assign(ss.begin(), ss.end());
    }

    const CTransactionRef txRedeem = MakeTransactionRef(mtxRedeem), txDone = MakeTransactionRef(mtxDone);
    auto snap = [&]() {
        LOCK(cs_main);
        CHouse h;
        BOOST_REQUIRE(phousetree->GetHouse(nHouse, h));
        CUnitsView v(punitsdb.get());
        CSwapRecord r;
        BOOST_REQUIRE(v.Get(SwapKey(hashLock), r));
        const Coin& coinPot = pcoinsTip->AccessCoin(COutPoint(txRedeem->GetHash(), 1));
        return strprintf("minted %u mg, pending swaps %u mg, swap %s, spread to the pot %s, holder %s", h.nMintedUnits,
                         HousePendingSwapUnits(v, nHouse), r.nStatus == SWAP_DONE ? "done" : "open",
                         coinPot.IsSpent() ? std::string("none") : strprintf("%d sats", coinPot.out.nValue),
                         pcoinsTip->HaveCoin(COutPoint(txRedeem->GetHash(), 0)) ? "paid" : "unpaid");
    };
    // Each alone (controls): both are valid against block start.
    BOOST_REQUIRE_MESSAGE(chain.Mine({txRedeem}).empty(), "P1 setup: the REDEEM alone does not connect");
    chain.Undo();
    BOOST_REQUIRE_MESSAGE(chain.Mine({txDone}).empty(), "P1 setup: the SWAP_DONE alone does not connect");
    chain.Undo();
    const auto r = chain.BothOrders(txRedeem, txDone, snap);
    BOOST_CHECK_MESSAGE(r.first.strVerdict.empty() == r.second.strVerdict.empty() &&
                            r.first.strSnapshot == r.second.strSnapshot,
                        "P1 (rule B): [REDEEM, DONE] " + Said(r.first.strVerdict) +
                            (r.first.strVerdict.empty() ? " -> " + r.first.strSnapshot : std::string()) +
                            "; [DONE, REDEEM] " + Said(r.second.strVerdict) +
                            (r.second.strVerdict.empty() ? " -> " + r.second.strSnapshot : std::string()) +
                            ". The REDEEM's spread reads the pending swaps the DONE clears earlier in the block");
}

// B pair P2 (testing 2026-11-26, from the in-block map): an unprotested SWAP_PAY (anyone pays a swap the house didn't
// deliver; no consensus house slot, validation.cpp SWAP_PAY) and a holder's REDEEM at the same house. The PAY takes the
// swap's units out of the pending swaps W and, paid below the bid at demand, writes the shortfall into the house's
// ledger M (issued_connect.cpp, SwapSettle); the REDEEM's exact spread reads both through the block-so-far units view
// (HouseOwedOutsideNotesMg = W + live M). The house: Stressed (a live protest), 100 g of notes out, a 50 g swap demanded
// at a bid of 1,200 sats a gram, its deadline passed undelivered, the house's bid now the suite's 1,000, a till of 2,167
// sats. The PAY pays 50,000 sats (50 g at the lower bid): W 50,000 -> 0 and M 0 -> 8,334 mg (50 g x 200 / 1,200, rounded
// up). The till ratio is 144 bps at block start (2,167 / 150,000) and 200 bps after the PAY (2,167 / 108,334, M
// counted): the floor. The REDEEM of 10 g, built against block start, pays the 56 mg spread (56 sats).
//   [REDEEM, PAY]: the REDEEM sees W, owes 56 mg and pays it; both connect.
//   [PAY, REDEEM]: the REDEEM sees W 0 and M 8,334, owes no spread, and its escrow output is refused
//   (bad-note-redeem-brassage-unexpected): the block is invalid.
// A PAY only lowers W + M (a shortfall is less than the units paid), so the spread only falls after one, and a REDEEM
// paying the block-start spread still clears a smaller one (the check is >=): the verdicts part where the PAY lifts the
// till to the floor, as here. Mempool keeps the pair apart only by its house-slot list, which holds SWAP_PAY.
// FAILS on master (the orders differ: [REDEEM, PAY] connects, [PAY, REDEEM] is refused).
BOOST_AUTO_TEST_CASE(order_swap_pay_and_redeem)
{
    OrderChain chain;
    OrderTestLog log;
    RealCapitalScope realCapital;
    BOOST_REQUIRE_EQUAL(g_nHouseRateTestOverride, 1000U);
    BOOST_REQUIRE_MESSAGE(chain.Mine({}).empty(), "P2 setup: empty block 1");   // the chain clock starts
    BOOST_REQUIRE_MESSAGE(chain.Mine({}).empty(), "P2 setup: empty block 2");
    const int nTip = TipForTest()->nHeight, H = nTip + 1;   // the pair's block

    CKey keyHolder, keySwapper;
    keyHolder.MakeNewKey(true);
    keySwapper.MakeNewKey(true);
    const CPubKey pubHolder = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchHolder(pubHolder.begin(), pubHolder.end());

    const uint32_t nHouse = 8;
    const uint64_t N = 100000, W = 50000, U = 10000;   // mg: notes out, the swap, the redemption
    const CHouse house = StressedHouseForTest(nHouse, uint256S("b2d0"), "orderp2", N, 2167, nTip);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(phousetree->WriteHouse(house));
        BOOST_REQUIRE(phousetree->WriteLastHouseID(nHouse));
    }

    // The swap: 50 g demanded at a bid of 1,200; its deadline is reached (the clock's active time now).
    const std::vector<unsigned char> vchPreimage(32, 0x6e);
    uint256 hashLock;
    CSHA256().Write(vchPreimage.data(), vchPreimage.size()).Finalize(hashLock.begin());
    const CScript scriptSwapPayout = GetScriptForDestination(keySwapper.GetPubKey().GetID());
    CChainClock clock;
    WriteUnitsAtTip([&](CUnitsView& v) {
        BOOST_REQUIRE(GetChainClock(v, clock));
        CSwapRecord rec;
        rec.nHouseID = nHouse;
        rec.nUnits = W;
        rec.nChainID = 1;
        rec.vchContract.assign(20, 0xc0);
        rec.vchEthAddress.assign(20, 0xea);
        rec.vchPayoutScript.assign(scriptSwapPayout.begin(), scriptSwapPayout.end());
        rec.nBid0 = 1200;
        rec.nDemandHeight = 1;
        rec.nDeadlineActive = clock.nActiveTime;
        rec.nStatus = SWAP_PENDING;
        v.Put(SwapKey(hashLock), rec);
        v.Put(SwapPendingKey(nHouse), W);
    });
    const COutPoint noteIn = NoteCoinForTest(uint256S("b2a7"), nHouse, U, vchHolder);

    // Block start: Stressed, W 50,000, M 0, 144 bps, a 56 mg spread on 10 g. After the PAY's writes (as ConnectIssuedTx
    // makes them, at the lower bid): W 0, M 8,334, 200 bps, no spread.
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(H);
    const int64_t nLapse = (int64_t)gp.nShortfallLapseSecs / 600;
    CAmount amountSpread = 0;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
        BOOST_REQUIRE_EQUAL(HousePendingSwapUnitsForChecks(nHouse), W);
        BOOST_REQUIRE_EQUAL(HouseLiveShortfallMgForChecks(nHouse, ClockAtHeight(H), nLapse), 0U);
        BOOST_REQUIRE_EQUAL(GoldTillRatioBps(house, H), 144U);
        amountSpread = GoldBrassageAmount(house, H, U);
        BOOST_REQUIRE_EQUAL(amountSpread, 56);
        CUnitsView vPaid(punitsdb.get());
        SwapFixBidT(vPaid, hashLock, (uint32_t)H);
        SwapSettle(vPaid, hashLock, SWAP_PAID, 1000, clock.nMonoTime, ClockAtHeight(H), nLapse);
        UnitsCheckScope scopePaid(&vPaid);
        BOOST_REQUIRE_EQUAL(HousePendingSwapUnitsForChecks(nHouse), 0U);
        BOOST_REQUIRE_EQUAL(HouseLiveShortfallMgForChecks(nHouse, ClockAtHeight(H), nLapse), 8334U);
        BOOST_REQUIRE_EQUAL(GoldTillRatioBps(house, H), 200U);
        BOOST_REQUIRE_EQUAL(GoldBrassageAmount(house, H, U), 0);
    }

    const CTransactionRef txRedeem = RedeemTxForTest(nHouse, house.houseID, U, amountSpread, keyHolder, noteIn,
                                                     FundCoinForTest(9211, 1 * COIN));
    // The PAY: 50 g at the lower of the bid at demand and the bid at the deadline (1,000), by anyone, from a plain coin.
    CMutableTransaction mtxPay;
    mtxPay.nVersion = TRANSACTION_NOTE_VERSION;
    mtxPay.nNoteOp = NOTE_OP_SWAP_PAY;
    mtxPay.vin.push_back(CTxIn(FundCoinForTest(9212, 1 * COIN)));
    mtxPay.vout.push_back(CTxOut((CAmount)W, scriptSwapPayout));
    mtxPay.vout.push_back(CTxOut(1 * COIN - (CAmount)W - 20000, CScript() << OP_TRUE));
    {
        NoteSwapPay p;
        p.nHouseID = nHouse;
        p.hashLock = hashLock;
        p.nRateNamed = 1000;
        p.fWasProtested = 0;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << p;
        mtxPay.vchNotePayload.assign(ss.begin(), ss.end());
    }
    const CTransactionRef txPay = MakeTransactionRef(mtxPay);

    auto snap = [&]() {
        LOCK(cs_main);
        CHouse h;
        BOOST_REQUIRE(phousetree->GetHouse(nHouse, h));
        CUnitsView v(punitsdb.get());
        CSwapRecord r;
        BOOST_REQUIRE(v.Get(SwapKey(hashLock), r));
        const Coin& coinPot = pcoinsTip->AccessCoin(COutPoint(txRedeem->GetHash(), 1));
        return strprintf("minted %u mg, pending swaps %u mg, live shortfall %u mg, swap %s, spread to the pot %s, holder %s",
                         h.nMintedUnits, HousePendingSwapUnits(v, nHouse), HouseLiveShortfallMg(v, nHouse, ClockAtHeight(H), nLapse),
                         r.nStatus == SWAP_PAID ? "paid" : "open",
                         coinPot.IsSpent() ? std::string("none") : strprintf("%d sats", coinPot.out.nValue),
                         pcoinsTip->HaveCoin(COutPoint(txRedeem->GetHash(), 0)) ? "paid" : "unpaid");
    };
    // Each alone (controls): both are valid against block start.
    BOOST_REQUIRE_MESSAGE(chain.Mine({txRedeem}).empty(), "P2 setup: the REDEEM alone does not connect");
    chain.Undo();
    BOOST_REQUIRE_MESSAGE(chain.Mine({txPay}).empty(), "P2 setup: the SWAP_PAY alone does not connect");
    BOOST_REQUIRE_EQUAL(snap(), "minted 100000 mg, pending swaps 0 mg, live shortfall 8334 mg, swap paid, spread to the pot none, holder unpaid");
    chain.Undo();
    const auto r = chain.BothOrders(txRedeem, txPay, snap);
    BOOST_CHECK_MESSAGE(r.first.strVerdict.empty() == r.second.strVerdict.empty() &&
                            r.first.strSnapshot == r.second.strSnapshot,
                        "P2 (rule B): [REDEEM, PAY] " + Said(r.first.strVerdict) +
                            (r.first.strVerdict.empty() ? " -> " + r.first.strSnapshot : std::string()) +
                            "; [PAY, REDEEM] " + Said(r.second.strVerdict) +
                            (r.second.strVerdict.empty() ? " -> " + r.second.strSnapshot : std::string()) +
                            ". The REDEEM's spread reads the pending swaps and shortfalls the PAY moves earlier in the block");
}

// B pair P3 (testing 2026-11-26, from the in-block map): a status-moving house slot op, then a note DEMAND, which reads
// the house's status through the block's staged record but takes no slot. Here the partners' DEFER (a Stressed house
// with a live protest invokes the option clause) and a holder's formal pre-auth DEMAND (mode 1). DEMAND's modes follow
// the status it reads: mode 1 at Open or Stressed only; at Deferred it is refused
// (bad-note-demand-preauth-queue-required), since there the queue mode 2 accrues from the demand and mode 1 only from
// its window's lapse. The house: Stressed, 100 g of notes out, 5,000 sats attested at the tip, one partner (M = 1); the
// DEFER locks the 5,000 sats into escrow. The DEMAND re-issues 10 g into the holder's custody.
//   [DEMAND, DEFER]: the DEMAND sees Stressed; both connect, and the suspended house holds a mode-1 demand, the kind
//   DEMAND refuses at a Deferred house.
//   [DEFER, DEMAND]: the DEMAND sees Deferred and is refused: the block is invalid.
// Mempool keeps them apart only by the UR3-8 guard (GetHouseStatusReaderID against the pooled slot ops).
// FAILS on master (the orders differ: [DEMAND, DEFER] connects, [DEFER, DEMAND] is refused).
BOOST_AUTO_TEST_CASE(order_defer_and_demand)
{
    OrderChain chain;
    OrderTestLog log;
    BOOST_REQUIRE_MESSAGE(chain.Mine({}).empty(), "P3 setup: empty block 1");
    BOOST_REQUIRE_MESSAGE(chain.Mine({}).empty(), "P3 setup: empty block 2");
    const int nTip = TipForTest()->nHeight, H = nTip + 1;   // the pair's block

    CKey keyPartner, keyHolder;
    keyPartner.MakeNewKey(true);
    keyHolder.MakeNewKey(true);
    const CPubKey pubPartner = keyPartner.GetPubKey(), pubHolder = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchHolder(pubHolder.begin(), pubHolder.end());

    const uint32_t nHouse = 9;
    const uint64_t N = 100000, U = 10000;    // mg: notes out, the demand
    const CAmount amountTill = 5000;         // sats attested at the tip: what the DEFER must lock
    CHouse house = StressedHouseForTest(nHouse, uint256S("b3d0"), "orderp3", N, amountTill, nTip);
    {
        HousePartner p;
        p.vchPubKey.assign(pubPartner.begin(), pubPartner.end());
        p.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(p);
    }
    {
        LOCK(cs_main);
        BOOST_REQUIRE(phousetree->WriteHouse(house));
        BOOST_REQUIRE(phousetree->WriteLastHouseID(nHouse));
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
    }
    const COutPoint noteIn = NoteCoinForTest(uint256S("b3a7"), nHouse, U, vchHolder);

    // The DEFER: vout[0] locks the attested till into escrow; partner 0 signs (priors as the record stands).
    CMutableTransaction mtxDefer;
    mtxDefer.nVersion = TRANSACTION_HOUSE_VERSION;
    mtxDefer.nHouseOp = HOUSE_OP_DEFER;
    mtxDefer.vin.push_back(CTxIn(FundCoinForTest(9301, 1 * COIN)));
    mtxDefer.vout.push_back(CTxOut(amountTill, HouseEscrowScript(house.houseID)));
    mtxDefer.vout.push_back(CTxOut(1 * COIN - amountTill - 20000, CScript() << OP_TRUE));
    {
        HouseDefer def;
        def.nHouseID = nHouse;
        def.nPrevLastActivation = house.nDeferLastActivation;
        def.nPrevEpisodeAnchor = house.nEpisodeAnchor;
        def.nPrevEpisodeDeferBlocks = house.nEpisodeDeferBlocks;
        def.nPrevEpisodeFloorUsed = house.fEpisodeFloorUsed;
        def.nPrevDeferInEpisode = house.fDeferInEpisode;
        { CDataStream s0(SER_NETWORK, PROTOCOL_VERSION); s0 << def; mtxDefer.vchHousePayload.assign(s0.begin(), s0.end()); }
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(keyPartner.Sign(HouseDeferSigHash(CTransaction(mtxDefer), house.houseID), vchSig));   // Stage 0 C1
        def.vApproverIndex.push_back(0);
        def.vApproverSig.push_back(vchSig);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << def;
        mtxDefer.vchHousePayload.assign(ss.begin(), ss.end());
    }
    const CTransactionRef txDefer = MakeTransactionRef(mtxDefer);

    // The DEMAND (mode 1), as at an Open or Stressed house: the 10 g re-issued into the holder's custody under this
    // demand's id, the standing pre-auth to a payout P2PKH, the holder's signature over the outputs; the note input
    // signed last.
    CMutableTransaction mtxDemand;
    mtxDemand.nVersion = TRANSACTION_NOTE_VERSION;
    mtxDemand.nNoteOp = NOTE_OP_DEMAND;
    mtxDemand.vin.push_back(CTxIn(noteIn));
    mtxDemand.vin.push_back(CTxIn(FundCoinForTest(9302, 1 * COIN)));
    {
        NoteDemand dem;
        dem.nHouseID = nHouse;
        dem.vUnits.push_back(U);
        dem.vchHolderPubKey = vchHolder;
        dem.fPreAuth = NOTE_DEMAND_MODE_PREAUTH;
        const CScript scriptPayout = GetScriptForDestination(pubHolder.GetID());
        dem.vchPayoutScript.assign(scriptPayout.begin(), scriptPayout.end());
        const uint256 demandId = DemandIdAny(CTransaction(mtxDemand), dem.vUnits, dem.vchPayoutScript, 0);
        mtxDemand.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteDemandCustodyScript(vchHolder, demandId)));
        mtxDemand.vout.push_back(CTxOut(1 * COIN - 20000, CScript() << OP_TRUE));
        BOOST_REQUIRE(keyHolder.Sign(NotePreAuthSigHash(nHouse, dem.vUnits, dem.vchPayoutScript, demandId), dem.vchPreAuthSig));
        {
            CDataStream ss0(SER_NETWORK, PROTOCOL_VERSION); ss0 << dem;
            mtxDemand.vchNotePayload.assign(ss0.begin(), ss0.end());   // first: the whole-tx digest reads the payload
        }
        BOOST_REQUIRE(keyHolder.Sign(DemandDigestAny(&NoteDemandSigHash, nHouse, dem.vUnits, mtxDemand), dem.vchHolderSig));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << dem;
        mtxDemand.vchNotePayload.assign(ss.begin(), ss.end());
        CBasicKeyStore keystore;
        keystore.AddKey(keyHolder);
        BOOST_REQUIRE(SignSignature(keystore, NoteScriptForPubKey(vchHolder), mtxDemand, 0, NOTE_DUST_VALUE, SIGHASH_ALL));
    }
    const CTransactionRef txDemand = MakeTransactionRef(mtxDemand);

    auto snap = [&]() {
        LOCK(cs_main);
        CHouse h;
        BOOST_REQUIRE(phousetree->GetHouse(nHouse, h));
        const Coin& coinDemand = pcoinsTip->AccessCoin(COutPoint(txDemand->GetHash(), 0));
        const uint32_t nTag = coinDemand.nDemandHeight;
        return strprintf("house %c (deferred at %u), till locked %s, demand %s", HouseEffectiveStatus(h, H + 1),
                         h.nDeferInvokedHeight, h.vOutReserveLock.empty() ? "no" : "yes",
                         coinDemand.IsSpent() ? std::string("none")
                                              : strprintf("at %u, %s", NoteDemandHeightOf(nTag),
                                                          NoteDemandIsQueue(nTag) ? "queue (mode 2)"
                                                          : NoteDemandIsPreAuth(nTag) ? "pre-auth (mode 1)" : "plain"));
    };
    // Each alone (controls): both are valid against block start.
    BOOST_REQUIRE_MESSAGE(chain.Mine({txDefer}).empty(), "P3 setup: the DEFER alone does not connect");
    chain.Undo();
    BOOST_REQUIRE_MESSAGE(chain.Mine({txDemand}).empty(), "P3 setup: the DEMAND alone does not connect");
    chain.Undo();
    const auto r = chain.BothOrders(txDemand, txDefer, snap);
    BOOST_CHECK_MESSAGE(r.first.strVerdict.empty() == r.second.strVerdict.empty() &&
                            r.first.strSnapshot == r.second.strSnapshot,
                        "P3 (rule B): [DEMAND, DEFER] " + Said(r.first.strVerdict) +
                            (r.first.strVerdict.empty() ? " -> " + r.first.strSnapshot : std::string()) +
                            "; [DEFER, DEMAND] " + Said(r.second.strVerdict) +
                            (r.second.strVerdict.empty() ? " -> " + r.second.strSnapshot : std::string()) +
                            ". The DEMAND's mode rule reads the status the DEFER moves earlier in the block");
}

// B pair P5 / O1 (testing 2026-11-26; freebankd asked for it with rule B2, ffe871c: CheckBlockCreditSlots refuses a block
// that spends a coin a FREEZE or UNFREEZE in the same block targets, in either order, bad-blk-freeze-spend).
//   (a) FREEZE of coin C and a BURN of C. Without B2 both orders fail, for different reasons ([FREEZE, BURN]: the burn
//       sheds the new freeze, bad-issued-frozen-flow; [BURN, FREEZE]: the freeze's target is spent).
//   (b) C frozen (40) by a confirmed FREEZE; an UNFREEZE of C to 0 and a BURN of C that sheds the freeze. Without B2 this
//       is order-dependent: [UNFREEZE, BURN] connects (the record is 0 when the burn reads it), [BURN, UNFREEZE] fails
//       (the burn sheds 40 frozen units). A producer picks which.
// Rule B: the same verdict in both orders; B2's slot makes it bad-blk-freeze-spend in both. Controls: each op alone
// connects. FAILS (b) on master (the orders differ).
template <typename T>
static std::vector<unsigned char> OrderEnc(const T& payload)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

BOOST_AUTO_TEST_CASE(order_freeze_and_spend_of_its_target)
{
    OrderChain chain;
    OrderTestLog consoleLog;
    UpdateCreateFeeForTest(0);   // no price feed here (issued_tests does the same)
    CKey keyIssuer, keyFreezer;
    keyIssuer.MakeNewKey(true);
    keyFreezer.MakeNewKey(true);
    auto tokenTx = [](uint8_t nOp, const COutPoint& in) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_TOKEN_VERSION;
        mtx.nIssuedOp = nOp;
        mtx.vin.push_back(CTxIn(in));
        mtx.vout.emplace_back(ISSUED_COIN_VALUE, CScript() << OP_TRUE);
        return mtx;
    };
    auto out = [](uint32_t n, const uint256& token, uint64_t nUnits, uint64_t nFrozen) {
        CIssuedOut o;
        o.nOut = n;
        o.tokenID = token;
        o.nUnits = nUnits;
        o.nFrozen = nFrozen;
        return o;
    };
    int nFund = 9500;
    // The token, then a coin C of 1,000 units, each mined in its own block.
    CMutableTransaction mc = tokenTx(ISSUED_OP_CREATE, FundCoinForTest(nFund++, 1 * COIN));
    IssuedCreate create;
    create.nKind = ISSUED_KIND_USD_CENTS;
    create.strTicker = "ORDP5";
    create.vchIssuerKey = ToByteVector(keyIssuer.GetPubKey());
    create.vchFreezeKey = ToByteVector(keyFreezer.GetPubKey());
    create.vchBackingContract = std::vector<unsigned char>(20, 0xaa);
    create.vchBackingAddress = std::vector<unsigned char>(20, 0xb5);
    create.strUpstream = "acme-gold";
    mc.vchIssuedPayload = OrderEnc(create);
    BOOST_REQUIRE(keyIssuer.Sign(IssuedSigHash(CTransaction(mc)), create.vchIssuerSig));
    mc.vchIssuedPayload = OrderEnc(create);
    const CTransactionRef txCreate = MakeTransactionRef(mc);
    BOOST_REQUIRE_EQUAL(Said(chain.Mine({txCreate})), "connected");
    const uint256 token = txCreate->GetHash();
    auto mint = [&](uint64_t nUnits) {
        CMutableTransaction mm = tokenTx(ISSUED_OP_MINT, FundCoinForTest(nFund++, 1 * COIN));
        IssuedMint m;
        m.tokenID = token;
        m.nUnits = nUnits;
        mm.vIssuedOut = {out(0, token, nUnits, 0)};
        mm.vchIssuedPayload = OrderEnc(m);
        BOOST_REQUIRE(keyIssuer.Sign(IssuedSigHash(CTransaction(mm)), m.vchIssuerSig));
        mm.vchIssuedPayload = OrderEnc(m);
        const CTransactionRef tx = MakeTransactionRef(mm);
        BOOST_REQUIRE_EQUAL(Said(chain.Mine({tx})), "connected");
        return COutPoint(tx->GetHash(), 0);
    };
    auto freeze = [&](uint8_t nOp, const COutPoint& c, uint64_t nFrozen) {
        CMutableTransaction mf = tokenTx(nOp, FundCoinForTest(nFund++, 1 * COIN));
        IssuedFreeze f;
        f.tokenID = token;
        f.vOutpoint = {c};
        f.vFrozen = {nFrozen};
        mf.vchIssuedPayload = OrderEnc(f);
        BOOST_REQUIRE(keyFreezer.Sign(IssuedSigHash(CTransaction(mf)), f.vchFreezeSig));
        mf.vchIssuedPayload = OrderEnc(f);
        return MakeTransactionRef(mf);
    };
    auto burn = [&](const COutPoint& c, uint64_t nIn, uint64_t nBurn) {   // the rest goes on unfrozen
        CMutableTransaction mb = tokenTx(ISSUED_OP_BURN, c);
        IssuedBurn b;
        b.tokenID = token;
        b.nUnits = nBurn;
        b.vchEthDest = std::vector<unsigned char>(20, 0xcc);
        mb.vIssuedOut = {out(0, token, nIn - nBurn, 0)};
        mb.vchIssuedPayload = OrderEnc(b);
        return MakeTransactionRef(mb);
    };
    auto transfer = [&](const COutPoint& c, uint64_t nUnits) {   // all of C on, unfrozen (never in the token slot)
        CMutableTransaction mt = tokenTx(ISSUED_OP_TRANSFER, c);
        mt.vIssuedOut = {out(0, token, nUnits, 0)};
        return MakeTransactionRef(mt);
    };
    auto snap = [&]() {
        CUnitsView units(punitsdb.get());
        CIssuedToken rec;
        return strprintf("supply %u", units.Get(IssuedTokenKey(token), rec) ? rec.nSupply : 0);
    };

    // (a) FREEZE of C and a BURN of C.
    const COutPoint cA = mint(10000);
    const CTransactionRef fA = freeze(ISSUED_OP_FREEZE, cA, 40), bA = burn(cA, 10000, ISSUED_BURN_MIN_UNITS);
    BOOST_CHECK_EQUAL(Said(chain.Mine({fA})), "connected");   // control: the FREEZE alone
    chain.Undo();
    BOOST_CHECK_EQUAL(Said(chain.Mine({bA})), "connected");   // control: the BURN alone
    chain.Undo();
    const auto rA = chain.BothOrders(fA, bA, snap);
    BOOST_CHECK_MESSAGE(rA.first.strVerdict == rA.second.strVerdict && rA.first.strSnapshot == rA.second.strSnapshot,
                        "P5a (rule B): [FREEZE, BURN] " + Said(rA.first.strVerdict) + ", [BURN, FREEZE] " +
                        Said(rA.second.strVerdict));
    BOOST_CHECK_MESSAGE(rA.first.strVerdict == "bad-blk-freeze-spend" && rA.second.strVerdict == "bad-blk-freeze-spend",
                        "P5a (rule B2): want bad-blk-freeze-spend in both orders: [FREEZE, BURN] " +
                        Said(rA.first.strVerdict) + ", [BURN, FREEZE] " + Said(rA.second.strVerdict));

    // (b) C frozen 40 by a confirmed FREEZE; an UNFREEZE to 0 and a BURN that sheds the freeze.
    const COutPoint cB = mint(10000);
    BOOST_REQUIRE_EQUAL(Said(chain.Mine({freeze(ISSUED_OP_FREEZE, cB, 40)})), "connected");
    const CTransactionRef uB = freeze(ISSUED_OP_UNFREEZE, cB, 0), bB = burn(cB, 10000, ISSUED_BURN_MIN_UNITS);
    BOOST_CHECK_EQUAL(Said(chain.Mine({uB})), "connected");   // control: the UNFREEZE alone
    BOOST_CHECK_EQUAL(Said(chain.Mine({bB})), "connected");   // control: the shedding BURN, a block after the UNFREEZE
    chain.Undo();
    chain.Undo();
    const auto rB = chain.BothOrders(uB, bB, snap);
    BOOST_CHECK_MESSAGE(rB.first.strVerdict == rB.second.strVerdict && rB.first.strSnapshot == rB.second.strSnapshot,
                        "P5b (rule B): [UNFREEZE, BURN] " + Said(rB.first.strVerdict) + " (" + rB.first.strSnapshot +
                        "), [BURN, UNFREEZE] " + Said(rB.second.strVerdict) + " (" + rB.second.strSnapshot + ")");
    BOOST_CHECK_MESSAGE(rB.first.strVerdict == "bad-blk-freeze-spend" && rB.second.strVerdict == "bad-blk-freeze-spend",
                        "P5b (rule B2): want bad-blk-freeze-spend in both orders: [UNFREEZE, BURN] " +
                        Said(rB.first.strVerdict) + ", [BURN, UNFREEZE] " + Said(rB.second.strVerdict));

    // (c), (d): the same two pairs with a TRANSFER of C, which no token slot covers, so the verdict is the freeze-target
    // rule's whatever the token slot holds (with BURN in the slot, as ffe871c had it, (a) and (b) stop there first).
    for (const bool fUnfreeze : {false, true}) {
        const COutPoint c = mint(10000);
        if (fUnfreeze)
            BOOST_REQUIRE_EQUAL(Said(chain.Mine({freeze(ISSUED_OP_FREEZE, c, 40)})), "connected");
        const CTransactionRef f = freeze(fUnfreeze ? ISSUED_OP_UNFREEZE : ISSUED_OP_FREEZE, c, fUnfreeze ? 0 : 40);
        const CTransactionRef t = transfer(c, 10000);
        BOOST_CHECK_EQUAL(Said(chain.Mine({f})), "connected");   // control: the (UN)FREEZE alone
        if (fUnfreeze) {
            BOOST_CHECK_EQUAL(Said(chain.Mine({t})), "connected");   // control: the shedding TRANSFER a block later
            chain.Undo();
        }
        chain.Undo();
        if (!fUnfreeze) {
            BOOST_CHECK_EQUAL(Said(chain.Mine({t})), "connected");   // control: the TRANSFER alone
            chain.Undo();
        }
        const auto r = chain.BothOrders(f, t, snap);
        const std::string strCase = fUnfreeze ? "P5d [UNFREEZE, TRANSFER]" : "P5c [FREEZE, TRANSFER]";
        BOOST_CHECK_MESSAGE(r.first.strVerdict == r.second.strVerdict && r.first.strSnapshot == r.second.strSnapshot,
                            strCase + " (rule B): " + Said(r.first.strVerdict) + ", the other order " + Said(r.second.strVerdict));
        BOOST_CHECK_MESSAGE(r.first.strVerdict == "bad-blk-freeze-spend" && r.second.strVerdict == "bad-blk-freeze-spend",
                            strCase + " (rule B2): want bad-blk-freeze-spend in both orders: " + Said(r.first.strVerdict) +
                            ", the other order " + Said(r.second.strVerdict));
    }
    UpdateCreateFeeForTest(Consensus::GramParams().nCreateFeeSats);
}

BOOST_AUTO_TEST_SUITE_END()
