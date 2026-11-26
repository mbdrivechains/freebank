// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// S1X-23 / S1X-24 (security's per-op cases):
// the credit checks on the mempool path read their input coins at the tip, so a coin made by a pooled tx is invisible to
// them while a block sees it with its real tags. ATMP must refuse (DoS 0, "unconfirmed-credit-parent")
//   (a) any spend of a pooled tx's output the mempool view tags as house escrow, and
//   (b) a note REDEEM or PROTEST spending a pooled tx's note output,
// and UpdateMempoolForReorg must drop such a tx already pooled when a reorg puts its parent back.
//
// Each case drives AcceptToMemoryPool with a shape-valid op whose only fault is a pooled parent; the controls change that
// one input and must be refused for some other reason (the houses here don't exist, so nothing is ever accepted). The
// pooled parents enter through addUnchecked: their own checks are not under test, only the tags the mempool view gives
// their outputs (checked first in each case).

#include <bill.h>   // BillHashOutputs (S1X-18 note 1)
#include <coins.h>
#include <consensus/validation.h>
#include <house.h>
#include <key.h>
#include <note.h>
#include <keystore.h>
#include <policy/policy.h>
#include <script/sign.h>
#include <script/standard.h>
#include <streams.h>
#include <txdb.h>
#include <txmempool.h>
#include <tinyformat.h>
#include <validation.h>
#include <version.h>

#include <test/sidechain_test_util.h>
#include <test/test_bitcoin.h>

#include <functional>
#include <map>

#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

void UpdateMempoolForReorg(DisconnectedBlockTransactions& disconnectpool, bool fAddToMempool);

namespace {

const uint32_t OWN = 7;       // the house the op acts for
const uint32_t FOREIGN = 9;   // another house: S1X-23 puts its pooled escrow first
const std::string REASON = "unconfirmed-credit-parent";

template <typename T>
std::vector<unsigned char> Enc(const T& p)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CScript PlainScript(unsigned char c)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, c) << OP_EQUALVERIFY << OP_CHECKSIG;
}

const std::vector<unsigned char> SIG(70, 0x30);   // shape only: a non-empty signature no check here gets to verify

struct PooledParentSetup : public TestChain100Setup {
    sidechain_test::SideDBScope sideDBs;   // the house/bill/pool DBs the contextual checks read (TestingSetup makes none)
    CKey keyHolder;
    std::vector<unsigned char> pubHolder;
    int nNext = 0;

    PooledParentSetup()
    {
        keyHolder.MakeNewKey(true);
        const CPubKey pub = keyHolder.GetPubKey();
        pubHolder.assign(pub.begin(), pub.end());
    }

    /** A confirmed coin at the tip, with the tags its block gave it. */
    COutPoint TipCoinWith(const CTxOut& out, const std::function<void(Coin&)>& fnTag = nullptr)
    {
        const COutPoint o(uint256S(strprintf("%x", 0xc0000 + ++nNext)), 0);
        Coin coin(out, chainActive.Height(), false, false, false, uint256());
        if (fnTag)
            fnTag(coin);
        pcoinsTip->AddCoin(o, std::move(coin), false);
        return o;
    }
    COutPoint Fee() { return TipCoinWith(CTxOut(COIN, PlainScript(0x0f))); }
    COutPoint OwnEscrow()
    {
        return TipCoinWith(CTxOut(5 * COIN, HouseEscrowScript(uint256S("07"))), [](Coin& c) { c.SetHouseEscrow(OWN); });
    }
    COutPoint ForeignEscrow()
    {
        return TipCoinWith(CTxOut(5 * COIN, HouseEscrowScript(uint256S("09"))), [](Coin& c) { c.SetHouseEscrow(FOREIGN); });
    }
    COutPoint OwnNote(uint64_t nUnits, uint32_t nDemandTag, const CScript& script)
    {
        return TipCoinWith(CTxOut(NOTE_DUST_VALUE, script), [=](Coin& c) { c.SetNote(OWN, nUnits, nDemandTag); });
    }

    /** Pool mtx the way a parent accepted earlier would sit there (its inputs are real tip coins). */
    void Pool(const CMutableTransaction& mtx)
    {
        TestMemPoolEntryHelper entry;
        mempool.addUnchecked(mtx.GetHash(), entry.FromTx(mtx));
        BOOST_REQUIRE(mempool.exists(mtx.GetHash()));
    }

    /** The coin the mempool view gives a pooled output: what the credit checks would have to read. */
    Coin ViewCoin(const COutPoint& o)
    {
        CCoinsViewMemPool view(pcoinsTip.get(), mempool);
        Coin coin;
        BOOST_REQUIRE(view.GetCoin(o, coin));
        return coin;
    }

    struct Verdict {
        bool fAccepted = false;
        bool fInvalid = false;
        int nDoS = -1;
        std::string strReason;
    };
    Verdict Atmp(const CMutableTransaction& mtx)
    {
        Verdict v;
        CValidationState state;
        v.fAccepted = AcceptToMemoryPool(mempool, state, MakeTransactionRef(mtx), nullptr, nullptr, true, 0);
        v.fInvalid = state.IsInvalid(v.nDoS);
        v.strReason = v.fAccepted ? "accepted" : (v.fInvalid ? state.GetRejectReason() : "missing-inputs");
        return v;
    }
    /** The case: refused for the pooled parent alone, DoS 0, and not pooled. */
    void CheckRefused(const CMutableTransaction& mtx, const std::string& strCase)
    {
        const Verdict v = Atmp(mtx);
        BOOST_CHECK_MESSAGE(!v.fAccepted && v.strReason == REASON && v.nDoS == 0,
                strprintf("%s: want refused (%s, DoS 0), got %s (DoS %d)", strCase, REASON, v.strReason, v.nDoS));
        BOOST_CHECK_MESSAGE(!mempool.exists(mtx.GetHash()), strCase + ": pooled anyway");
    }
    /** A control: it reaches the rule and passes it (it fails later, on the made-up house). */
    void CheckNotThisRule(const CMutableTransaction& mtx, const std::string& strCase)
    {
        const Verdict v = Atmp(mtx);
        BOOST_CHECK_MESSAGE(v.fInvalid && v.strReason != REASON,
                strprintf("%s: want a refusal other than %s, got %s", strCase, REASON, v.strReason));
        BOOST_TEST_MESSAGE(strCase + ": " + v.strReason);
    }

    // ---- pooled parents (house escrow) ----

    /** A TOPUP of the FOREIGN house: vout[0] the pledge (escrow), vout[1] plain change. */
    CMutableTransaction TopupParent()
    {
        HouseTopup t;
        t.nHouseID = FOREIGN;
        t.vchSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_HOUSE_VERSION;
        m.nHouseOp = HOUSE_OP_TOPUP;
        m.vchHousePayload = Enc(t);
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(5 * COIN, HouseEscrowScript(uint256S("09"))));
        m.vout.push_back(CTxOut(COIN / 2, PlainScript(0x01)));
        return m;
    }
    /** A note REDEEM with brassage at the FOREIGN house: vout[1] is the spread, escrow. */
    CMutableTransaction BrassageRedeemParent()
    {
        NoteRedeem r;
        r.nHouseID = FOREIGN;
        r.fBrassage = 1;
        r.vchHolderPubKey = pubHolder;
        r.vchHolderSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_REDEEM;
        m.vchNotePayload = Enc(r);
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(COIN / 2, PlainScript(0x02)));
        m.vout.push_back(CTxOut(COIN / 10, HouseEscrowScript(uint256S("09"))));
        return m;
    }
    /** A note CLAIM at the FOREIGN house returning escrow change at vout[1]. */
    CMutableTransaction EscrowChangeClaimParent()
    {
        NoteClaim c;
        c.nHouseID = FOREIGN;
        c.fEscrowChange = 1;
        c.vchHolderPubKey = pubHolder;
        c.vchHolderSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_CLAIM;
        m.vchNotePayload = Enc(c);
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(COIN / 2, PlainScript(0x03)));
        m.vout.push_back(CTxOut(2 * COIN, HouseEscrowScript(uint256S("09"))));
        return m;
    }

    // ---- pooled parents (notes, at the OWN house) ----

    /** A TRANSFER of demanded notes (S1X-24): vout[0..1] notes carrying demand height 60, vout[2] plain change. */
    CMutableTransaction TransferParent()
    {
        NoteTransfer x;
        x.nHouseID = OWN;
        x.vUnits = {3000000, 1000000};
        x.nDemandHeight = 60;
        x.vchSenderPubKey = pubHolder;
        x.vchSenderSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_TRANSFER;
        m.vchNotePayload = Enc(x);
        m.vin.push_back(CTxIn(OwnNote(4000000, 60, NoteScriptForPubKey(pubHolder))));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pubHolder)));
        m.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pubHolder)));
        m.vout.push_back(CTxOut(COIN / 2, PlainScript(0x04)));
        return m;
    }
    /** A PROTEST: its notes are re-issued into custody with the real tag (the payload carries it). */
    CMutableTransaction ProtestParent()
    {
        NoteProtest p;
        p.nHouseID = OWN;
        p.vUnits = {500000};
        p.vchHolderPubKey = pubHolder;
        p.vchHolderSig = SIG;
        p.nDemandTag = 60 | NOTE_DEMAND_PREAUTH_BIT;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_PROTEST;
        m.vchNotePayload = Enc(p);
        m.vin.push_back(CTxIn(OwnNote(500000, 60 | NOTE_DEMAND_PREAUTH_BIT, NotePreAuthScript(pubHolder))));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(NOTE_DUST_VALUE, NotePreAuthScript(pubHolder)));
        return m;
    }
    /** A pre-auth upgrade DEMAND (prior height 60): its tag is known unconfirmed, so unconfirmed-stamp-parent lets it by. */
    CMutableTransaction UpgradeDemandParent()
    {
        NoteDemand d;
        d.nHouseID = OWN;
        d.vUnits = {500000};
        d.vchHolderPubKey = pubHolder;
        d.vchHolderSig = SIG;
        d.fPreAuth = NOTE_DEMAND_MODE_PREAUTH;
        d.nPriorDemandHeight = 60;
        const CScript payout = PlainScript(0x05);
        d.vchPayoutScript.assign(payout.begin(), payout.end());
        d.vchPreAuthSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_DEMAND;
        m.vchNotePayload = Enc(d);
        m.vin.push_back(CTxIn(OwnNote(500000, 60, NoteScriptForPubKey(pubHolder))));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(NOTE_DUST_VALUE, NotePreAuthScript(pubHolder)));
        return m;
    }

    // ---- the ops under test, at the OWN house; vin as given, then a fee coin ----

    CMutableTransaction Close(const std::vector<COutPoint>& vIn)
    {
        HouseClose cl;
        cl.nHouseID = OWN;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_HOUSE_VERSION;
        m.nHouseOp = HOUSE_OP_CLOSE;
        m.vchHousePayload = Enc(cl);
        for (const COutPoint& o : vIn) m.vin.push_back(CTxIn(o));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(100000, PlainScript(0x10)));
        return m;
    }
    CMutableTransaction Release(const std::vector<COutPoint>& vIn)
    {
        HouseRelease rel;
        rel.nHouseID = OWN;
        rel.vApproverIndex = {0};
        rel.vApproverSig = {SIG};
        CMutableTransaction m;
        m.nVersion = TRANSACTION_HOUSE_VERSION;
        m.nHouseOp = HOUSE_OP_RELEASE;
        m.vchHousePayload = Enc(rel);
        for (const COutPoint& o : vIn) m.vin.push_back(CTxIn(o));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(100000, PlainScript(0x11)));
        return m;
    }
    CMutableTransaction Claim(const std::vector<COutPoint>& vIn)
    {
        NoteClaim c;
        c.nHouseID = OWN;
        c.vchHolderPubKey = pubHolder;
        c.vchHolderSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_CLAIM;
        m.vchNotePayload = Enc(c);
        for (const COutPoint& o : vIn) m.vin.push_back(CTxIn(o));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(100000, PlainScript(0x12)));
        return m;
    }
    CMutableTransaction Redeem(const std::vector<COutPoint>& vIn)
    {
        NoteRedeem r;
        r.nHouseID = OWN;
        r.vchHolderPubKey = pubHolder;
        r.vchHolderSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_REDEEM;
        m.vchNotePayload = Enc(r);
        for (const COutPoint& o : vIn) m.vin.push_back(CTxIn(o));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(100000, PlainScript(0x13)));
        return m;
    }
    CMutableTransaction Protest(const std::vector<COutPoint>& vIn, uint64_t nUnits, uint32_t nTag)
    {
        NoteProtest p;
        p.nHouseID = OWN;
        p.vUnits = {nUnits};
        p.vchHolderPubKey = pubHolder;
        p.vchHolderSig = SIG;
        p.nDemandTag = nTag;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_PROTEST;
        m.vchNotePayload = Enc(p);
        for (const COutPoint& o : vIn) m.vin.push_back(CTxIn(o));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(NOTE_DUST_VALUE, NotePreAuthScript(pubHolder)));
        return m;
    }
    CMutableTransaction Transfer(const std::vector<COutPoint>& vIn, uint64_t nUnits, uint32_t nDemandHeight)
    {
        NoteTransfer x;
        x.nHouseID = OWN;
        x.vUnits = {nUnits};
        x.nDemandHeight = nDemandHeight;
        x.vchSenderPubKey = pubHolder;
        x.vchSenderSig = SIG;
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_TRANSFER;
        m.vchNotePayload = Enc(x);
        for (const COutPoint& o : vIn) m.vin.push_back(CTxIn(o));
        m.vin.push_back(CTxIn(Fee()));
        m.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pubHolder)));
        return m;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pooled_credit_parent_tests, PooledParentSetup)

// Rule (a), S1X-23's class with the ops security named: [foreign pooled escrow first, own escrow]. Before the fix the
// mixing check skipped while the running house id was 0 (the pooled pledge's tag), and the own-escrow loops skipped the
// coin TipCoin can't see, so each was accepted and failed bad-house-inputs-mixed in every template.
BOOST_AUTO_TEST_CASE(s1x_23_close_with_a_foreign_pooled_pledge_first)
{
    LOCK(cs_main);
    const CMutableTransaction P = TopupParent();
    Pool(P);
    const Coin pledge = ViewCoin(COutPoint(P.GetHash(), 0));
    BOOST_REQUIRE(pledge.fHouseEscrow && pledge.nHouseID == 0);   // the pooled pledge reads as house 0
    BOOST_REQUIRE(!ViewCoin(COutPoint(P.GetHash(), 1)).fHouseEscrow);

    CheckRefused(Close({COutPoint(P.GetHash(), 0), OwnEscrow()}), "CLOSE [pooled foreign pledge, own escrow]");
    CheckRefused(Close({OwnEscrow(), COutPoint(P.GetHash(), 0)}), "CLOSE [own escrow, pooled foreign pledge]");
    // Controls: the same CLOSE with the foreign escrow confirmed, and with the pooled TOPUP's plain change instead.
    CheckNotThisRule(Close({ForeignEscrow(), OwnEscrow()}), "CLOSE [confirmed foreign escrow, own escrow]");
    CheckNotThisRule(Close({COutPoint(P.GetHash(), 1), OwnEscrow()}), "CLOSE [pooled plain change, own escrow]");
}

BOOST_AUTO_TEST_CASE(s1x_23_release_with_a_foreign_pooled_escrow_first)
{
    LOCK(cs_main);
    const CMutableTransaction P = BrassageRedeemParent();
    Pool(P);
    const Coin spread = ViewCoin(COutPoint(P.GetHash(), 1));
    BOOST_REQUIRE(spread.fHouseEscrow && spread.nHouseID == 0);   // a pooled REDEEM's brassage spread
    BOOST_REQUIRE(!ViewCoin(COutPoint(P.GetHash(), 0)).fHouseEscrow);

    CheckRefused(Release({COutPoint(P.GetHash(), 1), OwnEscrow()}), "RELEASE [pooled foreign spread, own lock]");
    CheckNotThisRule(Release({ForeignEscrow(), OwnEscrow()}), "RELEASE [confirmed foreign escrow, own lock]");
    CheckNotThisRule(Release({COutPoint(P.GetHash(), 0), OwnEscrow()}), "RELEASE [pooled REDEEM payout, own lock]");
}

// The CLAIM slot: a note CLAIM at a failed house takes the house's one pooled-op slot. With a foreign pooled escrow
// first, the escrow sum read it as nothing and the claim was accepted, squatting the slot for a fee it never pays.
BOOST_AUTO_TEST_CASE(s1x_23_claim_slot_squat_with_a_foreign_pooled_escrow_first)
{
    LOCK(cs_main);
    const CMutableTransaction P = EscrowChangeClaimParent();
    Pool(P);
    const Coin change = ViewCoin(COutPoint(P.GetHash(), 1));
    BOOST_REQUIRE(change.fHouseEscrow && change.nHouseID == 0);   // a pooled CLAIM's escrow change
    const COutPoint note = OwnNote(1000000, 0, NoteScriptForPubKey(pubHolder));

    CheckRefused(Claim({COutPoint(P.GetHash(), 1), OwnEscrow(), note}), "CLAIM [pooled foreign escrow change, own escrow, note]");
    CheckNotThisRule(Claim({ForeignEscrow(), OwnEscrow(), note}), "CLAIM [confirmed foreign escrow, own escrow, note]");
    CheckNotThisRule(Claim({COutPoint(P.GetHash(), 0), OwnEscrow(), note}), "CLAIM [pooled CLAIM payout, own escrow, note]");
}

// Rule (b), PROTEST: its demand-id scan read the tip, so a pooled parent's notes counted for nothing. The pre-auth
// upgrade DEMAND's tag is known unconfirmed, so the older unconfirmed-stamp-parent rule lets it through: this rule must
// catch it.
BOOST_AUTO_TEST_CASE(s1x_24_protest_after_a_pooled_parent)
{
    LOCK(cs_main);
    const uint32_t nTag = 60 | NOTE_DEMAND_PREAUTH_BIT;
    const CMutableTransaction P1 = ProtestParent();
    const CMutableTransaction P2 = UpgradeDemandParent();
    Pool(P1);
    Pool(P2);
    for (const CMutableTransaction* p : std::vector<const CMutableTransaction*>{&P1, &P2}) {
        const Coin c = ViewCoin(COutPoint(p->GetHash(), 0));
        BOOST_REQUIRE(c.fNote && c.nHouseID == OWN && c.nNoteUnits == 500000);
    }

    CheckRefused(Protest({COutPoint(P1.GetHash(), 0)}, 500000, nTag), "PROTEST of a pooled PROTEST's note");
    CheckRefused(Protest({COutPoint(P2.GetHash(), 0)}, 500000, nTag), "PROTEST of a pooled upgrade DEMAND's note");
    CheckNotThisRule(Protest({OwnNote(500000, nTag, NotePreAuthScript(pubHolder))}, 500000, nTag),
                     "PROTEST of a confirmed note");
}

// Rule (b), REDEEM at one house (S1X-24): the REDEEM of a pooled TRANSFER's demanded note skipped the interest floor at
// ATMP and took the house's slot, so holders' DEMANDs and PROTESTs had to outbid a fee that is never paid. Every other
// note op reads its inputs on the mempool view and still chains.
BOOST_AUTO_TEST_CASE(s1x_24_single_house_redeem_squat)
{
    LOCK(cs_main);
    const CMutableTransaction T = TransferParent();
    Pool(T);
    const Coin demanded = ViewCoin(COutPoint(T.GetHash(), 0));
    BOOST_REQUIRE(demanded.fNote && demanded.nHouseID == OWN && demanded.nNoteUnits == 3000000 &&
                  demanded.nDemandHeight == 60);
    const size_t nPooled = mempool.size();

    CheckRefused(Redeem({COutPoint(T.GetHash(), 0)}), "REDEEM of a pooled TRANSFER's demanded note");
    BOOST_CHECK_EQUAL(mempool.size(), nPooled);   // the house's slot stays free
    CheckNotThisRule(Redeem({OwnNote(3000000, 60, NoteScriptForPubKey(pubHolder))}), "REDEEM of a confirmed note");
    CheckNotThisRule(Redeem({COutPoint(T.GetHash(), 2)}), "REDEEM spending the pooled TRANSFER's plain change");
    CheckNotThisRule(Transfer({COutPoint(T.GetHash(), 1)}, 1000000, 60), "TRANSFER chained off the pooled TRANSFER");
}

// The reorg drop (security's addition): a tx accepted while its parent was confirmed must leave the pool when a reorg
// puts that parent back, as UR3-7 does for stamped outputs. Here the parents are already back in the pool and the
// children sit on them; UpdateMempoolForReorg must drop exactly the children rule (a) or (b) covers, with reason REORG
// (the stale sweep that runs after it evicts with EXPIRY, so the two can be told apart).
BOOST_AUTO_TEST_CASE(s1x_23_24_reorg_drops_pooled_children_of_restored_parents)
{
    LOCK(cs_main);
    const CMutableTransaction PEsc = TopupParent();
    const CMutableTransaction PNote = TransferParent();
    Pool(PEsc);
    Pool(PNote);
    const CMutableTransaction cClose = Close({COutPoint(PEsc.GetHash(), 0), OwnEscrow()});    // (a): drop
    const CMutableTransaction cRedeem = Redeem({COutPoint(PNote.GetHash(), 0)});             // (b): drop
    const CMutableTransaction cTransfer = Transfer({COutPoint(PNote.GetHash(), 1)}, 1000000, 60);   // stays
    CMutableTransaction cPlain;                                                              // stays
    cPlain.vin.push_back(CTxIn(COutPoint(PEsc.GetHash(), 1)));
    cPlain.vout.push_back(CTxOut(COIN / 4, PlainScript(0x20)));
    for (const CMutableTransaction* c : std::vector<const CMutableTransaction*>{&cClose, &cRedeem, &cTransfer, &cPlain})
        Pool(*c);
    BOOST_REQUIRE(SpendsPooledCreditOutput(CTransaction(cClose), mempool));
    BOOST_REQUIRE(SpendsPooledCreditOutput(CTransaction(cRedeem), mempool));
    BOOST_REQUIRE(!SpendsPooledCreditOutput(CTransaction(cTransfer), mempool));
    BOOST_REQUIRE(!SpendsPooledCreditOutput(CTransaction(cPlain), mempool));

    std::map<uint256, MemPoolRemovalReason> mapRemoved;
    boost::signals2::scoped_connection conn(mempool.NotifyEntryRemoved.connect(
        [&mapRemoved](CTransactionRef ptx, MemPoolRemovalReason reason) { mapRemoved.emplace(ptx->GetHash(), reason); }));
    DisconnectedBlockTransactions disconnectpool;
    UpdateMempoolForReorg(disconnectpool, true);

    auto fnDroppedForReorg = [&](const CMutableTransaction& m) {
        auto it = mapRemoved.find(m.GetHash());
        return it != mapRemoved.end() && it->second == MemPoolRemovalReason::REORG;
    };
    BOOST_CHECK_MESSAGE(fnDroppedForReorg(cClose), "CLOSE on a restored parent's escrow was not dropped by the reorg");
    BOOST_CHECK_MESSAGE(fnDroppedForReorg(cRedeem), "REDEEM of a restored TRANSFER's note was not dropped by the reorg");
    BOOST_CHECK_MESSAGE(!fnDroppedForReorg(cTransfer), "a TRANSFER chained on a restored TRANSFER was dropped as a reorg orphan");
    BOOST_CHECK_MESSAGE(!fnDroppedForReorg(cPlain), "a spend of a restored parent's plain change was dropped as a reorg orphan");
    BOOST_CHECK(!fnDroppedForReorg(PEsc) && !fnDroppedForReorg(PNote));
}

// S1X-18, security's note 1 (freebankd's follow-up 8c1290c): a pooled ESCROW_MERGE spends listed escrow coins, so an op
// that needs one of them (a CLAIM, CLOSE, RELEASE, settle RECLAIM, COLLECT, SWAP_CLAIM) met it as an INPUT conflict and,
// the MERGE having opted out of replacement (final sequences), was refused at the BIP125 test before the slot yield ever
// ran: a permissionless MERGE kept it out. Now such an incomer replaces the MERGE for free, whatever the MERGE pays.
// Here a RELEASE (the simplest such op to make valid: an Open house, reserve-lock inputs, M-of-N approvers) spending one
// of a pooled opt-out MERGE's coins, at a tenth of its fee, must be accepted and the MERGE gone. Controls, while the
// MERGE is pooled: a second MERGE meeting it is refused, and an incomer that also spends the MERGE's plain change is
// refused (txn-mempool-conflict: it may not spend what the replaced MERGE created).
BOOST_AUTO_TEST_CASE(s1x_18_a_release_replaces_a_pooled_opt_out_merge_of_its_coins)
{
    LOCK(cs_main);
    std::vector<CKey> keys(3);
    CHouse house;
    house.nHouseID = OWN;
    house.houseID = uint256S("5318");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 2;
    house.strClassID = "s18n1";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1;
    house.nLastAttestHeight = chainActive.Height();
    house.amountLastAttestReserves = 100 * COIN;
    for (int i = 0; i < 3; i++) {
        keys[i].MakeNewKey(true);
        const CPubKey pub = keys[i].GetPubKey();
        HousePartner p;
        p.vchPubKey.assign(pub.begin(), pub.end());
        p.amountPledge = HOUSE_MIN_PLEDGE;
        p.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(p);
    }
    const CScript scriptEscrow = HouseEscrowScript(house.houseID);
    auto escrowCoin = [&](CAmount n) { return TipCoinWith(CTxOut(n, scriptEscrow), [](Coin& c) { c.SetHouseEscrow(OWN); }); };
    const COutPoint R1 = escrowCoin(5 * COIN), R2 = escrowCoin(5 * COIN);
    house.vOutReserveLock = {R1, R2};
    std::sort(house.vOutReserveLock.begin(), house.vOutReserveLock.end());
    BOOST_REQUIRE(phousetree->WriteHouse(house));
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, chainActive.Height() + 1), HOUSE_STATUS_OPEN);

    CKey keyFee;
    keyFee.MakeNewKey(true);
    CBasicKeyStore keystore;
    keystore.AddKey(keyFee);
    const CScript scriptFee = GetScriptForDestination(keyFee.GetPubKey().GetID());
    auto feeCoin = [&]() { return TipCoinWith(CTxOut(COIN, scriptFee)); };
    const CScript scriptOut = PlainScript(0x31);

    // The pooled MERGE M of the reserve list: final sequences (no BIP125 signal), fee 0.001, a plain change at vout[1].
    const COutPoint F1 = feeCoin();
    CMutableTransaction M;
    {
        HouseEscrowMerge m;
        m.nHouseID = OWN;
        m.nList = HOUSE_ESCROW_LIST_RESERVE;
        M.nVersion = TRANSACTION_HOUSE_VERSION;
        M.nHouseOp = HOUSE_OP_ESCROW_MERGE;
        M.vchHousePayload = Enc(m);
        for (const COutPoint& o : {R1, R2, F1})
            M.vin.push_back(CTxIn(o));   // nSequence = SEQUENCE_FINAL
        M.vout.push_back(CTxOut(10 * COIN, scriptEscrow));
        M.vout.push_back(CTxOut(COIN - 100000, scriptOut));
        TestMemPoolEntryHelper entry;
        mempool.addUnchecked(M.GetHash(), entry.Fee(100000).FromTx(M));
        BOOST_REQUIRE(mempool.exists(M.GetHash()));
    }

    // A RELEASE of vIn (reserve coins and plain coins), all to one plain output, fee nFee, signed by approvers 0 and 1.
    auto release = [&](const std::vector<COutPoint>& vIn, CAmount nIn, CAmount nFee) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_RELEASE;
        for (const COutPoint& o : vIn)
            mtx.vin.push_back(CTxIn(o));
        mtx.vout.push_back(CTxOut(nIn - nFee, scriptOut));
        HouseRelease rel;
        rel.nHouseID = OWN;
        mtx.vchHousePayload = Enc(rel);   // Stage 0 C1: the approvers sign the finished tx
        const uint256 h = HouseReleaseSigHash(CTransaction(mtx), house.houseID);
        for (uint32_t i : {0u, 1u}) {
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(keys[i].Sign(h, sig));
            rel.vApproverIndex.push_back(i);
            rel.vApproverSig.push_back(sig);
        }
        mtx.vchHousePayload = Enc(rel);
        for (unsigned int n = 0; n < mtx.vin.size(); n++) {   // the plain inputs, signed last (the binding covers the payload)
            Coin coin;
            CCoinsViewMemPool view(pcoinsTip.get(), mempool);
            BOOST_REQUIRE(view.GetCoin(mtx.vin[n].prevout, coin));
            if (coin.out.scriptPubKey == scriptFee)
                BOOST_REQUIRE(SignSignature(keystore, coin.out.scriptPubKey, mtx, n, coin.out.nValue, SIGHASH_ALL));
        }
        return mtx;
    };

    // Control: a second MERGE meeting M (R2 and a fresh fee coin) is refused; M stays.
    {
        HouseEscrowMerge m;
        m.nHouseID = OWN;
        m.nList = HOUSE_ESCROW_LIST_RESERVE;
        CMutableTransaction M2;
        M2.nVersion = TRANSACTION_HOUSE_VERSION;
        M2.nHouseOp = HOUSE_OP_ESCROW_MERGE;
        M2.vchHousePayload = Enc(m);
        const COutPoint F3 = feeCoin();
        M2.vin.push_back(CTxIn(R2));
        M2.vin.push_back(CTxIn(F3));
        M2.vout.push_back(CTxOut(5 * COIN, scriptEscrow));
        M2.vout.push_back(CTxOut(COIN - 200000, scriptOut));
        const Verdict v = Atmp(M2);
        BOOST_CHECK_MESSAGE(!v.fAccepted, "S1X-18 note 1 control: a second MERGE replaced the pooled one: " + v.strReason);
        BOOST_TEST_MESSAGE("second MERGE: " + v.strReason);
        BOOST_CHECK(mempool.exists(M.GetHash()));
    }
    // Control: a RELEASE of R1 that also spends M's plain change is refused, txn-mempool-conflict; M stays.
    {
        const Verdict v = Atmp(release({R1, COutPoint(M.GetHash(), 1)}, 5 * COIN + COIN - 100000, 10000));
        BOOST_CHECK_MESSAGE(!v.fAccepted && v.strReason == "txn-mempool-conflict",
                            "S1X-18 note 1 control: a RELEASE spending the pooled MERGE's change: want txn-mempool-conflict, got " +
                            v.strReason);
        BOOST_CHECK(mempool.exists(M.GetHash()));
    }
    // The case: a RELEASE of R1 at a tenth of M's fee is accepted, and M leaves the pool.
    const COutPoint F2 = feeCoin();
    const CMutableTransaction rel = release({R1, F2}, 5 * COIN + COIN, 10000);
    const Verdict v = Atmp(rel);
    BOOST_CHECK_MESSAGE(v.fAccepted, "S1X-18 note 1: a RELEASE of a coin a pooled opt-out MERGE spends was refused (" + v.strReason +
                        "): the permissionless MERGE kept the house's op out");
    BOOST_CHECK_MESSAGE(!mempool.exists(M.GetHash()), "S1X-18 note 1: the MERGE is still pooled beside the RELEASE");
    BOOST_CHECK(mempool.exists(rel.GetHash()) == v.fAccepted);
}

BOOST_AUTO_TEST_SUITE_END()
