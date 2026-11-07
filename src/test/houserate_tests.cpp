// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Gold B (D-2026-11-07-1; GOLD_B.md §1): each house's own rate and the chain clock.

#include <houserate.h>
#include <house.h>
#include <note.h>

#include <consensus/validation.h>
#include <key.h>
#include <primitives/transaction.h>
#include <test/test_bitcoin.h>
#include <units.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(houserate_tests, BasicTestingSetup)

static const int64_t DAY = RATE_DAY_SECONDS;

BOOST_AUTO_TEST_CASE(chain_clock_monotone_and_active)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    CChainClock c;
    BOOST_CHECK(!GetChainClock(units, c));

    AdvanceChainClock(units, 1, 1000000, gp);
    BOOST_CHECK(GetChainClock(units, c));
    BOOST_CHECK_EQUAL(c.nHeight, 1u);
    BOOST_CHECK_EQUAL(c.nMonoTime, 1000000);
    BOOST_CHECK_EQUAL(c.nActiveTime, 0);

    AdvanceChainClock(units, 2, 1000600, gp);          // a 10-minute step counts in full
    GetChainClock(units, c);
    BOOST_CHECK_EQUAL(c.nMonoTime, 1000600);
    BOOST_CHECK_EQUAL(c.nActiveTime, 600);

    AdvanceChainClock(units, 3, 1000500, gp);          // an L1 time that steps back: the clock holds
    GetChainClock(units, c);
    BOOST_CHECK_EQUAL(c.nMonoTime, 1000600);
    BOOST_CHECK_EQUAL(c.nActiveTime, 600);

    AdvanceChainClock(units, 4, 1000600 + 36 * 3600, gp);   // a 36 h stall counts one hour of active time
    GetChainClock(units, c);
    BOOST_CHECK_EQUAL(c.nMonoTime, 1000600 + 36 * 3600);
    BOOST_CHECK_EQUAL(c.nActiveTime, 600 + 3600);

    // Each block's active time is kept by height: the windows' clock (GOLD_B §6).
    CClockAt at;
    BOOST_CHECK(units.Get(ClockAtKey(2), at));
    BOOST_CHECK_EQUAL(at.nActive, 600);
    BOOST_CHECK_EQUAL(at.nMono, 1000600);
    BOOST_CHECK(units.Get(ClockAtKey(4), at));
    BOOST_CHECK_EQUAL(at.nActive, 600 + 3600);
}

BOOST_AUTO_TEST_CASE(rate_shape_and_effect)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    uint64_t nBid = 0, nAsk = 0;

    BOOST_CHECK(HouseRateShapeOK(100000, 102000, gp.nRateSpreadBps));
    BOOST_CHECK(!HouseRateShapeOK(100000, 102001, gp.nRateSpreadBps));   // spread over 2%
    BOOST_CHECK(!HouseRateShapeOK(100000, 99999, gp.nRateSpreadBps));    // ask below bid
    BOOST_CHECK(!HouseRateShapeOK(0, 0, gp.nRateSpreadBps));

    BOOST_CHECK(!ApplyHouseRatePost(units, 7, 100000, 103000, 10, 10 * DAY, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-rate-spread");
    BOOST_CHECK(!units.Have(HouseRateKey(7)));   // a refused posting writes nothing

    BOOST_CHECK(ApplyHouseRatePost(units, 7, 100000, 101000, 10, 10 * DAY, gp, strReject));
    BOOST_CHECK(!HouseRateAt(units, 7, 10, nBid, nAsk));   // takes effect from the next block
    BOOST_CHECK(HouseRateAt(units, 7, 11, nBid, nAsk));
    BOOST_CHECK_EQUAL(nBid, 100000u);
    BOOST_CHECK_EQUAL(nAsk, 101000u);

    BOOST_CHECK(!ApplyHouseRatePost(units, 7, 90000, 90000, 10, 10 * DAY + 60, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-rate-same-block");

    BOOST_CHECK(ApplyHouseRatePost(units, 7, 90000, 90000, 12, 10 * DAY + 600, gp, strReject));   // falls: no cap
    BOOST_CHECK(HouseRateAt(units, 7, 12, nBid, nAsk));    // the block it is posted in: the previous rate
    BOOST_CHECK_EQUAL(nBid, 100000u);
    BOOST_CHECK(HouseRateAt(units, 7, 13, nBid, nAsk));
    BOOST_CHECK_EQUAL(nBid, 90000u);

    BOOST_CHECK(HouseRateFresh(units, 7, 11 * DAY + 600, gp.nRateRefreshSecs));
    BOOST_CHECK(!HouseRateFresh(units, 7, 11 * DAY + 601, gp.nRateRefreshSecs));
    BOOST_CHECK(!HouseRateFresh(units, 8, 10 * DAY, gp.nRateRefreshSecs));   // never posted
}

BOOST_AUTO_TEST_CASE(rate_rise_cap)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t t0 = 100 * DAY;
    BOOST_CHECK(ApplyHouseRatePost(units, 1, 100000, 100000, 1, t0, gp, strReject));
    // Within 24 h of the window's start the bid may reach 125% of its base, not more, and not by steps either.
    BOOST_CHECK(!ApplyHouseRatePost(units, 1, 125001, 125001, 2, t0 + 3600, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-rate-rise");
    BOOST_CHECK(ApplyHouseRatePost(units, 1, 120000, 120000, 3, t0 + 3600, gp, strReject));
    BOOST_CHECK(ApplyHouseRatePost(units, 1, 125000, 125000, 4, t0 + 7200, gp, strReject));
    BOOST_CHECK(!ApplyHouseRatePost(units, 1, 130000, 130000, 5, t0 + 7300, gp, strReject));
    // 24 h after the window started it restarts from the bid then in effect.
    BOOST_CHECK(ApplyHouseRatePost(units, 1, 156250, 156250, 6, t0 + DAY, gp, strReject));
    BOOST_CHECK(!ApplyHouseRatePost(units, 1, 160000, 160000, 7, t0 + DAY + 60, gp, strReject));
}

BOOST_AUTO_TEST_CASE(rate_window_max)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    uint64_t nMaxBid = 0, nMaxAsk = 0;

    BOOST_CHECK(!HouseRateWindowMax(units, 3, 1, 10 * DAY, 30, nMaxBid, nMaxAsk));
    BOOST_CHECK(ApplyHouseRatePost(units, 3, 100000, 101000, 1, 10 * DAY + 5, gp, strReject));
    // Day 20: 90. Days 11-19 had 100 in effect unposted; the posting fills them.
    BOOST_CHECK(ApplyHouseRatePost(units, 3, 90000, 90000, 2, 20 * DAY + 5, gp, strReject));
    BOOST_CHECK(HouseRateWindowMax(units, 3, 3, 20 * DAY + 10, 5, nMaxBid, nMaxAsk));
    BOOST_CHECK_EQUAL(nMaxBid, 100000u);
    BOOST_CHECK_EQUAL(nMaxAsk, 101000u);
    BOOST_CHECK(HouseRateWindowMax(units, 3, 3, 20 * DAY + 10, 0, nMaxBid, nMaxAsk));   // no window: the rate now
    BOOST_CHECK_EQUAL(nMaxBid, 90000u);
    // Day 40: 80. Day 40 itself had 90 until the posting.
    BOOST_CHECK(ApplyHouseRatePost(units, 3, 80000, 80000, 4, 40 * DAY + 5, gp, strReject));
    BOOST_CHECK(HouseRateWindowMax(units, 3, 5, 50 * DAY, 30, nMaxBid, nMaxAsk));
    BOOST_CHECK_EQUAL(nMaxBid, 90000u);
    // Day 75: the 30-day window (days 46-75) saw only 80, which is the rate in effect, recorded or not.
    BOOST_CHECK(HouseRateWindowMax(units, 3, 5, 75 * DAY, 30, nMaxBid, nMaxAsk));
    BOOST_CHECK_EQUAL(nMaxBid, 80000u);
    BOOST_CHECK_EQUAL(nMaxAsk, 80000u);
}

BOOST_AUTO_TEST_CASE(rate_payload_shape)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_RATE;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("01"), 0);   // not a coinbase
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;

    HouseRate r;
    r.nHouseID = 4;
    r.nKind = HOUSE_RATE_POST;
    r.nBid = 100000;
    r.nAsk = 101000;
    r.vchRateSig.assign(71, 0x30);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << r;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    CValidationState state;
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(mtx), state));

    r.vchRatePubKey.assign(pub.begin(), pub.end());   // a POST carries no key
    ss.clear();
    ss << r;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-rate-post");

    HouseRate k;
    k.nHouseID = 4;
    k.nKind = HOUSE_RATE_SETKEY;
    k.vchRatePubKey.assign(pub.begin(), pub.end());
    k.vApproverIndex.push_back(0);
    k.vApproverSig.push_back(std::vector<unsigned char>(71, 0x30));
    ss.clear();
    ss << k;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    CValidationState state2;
    BOOST_CHECK_MESSAGE(CheckHouseTransactionShape(CTransaction(mtx), state2), state2.GetRejectReason());

    k.nBid = 1;   // a SETKEY carries no rate
    ss.clear();
    ss << k;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    CValidationState state3;
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state3));
    BOOST_CHECK_EQUAL(state3.GetRejectReason(), "bad-house-rate-setkey");
}

BOOST_AUTO_TEST_CASE(charter_add_remove_related)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t t0 = 200 * DAY;
    HouseCharter add;
    add.nHouseID = 5;
    add.nKind = HOUSE_CHARTER_ADD;
    add.nChainID = 1;
    add.vchContract.assign(20, 0x45);   // PAXG-like
    add.nDecimals = 18;
    add.nGramsNum = 311034768;
    add.nGramsDen = 10000000;
    add.nRelated = HOUSE_RELATED_NO;
    BOOST_CHECK(ApplyHouseCharter(units, add, 10, t0, gp, strReject));
    BOOST_CHECK(!ApplyHouseCharter(units, add, 11, t0 + 60, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-charter-duplicate");
    CCharterToken tok;
    BOOST_CHECK(HouseCharterTokenAt(units, 5, 1, add.vchContract, t0, tok));
    BOOST_CHECK_EQUAL(tok.nRelated, HOUSE_RELATED_NO);

    // The last entry can't be removed; with a second one it can, 30 days on.
    HouseCharter rem;
    rem.nHouseID = 5;
    rem.nKind = HOUSE_CHARTER_REMOVE;
    rem.nIndex = 0;
    BOOST_CHECK(!ApplyHouseCharter(units, rem, 12, t0 + 120, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-charter-last");
    HouseCharter add2 = add;
    add2.vchContract.assign(20, 0x68);   // XAUT-like
    add2.nDecimals = 6;
    BOOST_CHECK(ApplyHouseCharter(units, add2, 13, t0 + 180, gp, strReject));
    BOOST_CHECK(ApplyHouseCharter(units, rem, 14, t0 + 240, gp, strReject));
    BOOST_CHECK(HouseCharterTokenAt(units, 5, 1, add.vchContract, t0 + 240 + gp.nCharterRemovalSecs - 1, tok));
    BOOST_CHECK(!HouseCharterTokenAt(units, 5, 1, add.vchContract, t0 + 240 + gp.nCharterRemovalSecs, tok));
    // Now the second entry is the house's last one not being removed.
    rem.nIndex = 1;
    BOOST_CHECK(!ApplyHouseCharter(units, rem, 15, t0 + 300, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-charter-last");

    // RELATED restates the declaration; a removed entry can't be restated once its removal took effect.
    HouseCharter rel;
    rel.nHouseID = 5;
    rel.nKind = HOUSE_CHARTER_RELATED;
    rel.nIndex = 1;
    rel.nRelated = HOUSE_RELATED_YES;
    BOOST_CHECK(ApplyHouseCharter(units, rel, 16, t0 + 360, gp, strReject));
    BOOST_CHECK(HouseCharterTokenAt(units, 5, 1, add2.vchContract, t0 + 360, tok));
    BOOST_CHECK_EQUAL(tok.nRelated, HOUSE_RELATED_YES);
    BOOST_CHECK_EQUAL(tok.nRelatedHeight, 16u);
    rel.nIndex = 0;
    BOOST_CHECK(!ApplyHouseCharter(units, rel, 17, t0 + 240 + gp.nCharterRemovalSecs, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-charter-index");
}

BOOST_AUTO_TEST_CASE(swap_rate_shortfall_and_pending)
{
    CSwapRecord r;
    r.nHouseID = 9;
    r.nUnits = 20000;            // 20 g
    r.nBid0 = 100000;            // sats per gram at the demand
    r.nDeadlineActive = 5000;
    // Before the deadline a payment is at the demand's bid; after it, at the lower of that and the bid then.
    BOOST_CHECK_EQUAL(SwapPayRate(r, 80000, 4999), 100000u);
    BOOST_CHECK_EQUAL(SwapPayRate(r, 80000, 5000), 80000u);
    BOOST_CHECK_EQUAL(SwapPayRate(r, 120000, 6000), 100000u);   // a higher bid at T_f is no free option
    // Once the bid at T_f is fixed, a later, lower bid doesn't lower the payment (the house can't time it).
    CSwapRecord rT = r;
    rT.nBidT = 90000;
    BOOST_CHECK_EQUAL(SwapPayRate(rT, 70000, 9000), 90000u);
    // The shortfall in mg: units x (1 - rate / bid0), rounded up; none at or above bid0.
    BOOST_CHECK_EQUAL(SwapShortfallMg(r, 80000), 4000u);
    BOOST_CHECK_EQUAL(SwapShortfallMg(r, 100000), 0u);
    BOOST_CHECK_EQUAL(SwapShortfallMg(r, 99999), 1u);

    CUnitsView units(nullptr);
    const uint256 h1 = uint256S("11"), h2 = uint256S("22");
    SwapOpen(units, h1, r);
    CSwapRecord r2 = r;
    r2.nUnits = 15000;
    SwapOpen(units, h2, r2);
    BOOST_CHECK_EQUAL(HousePendingSwapUnits(units, 9), 35000u);
    SwapMarkProtested(units, h2);
    CSwapRecord got;
    BOOST_REQUIRE(units.Get(SwapKey(h2), got));
    BOOST_CHECK_EQUAL(got.nStatus, SWAP_PROTESTED);
    BOOST_CHECK(got.Open());
    SwapSettle(units, h1, SWAP_DONE, 0, 777);
    BOOST_CHECK_EQUAL(HousePendingSwapUnits(units, 9), 15000u);
    SwapSettle(units, h2, SWAP_PAID, 80000, 888);
    BOOST_CHECK_EQUAL(HousePendingSwapUnits(units, 9), 0u);
    BOOST_REQUIRE(units.Get(SwapKey(h2), got));
    BOOST_CHECK_EQUAL(got.nStatus, SWAP_PAID);
    BOOST_CHECK(!got.Open());
    BOOST_CHECK_EQUAL(got.nShortfallMg, 3000u);
    BOOST_CHECK_EQUAL(got.nSettleTime, 888);
}

BOOST_AUTO_TEST_CASE(bid_at_deadline_from_postings)
{
    // The bid at T_f is the HIGHEST bid in effect in the day before it (review 2026-11-07: a dip posted just before T_f
    // and restored after it counts nothing); when the record's two postings can't show the whole day, the fallback (the
    // bid at demand) stands.
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t A = 1000;   // active time of the first posting
    BOOST_CHECK(ApplyHouseRatePost(units, 2, 100000, 100000, 1, 10 * DAY, gp, strReject, A));
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + DAY, 7, DAY), 100000u);           // only it in the day
    BOOST_CHECK(ApplyHouseRatePost(units, 2, 90000, 90000, 2, 12 * DAY, gp, strReject, A + 2 * DAY));
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + DAY, 7, DAY), 100000u);           // T_f before the cut
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + 2 * DAY + 100, 7, DAY), 100000u); // the cut came within the day: the high
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + 3 * DAY + 1, 7, DAY), 90000u);    // a day later only the cut
    BOOST_CHECK(ApplyHouseRatePost(units, 2, 80000, 80000, 3, 12 * DAY + 600, gp, strReject, A + 2 * DAY + 600));
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + 2 * DAY + 700, 7, DAY), 7u);      // two postings in the day: the fallback
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 9, A + DAY, 7, DAY), 7u);                // never posted
}

BOOST_AUTO_TEST_CASE(swap_payload_shape)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_SWAP;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("01"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    NoteSwap sw;
    sw.nHouseID = 3;
    sw.nUnits = 10000;
    sw.vchHolderPubKey.assign(pub.begin(), pub.end());
    sw.vchHolderSig.assign(71, 0x30);
    sw.nChainID = 1;
    sw.vchContract.assign(20, 0x45);
    sw.vchEthAddress.assign(20, 0x77);
    sw.hashLock = uint256S("aa");
    sw.vchPayoutScript = {0x51};
    const auto fnShape = [&](const NoteSwap& s) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << s;
        mtx.vchNotePayload.assign(ss.begin(), ss.end());
        CValidationState state;
        return CheckNoteTransactionShape(CTransaction(mtx), state) ? std::string("") : state.GetRejectReason();
    };
    BOOST_CHECK_EQUAL(fnShape(sw), "");
    NoteSwap small = sw;
    small.nUnits = NOTE_SWAP_MIN_MG - 1;   // under 10 g
    BOOST_CHECK_EQUAL(fnShape(small), "bad-note-swap-payload");
    NoteSwap noaddr = sw;
    noaddr.vchEthAddress.assign(20, 0);
    BOOST_CHECK_EQUAL(fnShape(noaddr), "bad-note-swap-payload");
    NoteSwap nolock = sw;
    nolock.hashLock.SetNull();
    BOOST_CHECK_EQUAL(fnShape(nolock), "bad-note-swap-payload");
}

// Gold B waterfall (GOLD_B.md §6): a failed swap paid below its bid at demand keeps its shortfall in the house's ledger
// for the lapse; a claim from a failed house takes a pending swap out of the pending count.
BOOST_AUTO_TEST_CASE(swap_claim_and_shortfall_ledger)
{
    CUnitsView units(nullptr);
    CSwapRecord rec;
    rec.nHouseID = 3;
    rec.nUnits = 20000;
    rec.nBid0 = 1000;
    rec.vchPayoutScript = {0x51};
    const uint256 h1 = uint256S("01"), h2 = uint256S("02");
    SwapOpen(units, h1, rec);
    SwapOpen(units, h2, rec);
    BOOST_CHECK_EQUAL(HousePendingSwapUnits(units, 3), 40000u);
    // h2 paid at 800 after its deadline, at clock 500: its shortfall goes in the ledger.
    SwapSettle(units, h2, SWAP_PAID, 800, 0, 500, 12960);
    CSwapRecord r2;
    BOOST_REQUIRE(units.Get(SwapKey(h2), r2));
    BOOST_CHECK_EQUAL(r2.nShortfallMg, SwapShortfallMg(rec, 800));
    BOOST_CHECK(r2.nShortfallMg > 0);
    BOOST_CHECK_EQUAL(r2.nSettleClock, 500);
    BOOST_CHECK_EQUAL(HouseLiveShortfallMg(units, 3, 600, 12960), r2.nShortfallMg);
    BOOST_CHECK_EQUAL(HouseLiveShortfallMg(units, 3, 500 + 12961, 12960), 0u);   // lapsed
    BOOST_CHECK_EQUAL(HouseLiveShortfallMg(units, 3, 499, 12960), 0u);           // not paid yet at that clock
    BOOST_CHECK_EQUAL(HousePendingSwapUnits(units, 3), 20000u);
    // h1 claimed from the failed house: it leaves the pending count.
    SwapClaim(units, h1);
    CSwapRecord r1;
    BOOST_REQUIRE(units.Get(SwapKey(h1), r1));
    BOOST_CHECK_EQUAL(r1.nStatus, SWAP_CLAIMED);
    BOOST_CHECK(!r1.Open());
    BOOST_CHECK_EQUAL(HousePendingSwapUnits(units, 3), 0u);
}

// Review 2026-11-07: a formal demand fixes the rate at the demand - the bid in effect at its block is recorded once and a
// later cut doesn't change it; and a failed house's windows end at its failure (the window as of then keeps the highs).
BOOST_AUTO_TEST_CASE(demand_bid_and_anchored_window)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    BOOST_CHECK(ApplyHouseRatePost(units, 4, 100000, 101000, 1, 10 * DAY, gp, strReject));
    RecordDemandBid(units, 4, 5);                 // a demand at block 5: the bid then is 100000
    uint64_t nRec = 0;
    BOOST_CHECK(units.Get(DemandBidKey(4, 5), nRec));
    BOOST_CHECK_EQUAL(nRec, 100000u);
    BOOST_CHECK(ApplyHouseRatePost(units, 4, 1, 1, 6, 10 * DAY + 60, gp, strReject));   // the house cuts to 1 sat/g
    RecordDemandBid(units, 4, 5);                 // recorded once: not overwritten
    BOOST_CHECK(units.Get(DemandBidKey(4, 5), nRec));
    BOOST_CHECK_EQUAL(nRec, 100000u);
    // The window as of the failure (day 10) holds the high; run on to day 200 it would have lost it.
    uint64_t nMaxBid = 0, nMaxAsk = 0;
    BOOST_CHECK(HouseRateWindowMax(units, 4, 7, 10 * DAY + 120, 90, nMaxBid, nMaxAsk));
    BOOST_CHECK_EQUAL(nMaxBid, 100000u);
    BOOST_CHECK(HouseRateWindowMax(units, 4, 7, 200 * DAY, 90, nMaxBid, nMaxAsk));
    BOOST_CHECK_EQUAL(nMaxBid, 1u);
}

BOOST_AUTO_TEST_SUITE_END()
