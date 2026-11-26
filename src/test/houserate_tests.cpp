// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Gold B (D-2026-11-07-1; GOLD_B.md §1): each house's own rate and the chain clock.

#include <houserate.h>
#include <house.h>
#include <note.h>

#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <issued.h>       // ConnectIssuedTx (the H2 restore tests)
#include <key.h>
#include <primitives/transaction.h>
#include <test/test_bitcoin.h>
#include <tinyformat.h>
#include <units.h>

#include <boost/test/unit_test.hpp>

#include <random>   // testing: run 4 properties (std::mt19937)

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

    BOOST_CHECK(HouseRateFresh(units, 7, 13, 11 * DAY + 600, gp.nRateRefreshSecs));
    BOOST_CHECK(!HouseRateFresh(units, 7, 13, 11 * DAY + 601, gp.nRateRefreshSecs));
    BOOST_CHECK(!HouseRateFresh(units, 8, 13, 10 * DAY, gp.nRateRefreshSecs));   // never posted

    // D-2026-11-11-3 (RS-1): freshness goes with the price. In the POST's own block (12) the posting in effect is the
    // one from block 10 (10 * DAY), so a day and a second later the house is stale there, though the block-12 POST
    // (10 * DAY + 600) would be fresh: a stale house can't POST and issue in one block. From block 13 it counts.
    BOOST_CHECK(!HouseRateFresh(units, 7, 12, 11 * DAY + 1, gp.nRateRefreshSecs));
    BOOST_CHECK(HouseRateFresh(units, 7, 13, 11 * DAY + 1, gp.nRateRefreshSecs));
    // A first posting has no rate in effect in its own block: not fresh there, fresh from the next.
    BOOST_CHECK(ApplyHouseRatePost(units, 9, 100000, 101000, 20, 20 * DAY, gp, strReject));
    BOOST_CHECK(!HouseRateFresh(units, 9, 20, 20 * DAY, gp.nRateRefreshSecs));
    BOOST_CHECK(HouseRateFresh(units, 9, 21, 20 * DAY, gp.nRateRefreshSecs));
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
    // UR1-5 (switch-on): 24 h after the window started, the bound still counts the lowest bid in effect over the last
    // 24 h (100,000 until t0 + 3600), so 156,250 (+25% on +25%) is refused; 125,000 is the most.
    BOOST_CHECK(!ApplyHouseRatePost(units, 1, 156250, 156250, 6, t0 + DAY, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-rate-rise");
    BOOST_CHECK(ApplyHouseRatePost(units, 1, 125000, 125000, 6, t0 + DAY, gp, strReject));
    // Once 125,000 has been the lowest bid in effect for a full window, 156,250 is allowed.
    BOOST_CHECK(ApplyHouseRatePost(units, 1, 156250, 156250, 7, t0 + 3 * DAY, gp, strReject));
    BOOST_CHECK(!ApplyHouseRatePost(units, 1, 200000, 200000, 8, t0 + 3 * DAY + 60, gp, strReject));
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
    // S1X-22: read at the start of day 50 the 30-day window is today plus the 30 whole days before (days 20-50), and
    // 100 was in effect on day 20 until 20 * DAY + 5, 30 days less 5 s ago: it counts (it dropped out before).
    BOOST_CHECK(HouseRateWindowMax(units, 3, 5, 50 * DAY, 30, nMaxBid, nMaxAsk));
    BOOST_CHECK_EQUAL(nMaxBid, 100000u);
    // A day later only 90 (days 21-51).
    BOOST_CHECK(HouseRateWindowMax(units, 3, 5, 51 * DAY, 30, nMaxBid, nMaxAsk));
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
    rem.nChainID = add.nChainID;              // UR1-1: the op names the token at its index
    rem.vchContract = add.vchContract;
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
    rem.vchContract = add2.vchContract;
    BOOST_CHECK(!ApplyHouseCharter(units, rem, 15, t0 + 300, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-charter-last");

    // RELATED restates the declaration; a removed entry can't be restated once its removal took effect.
    HouseCharter rel;
    rel.nHouseID = 5;
    rel.nKind = HOUSE_CHARTER_RELATED;
    rel.nIndex = 1;
    rel.nChainID = add2.nChainID;             // UR1-1
    rel.vchContract = add2.vchContract;
    rel.nRelated = HOUSE_RELATED_YES;
    BOOST_CHECK(ApplyHouseCharter(units, rel, 16, t0 + 360, gp, strReject));
    BOOST_CHECK(HouseCharterTokenAt(units, 5, 1, add2.vchContract, t0 + 360, tok));
    BOOST_CHECK_EQUAL(tok.nRelated, HOUSE_RELATED_YES);
    BOOST_CHECK_EQUAL(tok.nRelatedHeight, 16u);
    rel.nIndex = 0;
    rel.vchContract = add.vchContract;
    BOOST_CHECK(!ApplyHouseCharter(units, rel, 17, t0 + 240 + gp.nCharterRemovalSecs, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-charter-index");
    // UR1-1: naming a different token than the one at the index is refused
    rel.nIndex = 1;
    rel.vchContract = add.vchContract;        // index 1 is add2's token, not add's
    BOOST_CHECK(!ApplyHouseCharter(units, rel, 18, t0 + 400, gp, strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-house-charter-mismatch");
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

// S1X-19 (security: Low; Michael 11-25 yes): a posting counts from its own block's clock (RS-1: it takes effect the
// block after), not from the parent's clock it was connected under. At the exact boundary - the window starting at the
// parent's active time of the cut's block - the old high bid was still in force for that block, so it counts.
BOOST_AUTO_TEST_CASE(s1x_19_post_dated_from_its_own_block)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t A = 1000;
    auto clockAt = [&](uint32_t h, int64_t nActive) { CClockAt at; at.nActive = nActive; at.nMono = nActive; units.Put(ClockAtKey(h), at); };
    BOOST_CHECK(ApplyHouseRatePost(units, 2, 100000, 100000, 1, 10 * DAY, gp, strReject, A));   // P, connected under A
    clockAt(1, A + 600);                                                                     // block 1's own clock
    const int64_t PA = A + 2 * DAY;                                                          // the cut's parent clock
    BOOST_CHECK(ApplyHouseRatePost(units, 2, 90000, 90000, 50, 12 * DAY, gp, strReject, PA));  // C, connected under PA
    clockAt(50, PA + 600);                                                                   // block 50's own clock
    // The window [PA, PA + DAY]: the old bid was in force for block 50, so the high counts (it read 90000 before).
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, PA + DAY, 7, DAY), 100000u);
    // From the cut's own clock on, the window holds the cut alone.
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, PA + 600 + DAY, 7, DAY), 90000u);
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, PA + 599 + DAY, 7, DAY), 100000u);
    // Read in the posting block itself (nHeight 50: its clock record would not exist yet) the current posting is the
    // one before (D-2026-11-20-2), dated from block 1's clock. S1X-40: the record at the block's start had that posting
    // alone (none before it), so it is the answer either side of its own date, as a read before the POST gives.
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + 600 + DAY, 7, DAY, 50), 100000u);
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + 599 + DAY, 7, DAY, 50), 100000u);
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

// testing (2026-11-10), ultra s1 UR1-5 = security stage A H2. The rise cap measures a bid against the bid in effect
// when the window last RESTARTED, and the window restarts from whatever was posted last. So 125% just before the window
// ends and 125% of THAT just after it both pass: 56% over the bid in effect a minute earlier, which is what the cap
// exists to stop a stolen rate key doing. FAILS on v1.2.1; passes with a rolling-window bound. (rate_rise_cap's
// "restarts from the bid then in effect" assertion encodes the old behaviour and flips with the fix.)
BOOST_AUTO_TEST_CASE(testing_ur1_5_rate_rise_window_edge)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t t0 = 300 * DAY;
    const int64_t W = gp.nRateRiseWindowSecs;
    BOOST_REQUIRE(ApplyHouseRatePost(units, 2, 100000, 100000, 1, t0, gp, strReject));
    // 25% one minute before the window ends: allowed (100,000 was in effect the whole window)
    BOOST_CHECK(ApplyHouseRatePost(units, 2, 125000, 125000, 2, t0 + W - 60, gp, strReject));
    // one minute later: 156,250 is 156% of the bid in effect 60 s before - must be refused
    BOOST_CHECK_MESSAGE(!ApplyHouseRatePost(units, 2, 156250, 156250, 3, t0 + W, gp, strReject),
                        "a 56% bid rise in two posts 60 s apart was accepted (UR1-5 / stage A H2)");
}

// testing (2026-11-10), ultra s1 UR1-1. A charter REMOVE (and RELATED) names its target by INDEX, and the approvers'
// sighash binds only the index (the shape rule forces nChainID 0 and an empty contract on these kinds). An ADD prunes
// entries whose removal took effect and renumbers the list. So a REMOVE signed for one token lands on another if an
// unrelated ADD confirms first. Whatever the fix (bind the token's identity, or tombstones), the token the partners
// did NOT name must never be removed. FAILS on v1.2.1 (it removes C); passes once the op is bound to the token.
BOOST_AUTO_TEST_CASE(testing_ur1_1_charter_remove_after_renumber)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t t0 = 400 * DAY;
    auto tok = [](unsigned char c) { return std::vector<unsigned char>(20, c); };
    auto add = [&](unsigned char c, uint32_t h, int64_t t) {
        HouseCharter op;
        op.nHouseID = 6;
        op.nKind = HOUSE_CHARTER_ADD;
        op.nChainID = 1;
        op.vchContract = tok(c);
        op.nDecimals = 18;
        op.nGramsNum = 311034768;
        op.nGramsDen = 10000000;
        op.nRelated = HOUSE_RELATED_NO;
        return ApplyHouseCharter(units, op, h, t, gp, strReject);
    };
    BOOST_REQUIRE(add(0x41, 10, t0));        // A, index 0
    BOOST_REQUIRE(add(0x42, 11, t0 + 60));   // B, index 1  <- the token the partners mean to remove
    BOOST_REQUIRE(add(0x43, 12, t0 + 120));  // C, index 2
    BOOST_REQUIRE(add(0x44, 13, t0 + 180));  // D, index 3
    HouseCharter remA;
    remA.nHouseID = 6;
    remA.nKind = HOUSE_CHARTER_REMOVE;
    remA.nIndex = 0;
    remA.nChainID = 1;                 // the fix (UR1-1): the op names its token
    remA.vchContract = tok(0x41);
    BOOST_REQUIRE(ApplyHouseCharter(units, remA, 14, t0 + 240, gp, strReject));   // A leaves 30 days on

    // Past A's removal: A is dead but still at index 0, so B is still at index 1 - the partners sign "REMOVE 1" for B.
    const int64_t t2 = t0 + 240 + gp.nCharterRemovalSecs + 1;
    CCharterToken got;
    BOOST_REQUIRE(!HouseCharterTokenAt(units, 6, 1, tok(0x41), t2, got));   // A dead
    // An unrelated ADD confirms first: it prunes A and renumbers to [B, C, D, E].
    BOOST_REQUIRE(add(0x45, 15, t2));
    // The signed REMOVE for B (its identity filled in, which v1.2.1 ignores for this kind).
    HouseCharter remB;
    remB.nHouseID = 6;
    remB.nKind = HOUSE_CHARTER_REMOVE;
    remB.nIndex = 1;
    remB.nChainID = 1;
    remB.vchContract = tok(0x42);
    ApplyHouseCharter(units, remB, 16, t2 + 60, gp, strReject);   // the fix may apply it to B or refuse it: either is fine
    const int64_t tAfter = t2 + 60 + gp.nCharterRemovalSecs;
    BOOST_CHECK_MESSAGE(HouseCharterTokenAt(units, 6, 1, tok(0x43), tAfter, got),
                        "a REMOVE signed for token B removed token C after an ADD renumbered the charter (UR1-1)");
    BOOST_CHECK(HouseCharterTokenAt(units, 6, 1, tok(0x44), tAfter, got));   // D untouched either way
    BOOST_CHECK(HouseCharterTokenAt(units, 6, 1, tok(0x45), tAfter, got));   // E untouched either way
}

// ===========================================================================
// testing (2026-11-10): item 2 of Michael's sign-off (UR1-5 + stage A H2, freebank
// docs-local/CONSENSUS_SIGNOFF_2026-11-10.md), H2's second half. A thief holding the rate key cuts the bid to 1; the
// rise cap then makes the house climb back in 25% steps (about 52 days from 1 to 100,000) even after its partners
// SETKEY a new key. freebankd's fix (2026-11-10): a partners' SETKEY arms a one-shot restore - the house's first post
// within W (24 h) of it may go up to the highest bid in effect over the last 30 days, never above; any post clears it.
// Every op here runs through ConnectIssuedTx over an in-memory units DB, one block per op, each block journaled, so
// the tests read the same path a block does and can undo it.
// FAIL on master a00fb05 (no restore: the post at the 30-day max is refused); pass once the restore lands. The undo case
// is security's invariant-E check of the same change: SETKEY and a restore-level POST, disconnected, leave the units
// state byte-exact.
// ===========================================================================
namespace {
const uint32_t H2_HOUSE = 2;

CMutableTransaction H2RateTx(const HouseRate& rate, uint32_t nSeq)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_RATE;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("4832"), nSeq)));
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rate;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    return mtx;
}

// A short chain over one in-memory units DB: each Block() advances the chain clock, connects its rate ops through
// ConnectIssuedTx and writes the block with its undo record.
struct H2Chain {
    CUnitsDB db;
    CCoinsView coinsBase;
    CCoinsViewCache coins;
    std::vector<uint256> vHash;
    uint32_t nSeq;
    H2Chain() : db(1 << 20, true, true), coins(&coinsBase), nSeq(0) {}

    CMutableTransaction SetKey(const CKey& key)
    {
        HouseRate r;
        r.nHouseID = H2_HOUSE;
        r.nKind = HOUSE_RATE_SETKEY;
        const CPubKey pub = key.GetPubKey();
        r.vchRatePubKey.assign(pub.begin(), pub.end());
        return H2RateTx(r, nSeq++);
    }
    CMutableTransaction Post(const CKey& key, uint64_t nBid)
    {
        HouseRate r;
        r.nHouseID = H2_HOUSE;
        r.nKind = HOUSE_RATE_POST;
        r.nBid = r.nAsk = nBid;
        CMutableTransaction mtx = H2RateTx(r, nSeq++);
        BOOST_REQUIRE(key.Sign(HouseRateSigHash(CTransaction(mtx)), r.vchRateSig));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << r;
        mtx.vchHousePayload.assign(ss.begin(), ss.end());
        return mtx;
    }
    // One block at nTime holding one op; "" if it connected, else the reason.
    std::string Block(int64_t nTime, const CMutableTransaction& mtx)
    {
        const uint32_t nHeight = vHash.size() + 1;
        CUnitsView view(&db);
        AdvanceChainClock(view, nHeight, nTime, Params().GetConsensus().GramAt(nHeight));
        CValidationState state;
        const bool fOk = ConnectIssuedTx(CTransaction(mtx), coins, view, (int)nHeight, state);
        std::map<UnitsKey, UnitsSlot> mapChange, mapBefore;
        view.GetChanges(mapChange, mapBefore);
        const uint256 hash = uint256S(strprintf("%x", 0x48000 + nHeight));
        BOOST_REQUIRE(db.WriteBlock(mapChange, mapBefore, hash));
        vHash.push_back(hash);
        return fOk ? std::string() : (state.GetRejectReason().empty() ? std::string("(refused)") : state.GetRejectReason());
    }
    void Undo()
    {
        const uint256 hash = vHash.back();
        vHash.pop_back();
        BOOST_REQUIRE(db.UndoBlock(hash, vHash.empty() ? uint256S("00") : vHash.back()));
    }
};

const int64_t H2_T0 = 300 * DAY;
// The partners' SETKEY, two days after the thief's cut: the cut's own rise window (which on master still allows 125% of
// the pre-cut bid) has closed, so the climb back is H2's 25% steps from 1.
const int64_t H2_TKEY = H2_T0 + 12 * DAY;

// Key A posts 100,000 at T0; ten days later a thief holding A cuts the bid to 1.
void H2Setup(H2Chain& c, const CKey& keyA)
{
    BOOST_REQUIRE(c.Block(H2_T0 - 600, c.SetKey(keyA)).empty());
    BOOST_REQUIRE(c.Block(H2_T0, c.Post(keyA, 100000)).empty());
    BOOST_REQUIRE(c.Block(H2_T0 + 10 * DAY, c.Post(keyA, 1)).empty());   // the thief's cut (cuts are never capped)
}

std::string H2Show(const std::string& s) { return s.empty() ? std::string("accepted") : "refused (" + s + ")"; }
} // namespace

// S1X-11 (security's counter, adopted; Michael 11-25 yes): the partners' SETKEY restore survives their routine re-post
// (or an in-bound rise) and is still there for the restore itself; a CUT clears it, so the rate key alone can't cut and
// snap back within W.
BOOST_AUTO_TEST_CASE(s1x_11_restore_survives_a_repost_not_a_cut)
{
    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    {   // a re-post of the current bid keeps the restore
        H2Chain c;
        H2Setup(c, keyA);                                            // 100,000, then the thief's cut to 1
        BOOST_REQUIRE(c.Block(H2_TKEY, c.SetKey(keyB)).empty());
        BOOST_CHECK(c.Block(H2_TKEY + 600, c.Post(keyB, 1)).empty());   // the ticker re-posts the current bid
        const std::string str = c.Block(H2_TKEY + 1200, c.Post(keyB, 100000));
        BOOST_CHECK_MESSAGE(str.empty(), "S1X-11: the restore after a re-post was " + H2Show(str));
    }
    {   // a cut clears it
        H2Chain c;
        BOOST_REQUIRE(c.Block(H2_T0 - 600, c.SetKey(keyA)).empty());
        BOOST_REQUIRE(c.Block(H2_T0, c.Post(keyA, 100000)).empty());
        BOOST_REQUIRE(c.Block(H2_T0 + 10 * DAY, c.Post(keyA, 80000)).empty());   // a cut by the old key
        BOOST_REQUIRE(c.Block(H2_TKEY, c.SetKey(keyB)).empty());
        BOOST_CHECK(c.Block(H2_TKEY + 600, c.Post(keyB, 80000)).empty());          // a re-post keeps it ...
        BOOST_CHECK(c.Block(H2_TKEY + 1200, c.Post(keyB, 70000)).empty());         // ... a cut clears it
        const std::string str = c.Block(H2_TKEY + 1800, c.Post(keyB, 100000));
        BOOST_CHECK_MESSAGE(str == "bad-house-rate-rise", "S1X-11: a snap-back after a cut was " + H2Show(str));
    }
}

BOOST_AUTO_TEST_CASE(testing_h2_setkey_arms_a_restore)
{
    const int64_t W = Params().GetConsensus().GramAt(1).nRateRiseWindowSecs;
    CKey keyA, keyB, keyC;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    keyC.MakeNewKey(true);

    // (a) After the SETKEY: one above the 30-day max is refused; the max itself is accepted. (d) Then +25% over the
    // restored bid waits until the restored bid has been in effect for a full W (security 11-10, SW-1: a restore that
    // reset the rise windows let SETKEY + re-post + 25% climb 25% every few blocks, past item 2's "1.25x the lowest bid
    // of the last 24 h"). testing's first (d) asserted the reset; this replaces it.
    {
        H2Chain c;
        H2Setup(c, keyA);
        BOOST_REQUIRE(c.Block(H2_TKEY, c.SetKey(keyB)).empty());
        const std::string strOver = c.Block(H2_TKEY + 600, c.Post(keyB, 100001));
        BOOST_CHECK_MESSAGE(strOver == "bad-house-rate-rise", "H2 (a): a post one above the 30-day max after the "
                            "SETKEY was " + H2Show(strOver) + ", want bad-house-rate-rise");
        const std::string strMax = c.Block(H2_TKEY + 1200, c.Post(keyB, 100000));
        BOOST_CHECK_MESSAGE(strMax.empty(), "H2 (a): after a cut to 1 and a partners' SETKEY, a post at the 30-day "
                            "max (100,000) within W was " + H2Show(strMax));
        // (d), as fixed for security's SW-1 (switch-on review): for a full W after the restore nothing above the
        // restored bid R; R itself can be re-posted; after R has been in effect for W, the normal 25% applies from R.
        const std::string strRise = c.Block(H2_TKEY + 1800, c.Post(keyB, 125000));
        BOOST_CHECK_MESSAGE(strRise == "bad-house-rate-rise", "H2 (d): 25% over the restored bid within W was " +
                            H2Show(strRise) + " (SW-1: nothing above R for a full W)");
        const std::string strRepost = c.Block(H2_TKEY + 2400, c.Post(keyB, 100000));
        BOOST_CHECK_MESSAGE(strRepost.empty(), "H2 (d): re-posting the restored bid was " + H2Show(strRepost));
        const std::string strNormal = c.Block(H2_TKEY + 1200 + W + 600, c.Post(keyB, 125000));
        BOOST_CHECK_MESSAGE(strNormal.empty(), "H2 (d): 25% over the restored bid once it had been in effect for W was " +
                            H2Show(strNormal));
    }
    // (e) Security's SW-1 cycle: SETKEY, restore (or re-post) and post, over and over inside one W, never passes the
    // 30-day high (100,000).
    {
        H2Chain c;
        H2Setup(c, keyA);
        int64_t t = H2_TKEY;
        uint64_t nHigh = 0;
        for (int i = 0; i < 6; i++) {
            const CKey& k = (i % 2 == 0) ? keyB : keyC;
            BOOST_REQUIRE(c.Block(t, c.SetKey(k)).empty());
            t += 600;
            for (uint64_t nTry : {125000, 100001, 100000}) {
                if (c.Block(t, c.Post(k, nTry)).empty()) {
                    nHigh = std::max(nHigh, nTry);
                    break;
                }
            }
            t += 600;
        }
        BOOST_CHECK_MESSAGE(nHigh <= 100000, "H2 (e): repeated SETKEY / restore cycles inside one W reached " +
                            std::to_string(nHigh) + ", above the 30-day high 100,000 (SW-1 ratchet)");
    }
    // (b) A second SETKEY right after the first doesn't let the restore go higher.
    {
        H2Chain c;
        H2Setup(c, keyA);
        BOOST_REQUIRE(c.Block(H2_TKEY, c.SetKey(keyB)).empty());
        BOOST_REQUIRE(c.Block(H2_TKEY + 600, c.SetKey(keyC)).empty());
        const std::string strOver = c.Block(H2_TKEY + 1200, c.Post(keyC, 100001));
        BOOST_CHECK_MESSAGE(strOver == "bad-house-rate-rise", "H2 (b): after two SETKEYs, one above the 30-day max "
                            "was " + H2Show(strOver));
        const std::string strMax = c.Block(H2_TKEY + 1800, c.Post(keyC, 100000));
        BOOST_CHECK_MESSAGE(strMax.empty(), "H2 (b): after two SETKEYs, the 30-day max was " + H2Show(strMax));
    }
    // (c) A first post more than W after the SETKEY gets no restore.
    {
        H2Chain c;
        H2Setup(c, keyA);
        BOOST_REQUIRE(c.Block(H2_TKEY, c.SetKey(keyB)).empty());
        const std::string strLate = c.Block(H2_TKEY + W + 600, c.Post(keyB, 100000));
        BOOST_CHECK_MESSAGE(strLate == "bad-house-rate-rise", "H2 (c): a first post W + 10 min after the SETKEY, at "
                            "the 30-day max, was " + H2Show(strLate) + ": the restore should have lapsed");
    }
}

// Security 11-10 (SW-1): the restore must not reset the rise windows, or SETKEY + re-post + 25% climbs without limit.
// Each round below is a SETKEY (keys alternate), a re-post of the bid in effect (round 1 of the cut case restores to the
// 30-day high), then +25%, a block each, ten minutes apart, so every round of a case falls inside one W. Returns the
// highest bid any accepted post reached.
namespace {
uint64_t H2Cycle(H2Chain& c, int64_t& t, uint64_t nBid, const std::vector<CKey>& vKey, int nRounds, uint64_t nRestoreTo)
{
    uint64_t nHigh = 0;
    for (int i = 0; i < nRounds; i++) {
        const CKey& k = vKey[i % vKey.size()];
        BOOST_REQUIRE(c.Block(t, c.SetKey(k)).empty());
        t += 600;
        const uint64_t nRe = (i == 0 && nRestoreTo) ? nRestoreTo : nBid;
        if (c.Block(t, c.Post(k, nRe)).empty()) {
            nBid = nRe;
            nHigh = std::max(nHigh, nRe);
        }
        t += 600;
        const uint64_t nUp = nBid + nBid / 4;
        if (c.Block(t, c.Post(k, nUp)).empty()) {
            nBid = nUp;
            nHigh = std::max(nHigh, nUp);
        }
        t += 600;
    }
    return nHigh;
}
} // namespace

BOOST_AUTO_TEST_CASE(testing_h2_setkey_cycles_cannot_climb)
{
    CKey keyA, keyB, keyC;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    keyC.MakeNewKey(true);
    const std::vector<CKey> vKey = {keyB, keyC};

    // (1) After the thief's cut: five rounds inside one W never take the bid past the 30-day high (100,000).
    {
        H2Chain c;
        H2Setup(c, keyA);
        int64_t t = H2_TKEY;
        const uint64_t nHigh = H2Cycle(c, t, 1, vKey, 5, 100000);
        BOOST_CHECK_MESSAGE(nHigh <= 100000, "H2 cycle (cut): SETKEY + restore + 25% rounds inside one W took the bid "
                            "to " + std::to_string(nHigh) + ", past the 30-day high 100,000");
    }
    // (2) No cut: 100,000 in effect for ten days. Five rounds of SETKEY, re-post of the current bid, +25% inside one W:
    // the normal bound allows one +25% (to 125,000) and no more.
    {
        H2Chain c;
        BOOST_REQUIRE(c.Block(H2_T0 - 600, c.SetKey(keyA)).empty());
        BOOST_REQUIRE(c.Block(H2_T0, c.Post(keyA, 100000)).empty());
        int64_t t = H2_T0 + 10 * DAY;
        const uint64_t nHigh = H2Cycle(c, t, 100000, vKey, 5, 0);
        BOOST_CHECK_MESSAGE(nHigh <= 125000, "H2 cycle (no cut): SETKEY + re-post + 25% rounds inside one W took the bid "
                            "to " + std::to_string(nHigh) + ", past 1.25 x the lowest bid of the last 24 h (125,000)");
    }
    // (3) A post at or below the normal bound right after a SETKEY resets nothing. 120,000 for two days, then the house's
    // own cut to 100,000, in effect for eight; a SETKEY, then 110,000 (under both the normal bound 125,000 and the 30-day
    // high 120,000), then 137,500 = 1.25 x 110,000: refused, the lowest bid of the last 24 h is still 100,000.
    {
        H2Chain c;
        BOOST_REQUIRE(c.Block(H2_T0 - 600, c.SetKey(keyA)).empty());
        BOOST_REQUIRE(c.Block(H2_T0, c.Post(keyA, 120000)).empty());
        BOOST_REQUIRE(c.Block(H2_T0 + 2 * DAY, c.Post(keyA, 100000)).empty());
        const int64_t t = H2_T0 + 10 * DAY;
        BOOST_REQUIRE(c.Block(t, c.SetKey(keyB)).empty());
        const std::string strMid = c.Block(t + 600, c.Post(keyB, 110000));
        BOOST_CHECK_MESSAGE(strMid.empty(), "H2 (3): 110,000 after the SETKEY (within the normal bound) was " +
                            H2Show(strMid));
        const std::string strUp = c.Block(t + 1200, c.Post(keyB, 137500));
        BOOST_CHECK_MESSAGE(strUp == "bad-house-rate-rise", "H2 (3): 1.25 x 110,000 ten minutes later was " + H2Show(strUp) +
                            ": the post after the SETKEY reset the rise windows (the lowest bid of the last 24 h is "
                            "100,000)");
    }
}

// Security's invariant-E check: a SETKEY and a restore-level POST in the next block, both disconnected, leave every
// units key (the rate record with its rise and restore fields, the rate key, the day records, the clock) as it was.
BOOST_AUTO_TEST_CASE(testing_h2_setkey_restore_undoes_exactly)
{
    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    H2Chain c;
    H2Setup(c, keyA);
    const std::vector<std::pair<UnitsKey, UnitsValue>> vBefore = c.db.Scan(UnitsKey(), UnitsKey(), SIZE_MAX);
    BOOST_REQUIRE(!vBefore.empty());

    BOOST_REQUIRE(c.Block(H2_TKEY, c.SetKey(keyB)).empty());
    const std::string strRestore = c.Block(H2_TKEY + 600, c.Post(keyB, 100000));
    BOOST_CHECK_MESSAGE(strRestore.empty(), "H2 undo: the restore-level POST was " + H2Show(strRestore) +
                        " (no restore on this tree, so the undo below checks less than it should)");
    BOOST_CHECK(c.db.Scan(UnitsKey(), UnitsKey(), SIZE_MAX) != vBefore);   // the two blocks changed something

    c.Undo();
    c.Undo();
    const std::vector<std::pair<UnitsKey, UnitsValue>> vAfter = c.db.Scan(UnitsKey(), UnitsKey(), SIZE_MAX);
    size_t nDiff = 0;
    std::map<UnitsKey, UnitsValue> mapB(vBefore.begin(), vBefore.end()), mapA(vAfter.begin(), vAfter.end());
    for (const auto& p : mapB)
        if (!mapA.count(p.first) || mapA[p.first] != p.second)
            nDiff++;
    for (const auto& p : mapA)
        if (!mapB.count(p.first))
            nDiff++;
    BOOST_CHECK_MESSAGE(nDiff == 0, "H2 undo: after disconnecting the SETKEY and the restore POST, " +
                        std::to_string(nDiff) + " units key(s) differ from before them (invariant E)");
}

// testing (2026-11-10): stage A SA-H3 (security 11-08; consensus, on freebankd's second sign-off list for Michael).
// ClockBlocksForChecks judges block h on the clock record of h - 1. When that record is missing it extrapolates from the
// chain clock's tip - right for a height past the tip (the mempool's next block, a wallet's margin), wrong for a PAST
// height, where a missing record means a damaged units DB and any window judged on a made-up clock can come out either
// way. freebankd's contract (2026-11-10): a missing record at or below the clock's tip returns -1, ClockAtHeight /
// ClockSince / ClockDeadlineHeight propagate it, the mempool refuses with bad-clock-record-missing and connect treats it
// as a node-data error. Heights past the tip keep extrapolating. FAILS on master a00fb05 (the past height extrapolates).
BOOST_AUTO_TEST_CASE(testing_sa_h3_missing_past_clock_record_fails_closed)
{
    const bool fClockWas = g_fClockIsHeightForTests;
    g_fClockIsHeightForTests = false;                       // the real clock (unit tests count blocks by default)
    BOOST_REQUIRE(!Params().GetConsensus().fClockIsHeight);  // the unit tests' network keeps time
    const Consensus::GramParams gp = Params().GetConsensus().GramAt(1);
    CUnitsView units(nullptr);
    const int64_t t0 = 300 * DAY;
    for (uint32_t h = 1; h <= 10; h++)
        AdvanceChainClock(units, h, t0 + (int64_t)h * 600, gp);
    units.Erase(ClockAtKey(5));                              // one past record lost
    {
        UnitsCheckScope scope(&units);
        // Control: a present record is read as it is.
        CClockAt at4;
        BOOST_REQUIRE(units.Get(ClockAtKey(4), at4));
        BOOST_CHECK_EQUAL(ClockBlocksForChecks(5), at4.nActive / 600);
        // (a) The missing past record (block 6 reads the record of 5; the tip is 10) fails closed.
        const int64_t n6 = ClockBlocksForChecks(6);
        BOOST_CHECK_MESSAGE(n6 == -1, "SA-H3: block 6's clock, whose record (height 5, below the tip 10) is missing, "
                            "was extrapolated to " + std::to_string(n6) + " instead of failing (-1)");
        BOOST_CHECK_MESSAGE(ClockAtHeight(6) == -1, "SA-H3: ClockAtHeight(6) doesn't carry the failure (" +
                            std::to_string(ClockAtHeight(6)) + ")");
        // (b) Past the tip it still extrapolates, one clock block per block from the tip's clock.
        CChainClock clock;
        BOOST_REQUIRE(GetChainClock(units, clock));
        BOOST_CHECK_EQUAL(ClockBlocksForChecks(15), (clock.nActiveTime + (14 - (int64_t)clock.nHeight) * 600) / 600);
    }
    g_fClockIsHeightForTests = fClockWas;
}

// D-2026-11-20-2 (S1X-4; security 11-20 on 39f2ffd): the swap's bid at the deadline, read at height h, takes the posting
// before a post made at h; from h+1 the new one. Where the dropped posting could matter, the fallback stands.
BOOST_AUTO_TEST_CASE(s1x_4_bid_at_deadline_skips_a_post_at_the_height_read)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t A = 1000;   // active time of the first posting
    BOOST_REQUIRE(ApplyHouseRatePost(units, 2, 100000, 100000, 1, 10 * DAY, gp, strReject, A));
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, 2, 120000, 120000, 50, 15 * DAY, gp, strReject, A + 5 * DAY),
                          "setup: the second post was refused: " + strReject);
    const int64_t nActive = A + 6 * DAY + 1;   // the new posting has been in effect for the whole day before
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, nActive, 7, DAY, 51), 120000u);   // h+1: the new posting
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, nActive, 7, DAY), 120000u);       // no height: the new posting
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, nActive, 7, DAY, 50), 100000u);   // h: the posting before it
    // At h with T_f inside the day after the earlier posting: S1X-40 keeps the record as at the block's start (that
    // posting alone), so the answer is the one a read before the POST gives, not the fallback.
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, A + DAY / 2, 7, DAY, 50), 100000u);
}

// S1X-40 (testing: Low; security 11-26: Medium; Michael 2026-11-26 "Yes, build all 6"): the swap's bid at the deadline
// doesn't depend on where a POST sits in its block. Run 4 #5's case: demanded at 100,000 (the fallback); the house cut to
// 80,000 2.5 days before T_f and re-posted 80,000 12 h before it; after T_f, block h carries its next POST and the swap's
// EXPIRE. Before: [EXPIRE, POST] gave 80,000 and [POST, EXPIRE] the fallback 100,000.
BOOST_AUTO_TEST_CASE(s1x_40_bid_at_deadline_is_the_same_either_side_of_a_post_in_the_block)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t Tf = 40 * DAY;
    BOOST_REQUIRE(ApplyHouseRatePost(units, 2, 100000, 100000, 1, 10 * DAY, gp, strReject, 10 * DAY));
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, 2, 80000, 80000, 10, Tf - 5 * DAY / 2, gp, strReject, Tf - 5 * DAY / 2),
                          "setup: the cut was refused: " + strReject);
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, 2, 80000, 80000, 20, Tf - DAY / 2, gp, strReject, Tf - DAY / 2),
                          "setup: the re-post was refused: " + strReject);
    const uint32_t h = 30;
    const uint64_t nBefore = HouseBidAtActive(units, 2, Tf, 100000, DAY, h);   // [EXPIRE, POST]: read before the POST
    BOOST_CHECK_EQUAL(nBefore, 80000u);
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, 2, 80000, 80000, h, Tf + 100, gp, strReject, Tf + 100),
                          "setup: the post at h was refused: " + strReject);
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, Tf, 100000, DAY, h), nBefore);   // [POST, EXPIRE]: the same
    // From h+1 the record's current posting came after T_f and the one before it inside the day, so the rule's
    // fallback stands (D-2026-11-20-2 rule 2).
    BOOST_CHECK_EQUAL(HouseBidAtActive(units, 2, Tf, 100000, DAY, h + 1), 100000u);
}

// Security 11-20 (freebankd's audit, a spot covered only by an equality): RETIRE, RECOURSE and ops 7, 9 and 10 read the
// reference house's in-block status (RefHouseAnchor), so a no-cure PROTEST that fails it at h moves the price to the
// window anchored at h. That must price exactly as the plain window at h, or a repayment priced at the tip fails after
// the PROTEST in the same block. Neither counts a post made at h (D-2026-11-20-2); from h+1 it counts.
BOOST_AUTO_TEST_CASE(refhouse_anchor_at_h_prices_as_the_plain_window)
{
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t T = 400 * DAY;
    const uint32_t H = 500;
    AdvanceChainClock(units, H - 20, T - 3 * DAY, gp);
    BOOST_REQUIRE(ApplyHouseRatePost(units, 4, 100000, 101000, H - 20, T - 3 * DAY, gp, strReject));
    AdvanceChainClock(units, H - 10, T - DAY, gp);
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, 4, 110000, 111100, H - 10, T - DAY, gp, strReject),
                          "setup: the second post was refused: " + strReject);
    AdvanceChainClock(units, H - 1, T, gp);
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, 4, 120000, 121200, H, T, gp, strReject),
                          "setup: the post at H was refused: " + strReject);
    const uint64_t nOverridePrev = g_nHouseRateTestOverride;
    g_nHouseRateTestOverride = 0;
    {
        UnitsCheckScope scope(&units);
        uint64_t nBidPlain = 0, nAskPlain = 0, nBidAnchored = 0, nAskAnchored = 0;
        BOOST_REQUIRE(HouseRateMaxForChecks(4, H, 30, nBidPlain, nAskPlain));
        BOOST_REQUIRE(HouseRateMaxAtForChecks(4, H, 30, nBidAnchored, nAskAnchored));
        BOOST_CHECK_EQUAL(nAskAnchored, nAskPlain);
        BOOST_CHECK_EQUAL(nBidAnchored, nBidPlain);
        BOOST_CHECK_EQUAL(nAskPlain, 111100u);   // the post at H counts in neither
        uint64_t nBidNext = 0, nAskNext = 0;
        BOOST_REQUIRE(HouseRateMaxForChecks(4, H + 1, 30, nBidNext, nAskNext));
        BOOST_CHECK_EQUAL(nAskNext, 121200u);    // from H+1 it does
    }
    g_nHouseRateTestOverride = nOverridePrev;
}

// ===========================================================================
// testing (2026-11-26): S1X-22 and S1X-40 (S1X-40 is Claude max run 4 on v1.2.5 #5; S1X-22 is GPT-6.1's round 12
// window finding; security 11-26: S1X-22 Low, S1X-40 Medium; fixed in consensus batch 2, Michael 2026-11-26 "Yes,
// build all 6"). Written from the findings and the signed rules, not from freebankd's cases: random posting histories,
// checked against an oracle (S1X-22) and against the block-start read (S1X-40). Each case reports its first
// counterexample. FAIL on master 7f65d2e (src = c53f2e6); pass on mb/consensus-batch-2.
// ===========================================================================
namespace {
struct Run4Post { uint32_t nHeight; int64_t nTime; uint64_t nBid; uint64_t nAsk; };

// The highest bid and ask in effect at any instant of [nFrom, nTo]: each accepted posting is in effect from its time
// until the next one's.
void Run4OracleMax(const std::vector<Run4Post>& v, int64_t nFrom, int64_t nTo, uint64_t& nBid, uint64_t& nAsk)
{
    nBid = nAsk = 0;
    for (size_t i = 0; i < v.size(); i++) {
        const int64_t nStart = v[i].nTime;
        const int64_t nEnd = i + 1 < v.size() ? v[i + 1].nTime : std::numeric_limits<int64_t>::max();
        if (nStart <= nTo && nEnd > nFrom) {
            nBid = std::max(nBid, v[i].nBid);
            nAsk = std::max(nAsk, v[i].nAsk);
        }
    }
}

// Plays a random history of postings for house 4 (heights strictly rising, times rising, gaps under RATE_DAY_FILL_MAX
// days; moves from -35% to +25%; a refused post writes nothing and is left out). Returns the accepted ones.
std::vector<Run4Post> Run4History(CUnitsView& units, std::mt19937& rng, int nPosts, int64_t nStart, int64_t nMaxGap)
{
    Consensus::GramParams gp;
    std::vector<Run4Post> v;
    uint32_t h = 10;
    int64_t t = nStart;
    uint64_t bid = 100000;
    for (int i = 0; i < nPosts; i++) {
        h += 1 + rng() % 50;
        t += 1 + (int64_t)(rng() % (uint64_t)nMaxGap);
        const int64_t nMove = (int64_t)(rng() % 61) - 35;
        const uint64_t nBid = (uint64_t)std::max<int64_t>(1000, (int64_t)bid + (int64_t)bid * nMove / 100);
        const uint64_t nAsk = nBid + nBid * (rng() % 21) / 1000;   // spread 0 .. 2%
        std::string strReject;
        if (ApplyHouseRatePost(units, 4, nBid, nAsk, h, t, gp, strReject, t)) {
            v.push_back(Run4Post{h, t, nBid, nAsk});
            bid = nBid;
        }
    }
    return v;
}
} // namespace

// S1X-22: the "N-day" highest bid and ask (ASK30 for RETIRE, RECOURSE and HRETIRE; the 90-day high) include every rate
// in effect at any instant of the last N days. Master counted today plus the previous N - 1 days, so a rate in effect
// only N - 1 days and some hours ago dropped out. Also checked: the window never reaches past today plus the N whole
// days before it (the fix's own statement).
BOOST_AUTO_TEST_CASE(s1x_22_window_max_covers_every_instant_of_the_last_n_days)
{
    std::mt19937 rng(20261126);
    const std::vector<uint32_t> vDays = {1, 7, 30, 90};
    int nChecks = 0, nLow = 0, nHigh = 0;
    std::string strFirstLow, strFirstHigh;
    for (int trial = 0; trial < 400; trial++) {
        CUnitsView units(nullptr);
        const std::vector<Run4Post> v = Run4History(units, rng, 3 + (int)(rng() % 10), 100 * DAY + (int64_t)(rng() % DAY),
                                                    rng() % 2 ? 3 * DAY : 20 * DAY);
        if (v.empty())
            continue;
        for (int r = 0; r < 6; r++) {
            const uint32_t nDays = vDays[rng() % vDays.size()];
            const int64_t nNow = v.back().nTime + (int64_t)(rng() % (uint64_t)(40 * DAY));
            uint64_t nMaxBid = 0, nMaxAsk = 0;
            BOOST_REQUIRE(HouseRateWindowMax(units, 4, v.back().nHeight + 1, nNow, nDays, nMaxBid, nMaxAsk));
            uint64_t nWantBid, nWantAsk, nCapBid, nCapAsk;
            Run4OracleMax(v, nNow - (int64_t)nDays * DAY, nNow, nWantBid, nWantAsk);
            Run4OracleMax(v, ((int64_t)RateDayOf(nNow) - (int64_t)nDays) * DAY, nNow, nCapBid, nCapAsk);
            nChecks++;
            if ((nMaxBid < nWantBid || nMaxAsk < nWantAsk) && nLow++ == 0)
                strFirstLow = strprintf("trial %d: N=%u, now=%d: window max bid %u ask %u, but bid %u / ask %u was in "
                                        "effect within the last N days (%u postings, the last at %d)",
                                        trial, nDays, nNow, nMaxBid, nMaxAsk, nWantBid, nWantAsk, v.size(), v.back().nTime);
            if ((nMaxBid > nCapBid || nMaxAsk > nCapAsk) && nHigh++ == 0)
                strFirstHigh = strprintf("trial %d: N=%u, now=%d: window max bid %u ask %u exceeds the highest in effect "
                                         "since the start of day today-N (bid %u ask %u)",
                                         trial, nDays, nNow, nMaxBid, nMaxAsk, nCapBid, nCapAsk);
        }
    }
    BOOST_REQUIRE_GT(nChecks, 1000);
    BOOST_CHECK_MESSAGE(nLow == 0, strprintf("S1X-22: %d of %d window reads missed a rate in effect within the last N "
                                             "days. First: %s", nLow, nChecks, strFirstLow));
    BOOST_CHECK_MESSAGE(nHigh == 0, strprintf("S1X-22: %d of %d window reads counted a rate from before today-N. "
                                              "First: %s", nHigh, nChecks, strFirstHigh));
}

// S1X-40 (D-2026-11-20-2's promise, houserate.cpp and miner.cpp: a POST's place in its block doesn't matter): the bid at a
// swap's deadline read at height h is the same before and after a POST at h is applied, so the answer a swap op gets
// doesn't depend on whether the house's POST sits before or after it in the block. Master's shifted branch returned the
// fallback where the block-start record gave a posting.
BOOST_AUTO_TEST_CASE(s1x_40_bid_at_active_ignores_a_same_block_post)
{
    std::mt19937 rng(20261140);
    const uint64_t FALLBACK = 7;
    Consensus::GramParams gp;
    int nChecks = 0, nDiff = 0;
    std::string strFirst;
    for (int trial = 0; trial < 400; trial++) {
        CUnitsView units(nullptr);
        const std::vector<Run4Post> v = Run4History(units, rng, 1 + (int)(rng() % 6), 100 * DAY,
                                                    rng() % 2 ? DAY / 2 : 3 * DAY);
        if (v.empty())
            continue;
        // Deadlines T_f anywhere from a day before the first posting to two days after the last.
        std::vector<int64_t> vActive;
        for (int r = 0; r < 12; r++)
            vActive.push_back(v.front().nTime - DAY +
                              (int64_t)(rng() % (uint64_t)(v.back().nTime - v.front().nTime + 3 * DAY)));
        const uint32_t h = v.back().nHeight + 1 + (uint32_t)(rng() % 5);
        std::vector<uint64_t> vBefore;
        for (const int64_t a : vActive)
            vBefore.push_back(HouseBidAtActive(units, 4, a, FALLBACK, DAY, h));
        // The house's POST at h: a re-post, a cut or a small rise.
        const int64_t nMove = (int64_t)(rng() % 41) - 20;
        const uint64_t nBid = (uint64_t)std::max<int64_t>(1000, (int64_t)v.back().nBid + (int64_t)v.back().nBid * nMove / 100);
        const int64_t t = v.back().nTime + 1 + (int64_t)(rng() % (uint64_t)DAY);
        std::string strReject;
        if (!ApplyHouseRatePost(units, 4, nBid, nBid, h, t, gp, strReject, t))
            continue;
        for (size_t i = 0; i < vActive.size(); i++) {
            const uint64_t nAfter = HouseBidAtActive(units, 4, vActive[i], FALLBACK, DAY, h);
            nChecks++;
            if (nAfter != vBefore[i] && nDiff++ == 0)
                strFirst = strprintf("trial %d: %u postings (the last bid %u at %d, the one before %u), T_f %d, read at "
                                     "h=%u: %u before the POST at h, %u after it",
                                     trial, v.size(), v.back().nBid, v.back().nTime,
                                     v.size() > 1 ? v[v.size() - 2].nBid : (uint64_t)0, vActive[i], h, vBefore[i], nAfter);
        }
    }
    BOOST_REQUIRE_GT(nChecks, 1000);
    BOOST_CHECK_MESSAGE(nDiff == 0, strprintf("S1X-40: %d of %d reads at a POST's height changed when the POST was "
                                              "applied first. First: %s", nDiff, nChecks, strFirst));
}

BOOST_AUTO_TEST_SUITE_END()
