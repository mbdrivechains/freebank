// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <houserate.h>

#include <chainparams.h>
#include <house.h>        // HouseCharter, MAX_CHARTER_TOKENS
#include <issued.h>       // UnitsCheckScope
#include <validation.h>   // punitsdb

#include <algorithm>

uint64_t g_nHouseRateTestOverride = 0;
bool g_fClockIsHeightForTests = false;

void AdvanceChainClock(CUnitsView& units, uint32_t nHeight, int64_t nBlockTime, const Consensus::GramParams& gp)
{
    CChainClock prev, next;
    next.nHeight = nHeight;
    if (!units.Get(ChainClockKey(), prev)) {
        next.nMonoTime = nBlockTime;
        next.nActiveTime = 0;
    } else {
        next.nMonoTime = std::max(prev.nMonoTime, nBlockTime);
        const int64_t nStep = next.nMonoTime - prev.nMonoTime;
        next.nActiveTime = prev.nActiveTime + std::min<int64_t>(nStep, (int64_t)gp.nActiveGapCapSecs);
    }
    units.Put(ChainClockKey(), next);
    CClockAt at;
    at.nActive = next.nActiveTime;
    at.nMono = next.nMonoTime;
    units.Put(ClockAtKey(nHeight), at);   // the windows' clock at this height (GOLD_B §6)
}

bool GetChainClock(const CUnitsView& units, CChainClock& clock)
{
    return units.Get(ChainClockKey(), clock);
}

bool HouseRateAt(const CUnitsView& units, uint32_t nHouseID, uint32_t nHeight, uint64_t& nBid, uint64_t& nAsk)
{
    CHouseRate r;
    if (!units.Get(HouseRateKey(nHouseID), r))
        return false;
    if (r.nPostHeight < nHeight) {
        nBid = r.nBid;
        nAsk = r.nAsk;
        return true;
    }
    if (r.nPrevBid == 0)
        return false;
    nBid = r.nPrevBid;
    nAsk = r.nPrevAsk;
    return true;
}

bool HouseRateWindowMax(const CUnitsView& units, uint32_t nHouseID, uint32_t nHeight, int64_t nNow, uint32_t nDays,
                        uint64_t& nMaxBid, uint64_t& nMaxAsk)
{
    CHouseRate r;
    if (!units.Get(HouseRateKey(nHouseID), r))
        return false;
    // D-2026-11-20-2 (S1X-4, switch-on): the rate in effect at nHeight counts, as HouseRateAt prices it - a post at
    // nHeight itself counts from the next block (RS-1), so where a post sits in its block no longer matters to the
    // block's other readers. Every day since it was posted it has been the rate; the day records cover the days
    // before, and a posting enters them only when the next one replaces it (ApplyHouseRatePost).
    nMaxBid = r.nPostHeight >= nHeight ? r.nPrevBid : r.nBid;
    nMaxAsk = r.nPostHeight >= nHeight ? r.nPrevAsk : r.nAsk;
    if (nDays == 0)
        return true;
    // S1X-22 (testing: Low; security 11-26; Michael 2026-11-26 "Yes, build all 6"): today plus the previous nDays whole
    // days (nDays + 1 day records), so the window covers at least nDays days. With nToday + 1 - nDays it covered
    // nDays - 1 to nDays, and a high ask from 29 days and some hours ago dropped out of the "30-day" ASK30.
    const uint32_t nToday = RateDayOf(nNow);
    const uint32_t nFirst = nToday >= nDays ? nToday - nDays : 0;
    for (uint32_t d = nFirst; d <= nToday; d++) {
        CRateDay day;
        if (units.Get(RateDayKey(nHouseID, d), day)) {
            nMaxBid = std::max(nMaxBid, day.nMaxBid);
            nMaxAsk = std::max(nMaxAsk, day.nMaxAsk);
        }
    }
    return true;
}

bool HouseRateFresh(const CUnitsView& units, uint32_t nHouseID, uint32_t nHeight, int64_t nNow, int64_t nMaxAgeSecs)
{
    // D-2026-11-11-3 (RS-1): the posting in effect at nHeight, as HouseRateAt prices it - a POST at nHeight itself
    // counts from the next block. Rate ops share a block with the house's other ops now, so otherwise a stale house
    // could POST and MINT in one block and issue at the stale price.
    CHouseRate r;
    if (!units.Get(HouseRateKey(nHouseID), r))
        return false;
    const int64_t nPostTime = r.nPostHeight < nHeight ? r.nPostTime : r.nPrevPostTime;
    return nPostTime != 0 && nNow - nPostTime <= nMaxAgeSecs;
}

bool HouseRateShapeOK(uint64_t nBid, uint64_t nAsk, uint32_t nSpreadBps)
{
    if (nBid == 0 || nAsk < nBid)
        return false;
    return (unsigned __int128)nAsk * 10000 <= (unsigned __int128)nBid * (10000 + nSpreadBps);
}

static void RaiseDay(CUnitsView& units, uint32_t nHouseID, uint32_t nDay, uint64_t nBid, uint64_t nAsk)
{
    CRateDay day;
    units.Get(RateDayKey(nHouseID, nDay), day);
    if (nBid <= day.nMaxBid && nAsk <= day.nMaxAsk)
        return;
    day.nMaxBid = std::max(day.nMaxBid, nBid);
    day.nMaxAsk = std::max(day.nMaxAsk, nAsk);
    units.Put(RateDayKey(nHouseID, nDay), day);
}

void ArmHouseRateRestore(CUnitsView& units, uint32_t nHouseID, uint32_t nHeight, int64_t nNow, const Consensus::GramParams& gp)
{
    CHouseRate r;
    if (!units.Get(HouseRateKey(nHouseID), r))
        return;
    uint64_t nMaxBid = 0, nMaxAsk = 0;
    if (!HouseRateWindowMax(units, nHouseID, nHeight, nNow, RATE_RESTORE_DAYS, nMaxBid, nMaxAsk))
        return;
    r.nRestoreMax = nMaxBid;
    r.nRestoreUntil = nNow + (int64_t)gp.nRateRiseWindowSecs;
    units.Put(HouseRateKey(nHouseID), r);
}

/** S1X-19 (security: Low; Michael 11-25 yes): the active time a posting takes effect at - its own block's clock. RS-1:
 * a post at h counts from h+1, whose checks read block h's clock, while nPostActive holds the clock at connect (the
 * parent's). Dating the post from the parent's clock dropped the old bid from a swap's window for the posting block
 * when the parent's active time was the window's start. The posting block's record (ClockAtKey) exists once it has
 * connected; before that (reading in the posting block itself) the stored value is all there is. */
static int64_t PostEffectiveActive(const CUnitsView& units, uint32_t nPostHeight, int64_t nPostActiveAtConnect)
{
    CClockAt at;
    if (units.Get(ClockAtKey(nPostHeight), at))
        return at.nActive;
    return nPostActiveAtConnect;
}

bool ApplyHouseRatePost(CUnitsView& units, uint32_t nHouseID, uint64_t nBid, uint64_t nAsk, uint32_t nHeight,
                        int64_t nNow, const Consensus::GramParams& gp, std::string& strReject, int64_t nActiveNow)
{
    if (nActiveNow < 0)
        nActiveNow = nNow;
    if (!HouseRateShapeOK(nBid, nAsk, gp.nRateSpreadBps)) {
        strReject = "bad-house-rate-spread";
        return false;
    }
    CHouseRate r;
    const bool fFirst = !units.Get(HouseRateKey(nHouseID), r);
    if (!fFirst && r.nPostHeight >= nHeight) {
        strReject = "bad-house-rate-same-block";
        return false;
    }
    CHouseRate next;
    next.nBid = nBid;
    next.nAsk = nAsk;
    next.nPostHeight = nHeight;
    next.nPostTime = nNow;
    next.nPostActive = nActiveNow;
    bool fKeepRestore = false;   // S1X-11: whether a pending SETKEY restore survives this post
    if (fFirst) {
        next.nRiseCurStart = nNow;
        next.nRiseCurMin = nBid;
        next.nRisePrevMin = nBid;
    } else {
        // UR1-5 (switch-on): the bid may be at most (1 + nRateRiseBps) x the lowest bid in effect over the last
        // nRateRiseWindowSecs. It used to be measured from the bid in effect when a 24 h window last restarted, so a
        // house could post +25% just before the restart and +25% again just after: 56% in two blocks. Now the current
        // and previous windows' minimums both count, and they always cover the last W (a stolen rate key can't post a
        // huge bid and demand at it). A post after a cut is bounded by the cut (SA-H2); the partners' SETKEY restore
        // below is the way back up.
        const int64_t nW = (int64_t)gp.nRateRiseWindowSecs;
        next.nRiseCurStart = r.nRiseCurStart;
        next.nRiseCurMin = std::min(r.nRiseCurMin, r.nBid);
        next.nRisePrevMin = r.nRisePrevMin;
        if (nNow - r.nRiseCurStart >= nW) {
            // The closing window becomes the previous one: the lowest bid in effect in it. If the current bid has been
            // in effect for the whole last W, it was the only one, so the previous window carries just it.
            next.nRisePrevMin = nNow - r.nPostTime >= nW ? r.nBid : std::min(r.nRiseCurMin, r.nBid);
            next.nRiseCurStart = nNow;
            next.nRiseCurMin = r.nBid;   // in effect when the new window starts
        }
        const uint64_t nBase = std::min(next.nRisePrevMin, next.nRiseCurMin);
        const bool fRise = (unsigned __int128)nBid * 10000 > (unsigned __int128)nBase * (10000 + gp.nRateRiseBps);
        // SA-H2: a pending SETKEY restore lets this first post within W go back up to the recent high, never above it.
        // Only a post that NEEDS it is a restore (above the normal bound): a re-post of the current bid is not, so it
        // can't be used to reset the bound (security's switch-on review, SW-1).
        const bool fRestore = fRise && r.nRestoreUntil != 0 && nNow <= r.nRestoreUntil && nBid <= r.nRestoreMax;
        if (fRise && !fRestore) {
            strReject = "bad-house-rate-rise";
            return false;
        }
        if (fRestore) {
            // The bound runs from the restored bid R, so the thief's cut no longer counts - but for a full W after the
            // restore nothing above R (SW-1): the previous window's minimum becomes ceil(R / (1 + rise)), so the ceiling is R (+ at most
            // one unit of rounding). R can be re-posted; a rise above R waits until R has been in effect for W, when a
            // window restart carries R alone. Repeated SETKEY / restore cycles inside one W never pass the 30-day high,
            // since restoring never raises it.
            const uint64_t nFloorMin = (uint64_t)(((unsigned __int128)nBid * 10000 + (10000 + gp.nRateRiseBps) - 1) /
                                                  (10000 + gp.nRateRiseBps));
            // The cap rides in the previous window only; the current one holds R itself, so when this window
            // closes (W after the restore) the previous window carries R (or any lower bid posted since) and the
            // normal 25% runs from it.
            next.nRiseCurStart = nNow;
            next.nRisePrevMin = nFloorMin;
            next.nRiseCurMin = nBid;
        } else {
            next.nRiseCurMin = std::min(next.nRiseCurMin, nBid);
        }
        next.nPrev2Bid = r.nPrevBid;                 // S1X-40: the block-start record's previous posting, kept
        next.nPrev2PostActive = r.nPrevPostActive;   // (already converted to when it took effect, S1X-19)
        next.nPrevBid = r.nBid;
        next.nPrevAsk = r.nAsk;
        next.nPrevPostActive = PostEffectiveActive(units, r.nPostHeight, r.nPostActive);   // S1X-19: when it took effect
        next.nPrevPostTime = r.nPostTime;
        // S1X-11 (security's counter, adopted; Michael 11-25 yes): the restore survives a re-post or an in-bound rise
        // (the partners' routine ticker post right after their SETKEY no longer throws it away), and is cleared when it
        // is used, when W has ended, or by a post that CUTS the bid. Keeping it through a cut would let the rate key
        // alone cut and snap back within W after any SETKEY - the cut / pay short / recover lever - for one block's
        // cost; today that needs a second M-of-N SETKEY.
        fKeepRestore = r.nRestoreUntil != 0 && nNow <= r.nRestoreUntil && !fRestore && nBid >= r.nBid;
    }
    next.nRestoreMax = fKeepRestore ? r.nRestoreMax : 0;
    next.nRestoreUntil = fKeepRestore ? r.nRestoreUntil : 0;
    // Day records: the old rate stayed in effect on every day from its posting, that day included, to now (bounded: no
    // rule reads further back than RATE_DAY_FILL_MAX days). D-2026-11-20-2 (S1X-4): the new rate doesn't enter today's
    // record now - nothing at this height may read it - but when the next post replaces it; until then the window reads
    // it as the rate in effect, from the next block (HouseRateWindowMax).
    const uint32_t nToday = RateDayOf(nNow);
    if (!fFirst) {
        const uint32_t nOldDay = RateDayOf(r.nPostTime);
        const uint32_t nFrom = std::max(nOldDay, nToday >= RATE_DAY_FILL_MAX ? nToday - RATE_DAY_FILL_MAX : 0u);
        for (uint32_t d = nFrom; d < nToday; d++)
            RaiseDay(units, nHouseID, d, r.nBid, r.nAsk);
        RaiseDay(units, nHouseID, nToday, r.nBid, r.nAsk);
    }
    units.Put(HouseRateKey(nHouseID), next);
    return true;
}

template <typename F>
static bool WithChecksView(F fn)
{
    if (const CUnitsView* pView = UnitsCheckScope::Current())
        return fn(*pView);
    CUnitsView view(punitsdb.get());
    return fn(view);
}

/** Stage 0 rule B1: the units as of the block's start (UnitsCheckScope::BlockStart), for W and M. */
template <typename F>
static bool WithBlockStartView(F fn)
{
    if (const CUnitsView* pView = UnitsCheckScope::BlockStart())
        return fn(*pView);
    CUnitsView view(punitsdb.get());
    return fn(view);
}

bool HouseRateForChecks(uint32_t nHouseID, int nHeight, uint64_t& nBid, uint64_t& nAsk)
{
    if (g_nHouseRateTestOverride) {
        nBid = nAsk = g_nHouseRateTestOverride;
        return true;
    }
    return WithChecksView([&](const CUnitsView& units) { return HouseRateAt(units, nHouseID, (uint32_t)nHeight, nBid, nAsk); });
}

bool HouseRateMaxForChecks(uint32_t nHouseID, int nHeight, uint32_t nDays, uint64_t& nMaxBid, uint64_t& nMaxAsk)
{
    if (g_nHouseRateTestOverride) {
        nMaxBid = nMaxAsk = g_nHouseRateTestOverride;
        return true;
    }
    return WithChecksView([&](const CUnitsView& units) {
        CChainClock clock;
        if (!GetChainClock(units, clock))
            return false;
        return HouseRateWindowMax(units, nHouseID, (uint32_t)nHeight, clock.nMonoTime, nDays, nMaxBid, nMaxAsk);
    });
}

bool ChainClockForChecks(CChainClock& clock)
{
    return WithChecksView([&](const CUnitsView& units) { return GetChainClock(units, clock); });
}

bool ApplyHouseCharter(CUnitsView& units, const HouseCharter& op, uint32_t nHeight, int64_t nNow,
                       const Consensus::GramParams& gp, std::string& strReject)
{
    CHouseCharter charter;
    units.Get(HouseCharterKey(op.nHouseID), charter);
    if (op.nKind == HOUSE_CHARTER_ADD) {
        // Prune entries whose removal has taken effect (a pending swap keeps its own copy of the token it named).
        std::vector<CCharterToken> vKeep;
        for (const CCharterToken& t : charter.vToken)
            if (t.LiveAt(nNow))
                vKeep.push_back(t);
        size_t nLive = 0;
        for (const CCharterToken& t : vKeep) {
            nLive++;
            if (t.nChainID == op.nChainID && t.vchContract == op.vchContract) {
                strReject = "bad-house-charter-duplicate";
                return false;
            }
        }
        if (nLive >= MAX_CHARTER_TOKENS) {
            strReject = "bad-house-charter-full";
            return false;
        }
        CCharterToken t;
        t.nChainID = op.nChainID;
        t.vchContract = op.vchContract;
        t.nDecimals = op.nDecimals;
        t.nGramsNum = op.nGramsNum;
        t.nGramsDen = op.nGramsDen;
        t.nRelated = op.nRelated;
        t.nAddedTime = nNow;
        t.nRelatedHeight = nHeight;
        vKeep.push_back(t);
        charter.vToken = vKeep;
    } else {
        if (op.nIndex >= charter.vToken.size() || !charter.vToken[op.nIndex].LiveAt(nNow)) {
            strReject = "bad-house-charter-index";
            return false;
        }
        CCharterToken& t = charter.vToken[op.nIndex];
        // UR1-1 (switch-on, Michael 2026-11-10): the op names the token too (chain id + contract, in the signed
        // payload), and it must be the one at nIndex. An ADD renumbers from live entries, so a signed removal or
        // relabel used to land on whatever token had moved into that index.
        if (t.nChainID != op.nChainID || t.vchContract != op.vchContract) {
            strReject = "bad-house-charter-mismatch";
            return false;
        }
        if (op.nKind == HOUSE_CHARTER_REMOVE) {
            if (t.nRemoveAt != 0) {
                strReject = "bad-house-charter-removing";
                return false;
            }
            size_t nStaying = 0;
            for (const CCharterToken& o : charter.vToken)
                if (o.nRemoveAt == 0)
                    nStaying++;
            if (nStaying <= 1) {
                strReject = "bad-house-charter-last";   // a gold-note house keeps at least one entry
                return false;
            }
            t.nRemoveAt = nNow + (int64_t)gp.nCharterRemovalSecs;
        } else {
            t.nRelated = op.nRelated;
            t.nRelatedHeight = nHeight;
        }
    }
    units.Put(HouseCharterKey(op.nHouseID), charter);
    return true;
}

bool HouseCharterTokenAt(const CUnitsView& units, uint32_t nHouseID, uint64_t nChainID,
                         const std::vector<unsigned char>& vchContract, int64_t nNow, CCharterToken& token)
{
    CHouseCharter charter;
    if (!units.Get(HouseCharterKey(nHouseID), charter))
        return false;
    for (const CCharterToken& t : charter.vToken) {
        if (t.nChainID == nChainID && t.vchContract == vchContract && t.LiveAt(nNow)) {
            token = t;
            return true;
        }
    }
    return false;
}

void SwapOpen(CUnitsView& units, const uint256& hashLock, const CSwapRecord& rec)
{
    units.Put(SwapKey(hashLock), rec);
    uint64_t n = 0;
    units.Get(SwapPendingKey(rec.nHouseID), n);
    units.Put(SwapPendingKey(rec.nHouseID), n + rec.nUnits);
}

void SwapSettle(CUnitsView& units, const uint256& hashLock, uint8_t nStatus, uint64_t nRate, int64_t nNow,
                int64_t nClockNow, int64_t nLapseClock)
{
    CSwapRecord r;
    if (!units.Get(SwapKey(hashLock), r))
        return;
    r.nStatus = nStatus;
    r.nSettleTime = nNow;
    r.nSettleClock = nClockNow;
    if (nStatus == SWAP_PAID)
        r.nShortfallMg = SwapShortfallMg(r, nRate);
    units.Put(SwapKey(hashLock), r);
    if (r.nShortfallMg > 0) {
        // The house's ledger of shortfalls that can still claim if it fails (pruned past the lapse; bounded by the
        // swaps it fails to deliver within one lapse).
        CShortfallLedger led;
        units.Get(ShortfallLedgerKey(r.nHouseID), led);
        std::vector<std::pair<int64_t, uint64_t>> vKeep;
        for (const auto& e : led.vEntry)
            if (e.first + nLapseClock >= nClockNow)
                vKeep.push_back(e);
        vKeep.emplace_back(nClockNow, r.nShortfallMg);
        led.vEntry = vKeep;
        units.Put(ShortfallLedgerKey(r.nHouseID), led);
    }
    uint64_t n = 0;
    units.Get(SwapPendingKey(r.nHouseID), n);
    n = n > r.nUnits ? n - r.nUnits : 0;
    if (n == 0)
        units.Erase(SwapPendingKey(r.nHouseID));
    else
        units.Put(SwapPendingKey(r.nHouseID), n);
}

void SwapMarkProtested(CUnitsView& units, const uint256& hashLock)
{
    CSwapRecord r;
    if (!units.Get(SwapKey(hashLock), r))
        return;
    r.nStatus = SWAP_PROTESTED;
    units.Put(SwapKey(hashLock), r);
}

uint64_t HousePendingSwapUnits(const CUnitsView& units, uint32_t nHouseID)
{
    uint64_t n = 0;
    units.Get(SwapPendingKey(nHouseID), n);
    return n;
}

bool HouseRateKeyForChecks(uint32_t nHouseID, std::vector<unsigned char>& vchPubKey)
{
    return WithChecksView([&](const CUnitsView& units) { return units.Get(RateKeyKey(nHouseID), vchPubKey); });
}

bool HouseRateMaxAtForChecks(uint32_t nHouseID, int nAnchorHeight, uint32_t nDays, uint64_t& nMaxBid, uint64_t& nMaxAsk)
{
    if (g_nHouseRateTestOverride) {
        nMaxBid = nMaxAsk = g_nHouseRateTestOverride;
        return true;
    }
    return WithChecksView([&](const CUnitsView& units) {
        CClockAt at;
        int64_t nMono = 0;
        // As block nAnchorHeight saw it: its parent's clock (the chain clock advances after a block's transactions).
        if (nAnchorHeight > 1 && units.Get(ClockAtKey((uint32_t)(nAnchorHeight - 1)), at)) {
            nMono = at.nMono;
        } else {
            CChainClock clock;
            if (!GetChainClock(units, clock))
                return false;
            nMono = clock.nMonoTime;   // the anchor is the scope's next block: its window is today's
        }
        return HouseRateWindowMax(units, nHouseID, (uint32_t)nAnchorHeight, nMono, nDays, nMaxBid, nMaxAsk);
    });
}

uint64_t DemandBidForChecks(uint32_t nHouseID, uint32_t nDemandHeight)
{
    uint64_t n = 0;
    WithChecksView([&](const CUnitsView& units) { units.Get(DemandBidKey(nHouseID, nDemandHeight), n); return true; });
    return n;
}

void RecordDemandBid(CUnitsView& units, uint32_t nHouseID, uint32_t nHeight)
{
    uint64_t n = 0;
    if (units.Get(DemandBidKey(nHouseID, nHeight), n))
        return;
    uint64_t nBid = 0, nAsk = 0;
    if (HouseRateAt(units, nHouseID, nHeight, nBid, nAsk) && nBid > 0)
        units.Put(DemandBidKey(nHouseID, nHeight), nBid);
}

bool HouseRateFreshForChecks(uint32_t nHouseID, int nHeight, int64_t nMaxAgeSecs)
{
    if (g_nHouseRateTestOverride)
        return true;
    return WithChecksView([&](const CUnitsView& units) {
        CChainClock clock;
        return GetChainClock(units, clock) && HouseRateFresh(units, nHouseID, (uint32_t)nHeight, clock.nMonoTime, nMaxAgeSecs);
    });
}

bool HouseRateRecordForChecks(uint32_t nHouseID, CHouseRate& rate)
{
    return WithChecksView([&](const CUnitsView& units) { return units.Get(HouseRateKey(nHouseID), rate); });
}

bool HouseCharterForChecks(uint32_t nHouseID, CHouseCharter& charter)
{
    return WithChecksView([&](const CUnitsView& units) { return units.Get(HouseCharterKey(nHouseID), charter); });
}

bool SwapRecordForChecks(const uint256& hashLock, CSwapRecord& rec)
{
    return WithChecksView([&](const CUnitsView& units) { return units.Get(SwapKey(hashLock), rec); });
}

uint64_t HousePendingSwapUnitsForChecks(uint32_t nHouseID)
{
    uint64_t n = 0;
    WithBlockStartView([&](const CUnitsView& units) { n = HousePendingSwapUnits(units, nHouseID); return true; });   // Stage 0 B1
    return n;
}

bool HouseCharterTokenForChecks(uint32_t nHouseID, uint64_t nChainID, const std::vector<unsigned char>& vchContract,
                                int64_t nNow, CCharterToken& token)
{
    return WithChecksView([&](const CUnitsView& units) {
        return HouseCharterTokenAt(units, nHouseID, nChainID, vchContract, nNow, token);
    });
}

/** The highest bid in effect in [nActive - WINDOW, nActive] from two postings: C (bid, the active time it took effect)
 *  and the one before it, P (0 = none). When the day could hold a posting older than P, the fallback stands. */
static uint64_t BidAtActiveFrom(uint64_t nCurBid, int64_t nCurEffective, uint64_t nPrevBid, int64_t nPrevEffective,
                                int64_t nActive, int64_t nWindowSecs, uint64_t nFallback)
{
    const int64_t nStart = nActive - nWindowSecs;
    if (nCurEffective <= nActive) {
        // C is in effect at nActive; before C (if C came inside the day) P was.
        if (nCurEffective <= nStart || nPrevBid == 0)
            return nCurBid;
        if (nPrevEffective <= nStart)
            return std::max(nCurBid, nPrevBid);
        return nFallback;
    }
    // C came after nActive: P was in effect at nActive.
    if (nPrevBid == 0 || nPrevEffective > nActive)
        return nFallback;
    return nPrevEffective <= nStart ? nPrevBid : nFallback;
}

uint64_t HouseBidAtActive(const CUnitsView& units, uint32_t nHouseID, int64_t nActive, uint64_t nFallback,
                         int64_t nWindowSecs, uint32_t nHeight)
{
    // The HIGHEST bid in effect in the day before nActive (review 2026-11-07: the bid at the instant T_f could be a dip
    // posted just before it and restored just after). The record keeps two postings; when the day could hold an older
    // one too, the fallback (the swap's bid at demand - the holder's side) stands.
    const int64_t WINDOW = nWindowSecs;   // GramParams::nSwapBidWindowSecs (a day on main)
    CHouseRate r;
    if (!units.Get(HouseRateKey(nHouseID), r))
        return nFallback;
    // D-2026-11-20-2 (S1X-4, switch-on): a post at nHeight counts from the next block for every check, so read at
    // nHeight the record is the one at the block's start: C was the previous posting, P the one before it. S1X-40: P is
    // kept (nPrev2*), so the answer is the same whether the POST sits before or after the reader in the block (before,
    // with P gone, this branch returned the fallback where the block-start record gave C, max(C, P) or P).
    if (r.nPostHeight >= nHeight) {
        if (r.nPrevBid == 0)
            return nFallback;   // no posting was in effect at the block's start
        return BidAtActiveFrom(r.nPrevBid, r.nPrevPostActive, r.nPrev2Bid, r.nPrev2PostActive, nActive, WINDOW,
                               nFallback);
    }
    // S1X-19: C counts from the active time it took effect at (its own block's clock); nPrevPostActive was converted
    // the same way when C was posted.
    const int64_t nCurEffective = PostEffectiveActive(units, r.nPostHeight, r.nPostActive);
    return BidAtActiveFrom(r.nBid, nCurEffective, r.nPrevBid, r.nPrevPostActive, nActive, WINDOW, nFallback);
}

void SwapFixBidT(CUnitsView& units, const uint256& hashLock, uint32_t nHeight)
{
    CSwapRecord r;
    if (!units.Get(SwapKey(hashLock), r) || r.nBidT != 0)
        return;
    r.nBidT = g_nHouseRateTestOverride ? g_nHouseRateTestOverride
                                       : HouseBidAtActive(units, r.nHouseID, r.nDeadlineActive, r.nBid0,
                                        Params().GetConsensus().GramAt(r.nDemandHeight).nSwapBidWindowSecs, nHeight);
    units.Put(SwapKey(hashLock), r);
}

uint64_t SwapBidAtDeadlineForChecks(const CSwapRecord& r, uint32_t nHeight)
{
    if (r.nBidT != 0)
        return r.nBidT;
    if (g_nHouseRateTestOverride)
        return g_nHouseRateTestOverride;
    uint64_t n = r.nBid0;
    WithChecksView([&](const CUnitsView& units) { n = HouseBidAtActive(units, r.nHouseID, r.nDeadlineActive, r.nBid0,
                                        Params().GetConsensus().GramAt(r.nDemandHeight).nSwapBidWindowSecs, nHeight); return true; });
    return n;
}

// ---- Gold B clocks in time (GOLD_B.md §6) ----

static const int64_t CLOCK_BLOCK_SECS = 600;

int64_t ClockBlocksForChecks(int nHeight)
{
    if (nHeight <= 0)
        return 0;
    if (g_fClockIsHeightForTests || Params().GetConsensus().fClockIsHeight)
        return nHeight;
    // Block h is judged on its PARENT's clock (review 2026-11-07): the record of h - 1, which the mempool, the template
    // check and connect all have. The chain clock advances after a block's transactions.
    const int nAt = nHeight - 1;
    if (nAt <= 0)
        return 0;
    int64_t nActive = -1;
    WithChecksView([&](const CUnitsView& units) {
        CClockAt at;
        if (units.Get(ClockAtKey((uint32_t)nAt), at)) {
            nActive = at.nActive;
            return true;
        }
        CChainClock clock;
        if (!GetChainClock(units, clock))
            return false;
        // SA-H3 (Michael 2026-11-11): a PAST height (at or below the clock's tip) without its record means a damaged units
        // DB; a window judged on a made-up clock could come out either way, so fail closed (-1 and the flag the mempool
        // and connect act on). A height past the tip (the mempool's next block, a wallet's payment margin) counts one
        // clock block per block from the tip's clock: a wallet pricing interest at tip + N keeps N clock blocks of margin,
        // and a window judged early in the mempool is judged again at connect.
        if ((int64_t)nAt <= (int64_t)clock.nHeight) {
            g_fClockRecordMissing = true;
            nActive = -2;
            return false;
        }
        nActive = clock.nActiveTime + ((int64_t)nAt - (int64_t)clock.nHeight) * CLOCK_BLOCK_SECS;
        if (nActive < 0)
            nActive = 0;
        return true;
    });
    if (nActive == -2)
        return -1;   // SA-H3: a missing past record
    return nActive < 0 ? 0 : nActive / CLOCK_BLOCK_SECS;
}

namespace {
struct ClockHookInit {
    ClockHookInit() { g_fnClockAt = &ClockBlocksForChecks; }
} g_clockHookInit;
} // namespace

// ---- Gold B waterfall (GOLD_B.md §6): pending swaps and shortfalls claim at the noteholders' rank ----

void SwapClaim(CUnitsView& units, const uint256& hashLock)
{
    CSwapRecord r;
    if (!units.Get(SwapKey(hashLock), r))
        return;
    if (r.Open()) {
        uint64_t n = 0;
        units.Get(SwapPendingKey(r.nHouseID), n);
        n = n > r.nUnits ? n - r.nUnits : 0;
        if (n == 0)
            units.Erase(SwapPendingKey(r.nHouseID));
        else
            units.Put(SwapPendingKey(r.nHouseID), n);
    }
    else if (r.nStatus == SWAP_PAID && r.nShortfallMg > 0) {
        // A claimed shortfall leaves the house's ledger (the partners' settle waits for the ledger to empty).
        CShortfallLedger led;
        if (units.Get(ShortfallLedgerKey(r.nHouseID), led)) {
            for (size_t i = 0; i < led.vEntry.size(); i++) {
                if (led.vEntry[i].first == r.nSettleClock && led.vEntry[i].second == r.nShortfallMg) {
                    led.vEntry.erase(led.vEntry.begin() + i);
                    break;
                }
            }
            if (led.vEntry.empty())
                units.Erase(ShortfallLedgerKey(r.nHouseID));
            else
                units.Put(ShortfallLedgerKey(r.nHouseID), led);
        }
    }
    r.nStatus = SWAP_CLAIMED;
    units.Put(SwapKey(hashLock), r);
}

uint64_t HouseLiveShortfallMg(const CUnitsView& units, uint32_t nHouseID, int64_t nClockAt, int64_t nLapseClock)
{
    CShortfallLedger led;
    if (!units.Get(ShortfallLedgerKey(nHouseID), led))
        return 0;
    unsigned __int128 n = 0;
    for (const auto& e : led.vEntry)
        if (e.first <= nClockAt && e.first + nLapseClock >= nClockAt)
            n += e.second;
    return (uint64_t)std::min<unsigned __int128>(n, (unsigned __int128)MAX_MONEY);
}

uint64_t HouseLiveShortfallMgForChecks(uint32_t nHouseID, int64_t nClockAt, int64_t nLapseClock)
{
    uint64_t n = 0;
    WithBlockStartView([&](const CUnitsView& units) { n = HouseLiveShortfallMg(units, nHouseID, nClockAt, nLapseClock); return true; });   // Stage 0 B1
    return n;
}
