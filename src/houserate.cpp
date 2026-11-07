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
    // The latest posting and the rate in effect now both count: the latest is in effect from the next block at the
    // latest, and every day since it was posted it has been the rate (the day records cover the days before).
    nMaxBid = std::max(r.nBid, r.nPostHeight >= nHeight ? r.nPrevBid : r.nBid);
    nMaxAsk = std::max(r.nAsk, r.nPostHeight >= nHeight ? r.nPrevAsk : r.nAsk);
    if (nDays == 0)
        return true;
    const uint32_t nToday = RateDayOf(nNow);
    const uint32_t nFirst = nToday + 1 >= nDays ? nToday + 1 - nDays : 0;
    for (uint32_t d = nFirst; d <= nToday; d++) {
        CRateDay day;
        if (units.Get(RateDayKey(nHouseID, d), day)) {
            nMaxBid = std::max(nMaxBid, day.nMaxBid);
            nMaxAsk = std::max(nMaxAsk, day.nMaxAsk);
        }
    }
    return true;
}

bool HouseRateFresh(const CUnitsView& units, uint32_t nHouseID, int64_t nNow, int64_t nMaxAgeSecs)
{
    CHouseRate r;
    return units.Get(HouseRateKey(nHouseID), r) && nNow - r.nPostTime <= nMaxAgeSecs;
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
    if (fFirst) {
        next.nRiseBaseBid = nBid;
        next.nRiseBaseTime = nNow;
    } else {
        // The bid may rise at most nRateRiseBps over the bid in effect when the rise window last restarted; the window
        // restarts once it is nRateRiseWindowSecs old (a stolen rate key can't post a huge bid and demand at it).
        next.nRiseBaseBid = r.nRiseBaseBid;
        next.nRiseBaseTime = r.nRiseBaseTime;
        if (nNow - r.nRiseBaseTime >= (int64_t)gp.nRateRiseWindowSecs) {
            next.nRiseBaseBid = r.nBid;
            next.nRiseBaseTime = nNow;
        }
        if ((unsigned __int128)nBid * 10000 > (unsigned __int128)next.nRiseBaseBid * (10000 + gp.nRateRiseBps)) {
            strReject = "bad-house-rate-rise";
            return false;
        }
        next.nPrevBid = r.nBid;
        next.nPrevAsk = r.nAsk;
        next.nPrevPostActive = r.nPostActive;
    }
    // Day records: the old rate stayed in effect on every day from its posting to now; the days it was never posted on
    // get it now (bounded: no rule reads further back than RATE_DAY_FILL_MAX days). Today gets the old and the new.
    const uint32_t nToday = RateDayOf(nNow);
    if (!fFirst) {
        const uint32_t nOldDay = RateDayOf(r.nPostTime);
        const uint32_t nFrom = std::max(nOldDay + 1, nToday >= RATE_DAY_FILL_MAX ? nToday - RATE_DAY_FILL_MAX : 0u);
        for (uint32_t d = nFrom; d < nToday; d++)
            RaiseDay(units, nHouseID, d, r.nBid, r.nAsk);
        RaiseDay(units, nHouseID, nToday, r.nBid, r.nAsk);
    }
    RaiseDay(units, nHouseID, nToday, nBid, nAsk);
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

bool HouseRateFreshForChecks(uint32_t nHouseID, int64_t nMaxAgeSecs)
{
    if (g_nHouseRateTestOverride)
        return true;
    return WithChecksView([&](const CUnitsView& units) {
        CChainClock clock;
        return GetChainClock(units, clock) && HouseRateFresh(units, nHouseID, clock.nMonoTime, nMaxAgeSecs);
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
    WithChecksView([&](const CUnitsView& units) { n = HousePendingSwapUnits(units, nHouseID); return true; });
    return n;
}

bool HouseCharterTokenForChecks(uint32_t nHouseID, uint64_t nChainID, const std::vector<unsigned char>& vchContract,
                                int64_t nNow, CCharterToken& token)
{
    return WithChecksView([&](const CUnitsView& units) {
        return HouseCharterTokenAt(units, nHouseID, nChainID, vchContract, nNow, token);
    });
}

uint64_t HouseBidAtActive(const CUnitsView& units, uint32_t nHouseID, int64_t nActive, uint64_t nFallback,
                         int64_t nWindowSecs)
{
    // The HIGHEST bid in effect in the day before nActive (review 2026-11-07: the bid at the instant T_f could be a dip
    // posted just before it and restored just after). The record keeps two postings; when the day could hold an older
    // one too, the fallback (the swap's bid at demand - the holder's side) stands.
    const int64_t WINDOW = nWindowSecs;   // GramParams::nSwapBidWindowSecs (a day on main)
    CHouseRate r;
    if (!units.Get(HouseRateKey(nHouseID), r))
        return nFallback;
    const int64_t nStart = nActive - WINDOW;
    if (r.nPostActive <= nActive) {
        // C is in effect at nActive; before C (if C came inside the day) P was.
        if (r.nPostActive <= nStart || r.nPrevBid == 0)
            return r.nBid;
        if (r.nPrevPostActive <= nStart)
            return std::max(r.nBid, r.nPrevBid);
        return nFallback;
    }
    // C came after nActive: P was in effect at nActive.
    if (r.nPrevBid == 0 || r.nPrevPostActive > nActive)
        return nFallback;
    return r.nPrevPostActive <= nStart ? r.nPrevBid : nFallback;
}

void SwapFixBidT(CUnitsView& units, const uint256& hashLock)
{
    CSwapRecord r;
    if (!units.Get(SwapKey(hashLock), r) || r.nBidT != 0)
        return;
    r.nBidT = g_nHouseRateTestOverride ? g_nHouseRateTestOverride
                                       : HouseBidAtActive(units, r.nHouseID, r.nDeadlineActive, r.nBid0,
                                        Params().GetConsensus().GramAt(r.nDemandHeight).nSwapBidWindowSecs);
    units.Put(SwapKey(hashLock), r);
}

uint64_t SwapBidAtDeadlineForChecks(const CSwapRecord& r)
{
    if (r.nBidT != 0)
        return r.nBidT;
    if (g_nHouseRateTestOverride)
        return g_nHouseRateTestOverride;
    uint64_t n = r.nBid0;
    WithChecksView([&](const CUnitsView& units) { n = HouseBidAtActive(units, r.nHouseID, r.nDeadlineActive, r.nBid0,
                                        Params().GetConsensus().GramAt(r.nDemandHeight).nSwapBidWindowSecs); return true; });
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
        // A height without its record: past the scope's tip (the mempool's next block, a wallet's payment margin) or,
        // not expected after the reindex B's units layout forces, a past one. Count one clock block per block from the
        // tip's clock either way: a wallet pricing interest at tip + N then keeps N clock blocks of margin, and a
        // window judged early in the mempool is judged again at connect (CreateNewBlock drops a package that fails).
        nActive = clock.nActiveTime + ((int64_t)nAt - (int64_t)clock.nHeight) * CLOCK_BLOCK_SECS;
        if (nActive < 0)
            nActive = 0;
        return true;
    });
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
    WithChecksView([&](const CUnitsView& units) { n = HouseLiveShortfallMg(units, nHouseID, nClockAt, nLapseClock); return true; });
    return n;
}
