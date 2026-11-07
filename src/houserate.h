// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HOUSERATE_H
#define BITCOIN_HOUSERATE_H

/** Gold B (D-2026-11-07-1; docs-local/drafts/GOLD_B.md §1): each house's own binding rate, and the chain clock.
 *
 *  There is no chain-wide gold price. A house posts a bid and an ask in sats per gram (HOUSE_OP_RATE), signed by a rate
 *  key its partners register; the bid is what its notes pay in sECX, the ask what its bills repay at. The rate takes
 *  effect from the next block. Every record lives in the units DB, so a block's changes undo with it.
 *
 *  The chain clock is a block's time - the header time of the L1 block that carries it (consensus since v0.2.19) - made
 *  monotone, plus an "active" time that leaves out gaps of more than an hour between blocks (the swap deadline runs on
 *  it, so a FreeBank stall can't fail a swap whose gold was delivered: design, 2026-11-07). */

#include <consensus/params.h>
#include <serialize.h>
#include <units.h>

#include <stdint.h>
#include <string>

struct CChainClock {
    uint32_t nHeight;       // the block this clock is for
    int64_t nMonoTime;      // max(the previous block's, this block's time)
    int64_t nActiveTime;    // the previous block's + min(the step in nMonoTime, the gap cap)

    CChainClock() : nHeight(0), nMonoTime(0), nActiveTime(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHeight);
        READWRITE(nMonoTime);
        READWRITE(nActiveTime);
    }
};

/** A house's posted rate: the current one and the one before it (the current takes effect the block after nPostHeight),
 *  and the base the bid-rise cap counts from. */
struct CHouseRate {
    uint64_t nBid;            // sats per gram
    uint64_t nAsk;
    uint32_t nPostHeight;
    int64_t nPostTime;        // chain clock (monotone) at posting
    uint64_t nPrevBid;        // in effect until the block after nPostHeight; 0 = none (first posting)
    uint64_t nPrevAsk;
    uint64_t nRiseBaseBid;    // the bid in effect when the rise window last restarted
    int64_t nRiseBaseTime;
    int64_t nPostActive;      // chain active time at posting (the swap's bid at T_f reads it; design 2026-11-07)
    int64_t nPrevPostActive;  // the same for the previous posting

    CHouseRate() : nBid(0), nAsk(0), nPostHeight(0), nPostTime(0), nPrevBid(0), nPrevAsk(0), nRiseBaseBid(0),
                   nRiseBaseTime(0), nPostActive(0), nPrevPostActive(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBid);
        READWRITE(nAsk);
        READWRITE(nPostHeight);
        READWRITE(nPostTime);
        READWRITE(nPrevBid);
        READWRITE(nPrevAsk);
        READWRITE(nRiseBaseBid);
        READWRITE(nRiseBaseTime);
        READWRITE(nPostActive);
        READWRITE(nPrevPostActive);
    }
};

/** The highest bid and ask in effect at any time during one UTC day (day = chain time / 86400). */
struct CRateDay {
    uint64_t nMaxBid;
    uint64_t nMaxAsk;

    CRateDay() : nMaxBid(0), nMaxAsk(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nMaxBid);
        READWRITE(nMaxAsk);
    }
};

static const int64_t RATE_DAY_SECONDS = 86400;
/** How far back a posting fills the day records for days the old rate stayed in effect unposted: the longest window any
 *  rule reads (the waterfall's 90 days), plus one. */
static const uint32_t RATE_DAY_FILL_MAX = 91;

/** One gold token in a house's charter (Gold B, GOLD_B.md §2): an ERC-20 on chain nChainID at vchContract, nDecimals
 *  decimals, nGramsNum / nGramsDen grams per token, and the partners' related-issuer declaration (HOUSE_RELATED_*:
 *  undeclared, no, yes; a statement the chain doesn't check). Live from nAddedTime; from nRemoveAt (0 = not being
 *  removed) a demand can't name it. */
struct CCharterToken {
    uint64_t nChainID;
    std::vector<unsigned char> vchContract;
    uint8_t nDecimals;
    uint64_t nGramsNum;
    uint64_t nGramsDen;
    uint8_t nRelated;
    int64_t nAddedTime;
    int64_t nRemoveAt;
    uint32_t nRelatedHeight;   // the block of the last declaration

    CCharterToken() : nChainID(0), nDecimals(0), nGramsNum(0), nGramsDen(0), nRelated(0), nAddedTime(0), nRemoveAt(0),
                      nRelatedHeight(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nChainID);
        READWRITE(vchContract);
        READWRITE(nDecimals);
        READWRITE(nGramsNum);
        READWRITE(nGramsDen);
        READWRITE(nRelated);
        READWRITE(nAddedTime);
        READWRITE(nRemoveAt);
        READWRITE(nRelatedHeight);
    }
    bool LiveAt(int64_t nTime) const { return nRemoveAt == 0 || nTime < nRemoveAt; }
};
/** A house's charter: its entries, in the order added; an entry keeps its index until it is pruned (an entry past its
 *  removal time is pruned by the house's next ADD). */
struct CHouseCharter {
    std::vector<CCharterToken> vToken;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vToken);
    }
};

/** A swap (Gold B, GOLD_B.md §4; NOTE_OP_SWAP and after), by its hash lock. The units stay the house's liability
 *  (pending) until DONE or PAID; a PAID swap below its bid at demand keeps a shortfall in mg, a claim at the holder's rank
 *  if the house becomes insolvent within 90 days of nSettleTime. */
static const uint8_t SWAP_PENDING = 0;
static const uint8_t SWAP_DONE = 1;
static const uint8_t SWAP_PAID = 2;
static const uint8_t SWAP_PROTESTED = 3;
static const uint8_t SWAP_CLAIMED = 4;     // claimed from a failed house's escrow pot (NOTE_OP_SWAP_CLAIM)
struct CSwapRecord {
    uint32_t nHouseID;
    uint64_t nUnits;
    uint64_t nChainID;
    std::vector<unsigned char> vchContract;
    std::vector<unsigned char> vchEthAddress;
    std::vector<unsigned char> vchPayoutScript;
    uint64_t nBid0;             // the house's bid at the demand
    uint32_t nDemandHeight;
    int64_t nDeadlineActive;    // chain active time by which s must be revealed
    uint8_t nStatus;
    uint64_t nShortfallMg;
    int64_t nSettleTime;        // monotone chain time it was done or paid
    uint64_t nBidT;             // the house's bid at the deadline, fixed by the first swap op at or after it (0 = not yet)
    int64_t nSettleClock;       // the clock (clock blocks, house.h) it was done or paid: a shortfall's lapse

    CSwapRecord() : nHouseID(0), nUnits(0), nChainID(0), nBid0(0), nDemandHeight(0), nDeadlineActive(0),
                    nStatus(SWAP_PENDING), nShortfallMg(0), nSettleTime(0), nBidT(0), nSettleClock(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nUnits);
        READWRITE(nChainID);
        READWRITE(vchContract);
        READWRITE(vchEthAddress);
        READWRITE(vchPayoutScript);
        READWRITE(nBid0);
        READWRITE(nDemandHeight);
        READWRITE(nDeadlineActive);
        READWRITE(nStatus);
        READWRITE(nShortfallMg);
        READWRITE(nSettleTime);
        READWRITE(nBidT);
        READWRITE(nSettleClock);
    }
    bool Open() const { return nStatus == SWAP_PENDING || nStatus == SWAP_PROTESTED; }
};

inline UnitsKey SwapKey(const uint256& hashLock) { return UnitsKey(UNITS_SWAP).Hash(hashLock); }
inline UnitsKey SwapPendingKey(uint32_t nHouseID) { return UnitsKey(UNITS_SWAP_PENDING).U32(nHouseID); }

/** The failed-swap rate: before the deadline, the bid at the demand (a house that pays early pays the demand's rate);
 *  from it, the lower of the bid at the demand and the bid at the deadline (nBidT, fixed by the first swap op at or after
 *  it; nBidNow stands in when this op is that first one). */
inline uint64_t SwapPayRate(const CSwapRecord& r, uint64_t nBidAtDeadline, int64_t nActiveNow)
{
    if (nActiveNow < r.nDeadlineActive)
        return r.nBid0;
    return std::min(r.nBid0, r.nBidT != 0 ? r.nBidT : nBidAtDeadline);
}
/** The swap's shortfall in mg when paid at nRate below its bid at demand: units x (1 - rate / bid0), rounded up. */
inline uint64_t SwapShortfallMg(const CSwapRecord& r, uint64_t nRate)
{
    if (nRate >= r.nBid0 || r.nBid0 == 0)
        return 0;
    return (uint64_t)(((unsigned __int128)r.nUnits * (r.nBid0 - nRate) + r.nBid0 - 1) / r.nBid0);
}

inline UnitsKey ChainClockKey() { return UnitsKey(UNITS_CHAIN_CLOCK); }
inline UnitsKey ClockAtKey(uint32_t nHeight) { return UnitsKey(UNITS_CLOCK_AT).U32(nHeight); }
inline UnitsKey ShortfallLedgerKey(uint32_t nHouseID) { return UnitsKey(UNITS_SHORTFALL).U32(nHouseID); }
inline UnitsKey DemandBidKey(uint32_t nHouseID, uint32_t nHeight) { return UnitsKey(UNITS_DEMAND_BID).U32(nHouseID).U32(nHeight); }
/** The chain clock at one block (units 'H' + height): its active time (the windows' clock) and monotone time (the rate
 *  windows', so a failed house's windows can end at its failure). */
struct CClockAt {
    int64_t nActive;
    int64_t nMono;
    CClockAt() : nActive(0), nMono(0) {}
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nActive);
        READWRITE(nMono);
    }
};
/** A house's failed-swap shortfalls still able to claim (GOLD_B §4/§6): (clock paid, mg), pruned past the lapse. */
struct CShortfallLedger {
    std::vector<std::pair<int64_t, uint64_t>> vEntry;
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vEntry);
    }
};
inline UnitsKey HouseCharterKey(uint32_t nHouseID) { return UnitsKey(UNITS_CHARTER).U32(nHouseID); }
inline UnitsKey HouseRateKey(uint32_t nHouseID) { return UnitsKey(UNITS_HOUSE_RATE).U32(nHouseID); }
inline UnitsKey RateDayKey(uint32_t nHouseID, uint32_t nDay) { return UnitsKey(UNITS_RATE_DAY).U32(nHouseID).U32(nDay); }
inline UnitsKey RateKeyKey(uint32_t nHouseID) { return UnitsKey(UNITS_RATE_KEY).U32(nHouseID); }

inline uint32_t RateDayOf(int64_t nTime) { return nTime <= 0 ? 0 : (uint32_t)(nTime / RATE_DAY_SECONDS); }

/** Advance the chain clock to block nHeight with time nBlockTime (its median time past). Called once per connected
 *  block, AFTER its transactions, so a block's transactions see the parent's clock (the rule ClockBlocksForChecks and
 *  the mempool rely on). The first block with no clock record starts it at its own time, active time 0. */
void AdvanceChainClock(CUnitsView& units, uint32_t nHeight, int64_t nBlockTime, const Consensus::GramParams& gp);
/** The clock as the last advanced block left it; false before the first. */
bool GetChainClock(const CUnitsView& units, CChainClock& clock);

/** The rate in effect at block nHeight (a posting at nHeight takes effect at nHeight + 1). False: none yet. */
bool HouseRateAt(const CUnitsView& units, uint32_t nHouseID, uint32_t nHeight, uint64_t& nBid, uint64_t& nAsk);
/** The highest bid and ask in effect at any time in the nDays days up to and including the day of nNow, the rate in
 *  effect at nHeight and the latest posting included. False: the house has never posted. */
bool HouseRateWindowMax(const CUnitsView& units, uint32_t nHouseID, uint32_t nHeight, int64_t nNow, uint32_t nDays,
                        uint64_t& nMaxBid, uint64_t& nMaxAsk);
/** Posted within nMaxAgeSecs of nNow (the issuing refresh rule). */
bool HouseRateFresh(const CUnitsView& units, uint32_t nHouseID, int64_t nNow, int64_t nMaxAgeSecs);

/** The shape rule every posting meets: 0 < bid <= ask <= bid x (1 + spread). */
bool HouseRateShapeOK(uint64_t nBid, uint64_t nAsk, uint32_t nSpreadBps);
/** Apply a posting at block nHeight, clock time nNow. Checks the spread and the bid-rise cap and that the house hasn't
 *  posted in this block; on success writes the rate and the day records. On failure writes nothing. */
bool ApplyHouseRatePost(CUnitsView& units, uint32_t nHouseID, uint64_t nBid, uint64_t nAsk, uint32_t nHeight,
                        int64_t nNow, const Consensus::GramParams& gp, std::string& strReject, int64_t nActiveNow = -1);
/** The house's bid in effect at active time nActive (design 2026-11-07, the swap's bid at T_f): the current posting if
 *  it was made at or before nActive, else the previous one if that was; with two postings since, nFallback (the swap
 *  passes its bid at demand, so re-posting twice after T_f gains the house nothing). */
uint64_t HouseBidAtActive(const CUnitsView& units, uint32_t nHouseID, int64_t nActive, uint64_t nFallback,
                         int64_t nWindowSecs);

struct HouseCharter;
/** Apply a HOUSE_OP_CHARTER (its approvers already checked) at block nHeight, clock time nNow: ADD (at most
 *  MAX_CHARTER_TOKENS live entries, no live duplicate of the same chain and contract; prunes entries past their removal
 *  time first), REMOVE (takes effect nCharterRemovalSecs later; never the house's last entry not being removed),
 *  RELATED (restates the declaration of a live entry). Writes only on success. */
bool ApplyHouseCharter(CUnitsView& units, const HouseCharter& op, uint32_t nHeight, int64_t nNow,
                       const Consensus::GramParams& gp, std::string& strReject);
/** The house's live charter entry for a token, by chain id and contract (a demand names a token this way, so pruning
 *  an old entry can never change which token a demand means). */
bool HouseCharterTokenAt(const CUnitsView& units, uint32_t nHouseID, uint64_t nChainID,
                         const std::vector<unsigned char>& vchContract, int64_t nNow, CCharterToken& token);

/** The swap writes (ConnectIssuedTx, after CheckNoteOperation's checks): a new swap (record and pending units), DONE,
 *  PAID (shortfall at nRate), PROTESTED. */
void SwapOpen(CUnitsView& units, const uint256& hashLock, const CSwapRecord& rec);
void SwapSettle(CUnitsView& units, const uint256& hashLock, uint8_t nStatus, uint64_t nRate, int64_t nNow,
                int64_t nClockNow = 0, int64_t nLapseClock = 0);
/** The waterfall (GOLD_B §6): a failed house's swap claimed (NOTE_OP_SWAP_CLAIM): a pending one leaves the pending count. */
void SwapClaim(CUnitsView& units, const uint256& hashLock);
/** Shortfall mg the house paid within nLapseClock clock blocks up to nClockAt (its ledger, units 'M' + house). */
uint64_t HouseLiveShortfallMg(const CUnitsView& units, uint32_t nHouseID, int64_t nClockAt, int64_t nLapseClock);
uint64_t HouseLiveShortfallMgForChecks(uint32_t nHouseID, int64_t nClockAt, int64_t nLapseClock);
void SwapMarkProtested(CUnitsView& units, const uint256& hashLock);
/** Fix the swap's bid at the deadline if it isn't fixed yet: HouseBidAtActive at the deadline. */
void SwapFixBidT(CUnitsView& units, const uint256& hashLock);
/** The bid at T_f a swap op at or after the deadline would fix (against the scope's view; honours the test override). */
uint64_t SwapBidAtDeadlineForChecks(const CSwapRecord& r);
uint64_t HousePendingSwapUnits(const CUnitsView& units, uint32_t nHouseID);
bool SwapRecordForChecks(const uint256& hashLock, CSwapRecord& rec);
uint64_t HousePendingSwapUnitsForChecks(uint32_t nHouseID);
bool HouseCharterTokenForChecks(uint32_t nHouseID, uint64_t nChainID, const std::vector<unsigned char>& vchContract,
                                int64_t nNow, CCharterToken& token);

/** The reads above against the units check scope's view (issued.h UnitsCheckScope: the block so far, or the mempool's),
 *  else the DB at the tip. Window reads take "now" from the view's chain clock. */
bool HouseRateForChecks(uint32_t nHouseID, int nHeight, uint64_t& nBid, uint64_t& nAsk);
bool HouseRateMaxForChecks(uint32_t nHouseID, int nHeight, uint32_t nDays, uint64_t& nMaxBid, uint64_t& nMaxAsk);
bool ChainClockForChecks(CChainClock& clock);
/** The house's registered rate key (HOUSE_OP_RATE SETKEY), or false when none is set. */
bool HouseRateKeyForChecks(uint32_t nHouseID, std::vector<unsigned char>& vchPubKey);
/** The window maxima as they stood at block nAnchorHeight (its monotone time): a failed house's 30/90-day windows end at
 *  its failure E, never later (an insolvent house can't post, so a window running on would only lose its highs). */
bool HouseRateMaxAtForChecks(uint32_t nHouseID, int nAnchorHeight, uint32_t nDays, uint64_t& nMaxBid, uint64_t& nMaxAsk);
/** The bid in effect when a demand of the house connected at nDemandHeight (0 if none recorded): a formal demand fixes
 *  the rate at the demand (GOLD_B §3), so a house-alone discharge pays at least that. */
uint64_t DemandBidForChecks(uint32_t nHouseID, uint32_t nDemandHeight);
/** Record the bid in effect at a demand (once per house and height). */
void RecordDemandBid(CUnitsView& units, uint32_t nHouseID, uint32_t nHeight);
/** Has the house posted its rate within nMaxAgeSecs of the chain's monotone time (issuing needs a fresh rate)? */
bool HouseRateFreshForChecks(uint32_t nHouseID, int64_t nMaxAgeSecs);
/** The house's rate record (its last POST: height, chain-clock time), or false when it has never posted. */
bool HouseRateRecordForChecks(uint32_t nHouseID, CHouseRate& rate);
/** The house's charter (every entry, including those past their removal time not yet pruned). */
bool HouseCharterForChecks(uint32_t nHouseID, CHouseCharter& charter);
/** Unit tests only: when non-zero, every house's rate (and every window's maximum) is this bid and ask. */
extern uint64_t g_nHouseRateTestOverride;
/** The clock in clock blocks (600 s of active time) at a block height, against the check scope's view: the height's
 *  record; past the scope's tip, the tip's clock plus one clock block per block beyond it. Plain heights on regtest
 *  (Consensus::Params::fClockIsHeight) and while g_fClockIsHeightForTests is set. Installed as house.h's g_fnClockAt. */
int64_t ClockBlocksForChecks(int nHeight);
/** Unit tests only: windows count plain heights (the fixture sets it; the clock tests clear it). */
extern bool g_fClockIsHeightForTests;

#endif // BITCOIN_HOUSERATE_H
