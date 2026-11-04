// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICEFEED_H
#define BITCOIN_PRICEFEED_H

// The price feed in the units DB (gram-notes release, docs-local/GOLD_USD_SCOPE.md step 3; design draft 9 "The price
// feed"; R3-10; D-2026-11-01-6 item 3). Reporters' v17 submissions carry observations (oracle.h streams); each
// reporter's latest observation per (stream, subject) is kept. A fix at a height is the lower median of the latest
// observations within the window from reporters that count (bonded, not unbonding, active), if at least the quorum
// report: quorum = max(min, ceil(active / 2)) capped at max, active = bonded reporters with a submission within the
// last nOracleActiveWindows windows, so silent bonds can't raise it. Each block records its gold-price fixes; the
// payout view is the median of the last nPriceViewBlocks blocks' fixes, and a day's median is kept for the 2028
// exit's volatility measure (D-2026-11-01-5).

#include <consensus/params.h>
#include <oracle.h>
#include <serialize.h>
#include <uint256.h>

#include <functional>
#include <vector>

class CUnitsView;

/** A reporter's latest observation for one (stream, subject). */
struct COracleObsRec {
    uint64_t nValue = 0;
    uint64_t nAux = 0;
    uint64_t nAux2 = 0;
    int32_t nHeight = 0;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nValue);
        READWRITE(nAux);
        READWRITE(nAux2);
        READWRITE(nHeight);
    }
};

/** One block's fix for a stream (and, for a token stream, a subject). */
struct CPriceFix {
    uint64_t nValue = 0;
    uint64_t nAux = 0;
    uint64_t nAux2 = 0;
    uint32_t nCount = 0;   // reporters behind it

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nValue);
        READWRITE(nAux);
        READWRITE(nAux2);
        READWRITE(nCount);
    }
};

/** Does this reporter's observation count (bonded, not unbonding, active)? */
typedef std::function<bool(uint32_t nSubmitterID)> ReporterCounts;

uint32_t PriceFeedQuorum(uint32_t nActive, const Consensus::GramParams& gp);

/** Store a submission's observations as the reporter's latest. */
void PriceFeedRecord(CUnitsView& units, uint32_t nSubmitterID, const std::vector<COracleObs>& vObs, int nHeight);

/** The fix for (stream, subject) as of nHeight over the last nWindow blocks. False when fewer than nQuorum count. The
 *  value, aux and aux2 are each the lower median of the counted observations' (aux: the Ethereum block cited; aux2:
 *  the units of the token's burns paid out, in total). */
bool PriceFeedFixAt(const CUnitsView& units, uint8_t nStream, const uint256& subject, int nHeight, uint32_t nWindow,
                    uint32_t nQuorum, const ReporterCounts& fnCounts, CPriceFix& fix);

/** End of a block: record its gold-price fixes, prune history past what the payout view and a day need, and at a
 *  day's last block keep that day's median. */
/** Review round 1 (G7a): reporters (passing fnCounts: bonded, not unbonding) with an observation on (stream, subject)
 *  within the last nBlocks - the quorum base for that stream, so a near-silent reporter can't raise it. */
uint32_t PriceFeedActiveOn(const CUnitsView& units, uint8_t nStream, const uint256& subject, int nHeight, uint32_t nBlocks,
                           const ReporterCounts& fnCounts);
void PriceFeedEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp, uint32_t nActive,
                       const ReporterCounts& fnCounts);

/** The payout view's oracle side at nHeight: the median of the gold-per-ECX fixes of the last nPriceViewBlocks blocks,
 *  in sats per gram. False = stale (no fix in that span). */
bool PriceFeedPayoutView(const CUnitsView& units, int nHeight, const Consensus::GramParams& gp, uint64_t& nSatsPerGram);

/** log2(x) in Q32 fixed point (x > 0), by integer squaring: deterministic on every platform. */
int64_t Log2Q32(uint64_t x);

/** The exit (D-2026-11-01-5, dormant until two years of daily medians exist): the volatility band of the trailing
 *  nExitDays of daily medians ending at day nDay - 0 calm (sigma <= nExitCalmBps), 1 between, 2 stormy (sigma >
 *  nExitStormBps). False until every one of those days has a median. */
bool PriceFeedExitBand(const CUnitsView& units, uint32_t nDay, const Consensus::GramParams& gp, int& nBand);

/** The exit's state: the step (0..4, each 25% of capital and till that may count in sECX) and when it last moved. */
struct CExitState
{
    uint8_t nStep = 0;
    uint32_t nStepHeight = 0;   // 0 = sigma not yet measurable

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nStep);
        READWRITE(nStepHeight);
    }
};
/** At a day's last block (after its median is kept): measure sigma and move the step by the rules. */
void PriceFeedExitEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp);
uint8_t PriceFeedExitStep(const CUnitsView& units);

/** The no-price path (D-2026-11-01-6 item 3; legal condition 2, change 3): at each block's end, a block with no payout
 *  price (stale oracle and no usable pool) joins a run of such blocks; the overdue clocks (bills, protests, the equity
 *  proof's overdue bills) count only blocks with a price, so nothing falls overdue while none exists. */
void PriceFeedNoPriceEndBlock(CUnitsView& units, int nHeight, bool fPriced);
/** Blocks in (nFrom, nTo] that had no payout price. */
uint32_t PriceFeedUnpricedBlocks(const CUnitsView& units, int nFrom, int nTo);

/** A token's backing fix at nHeight (over nBackingWindow). False = none; nFixHeight = the newest counted report. */
bool PriceFeedBackingAt(const CUnitsView& units, const uint256& tokenID, int nHeight, const Consensus::GramParams& gp,
                        uint32_t nQuorum, const ReporterCounts& fnCounts, CPriceFix& fix, int& nFixHeight);

#endif // BITCOIN_PRICEFEED_H
