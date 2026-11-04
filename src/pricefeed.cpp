// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricefeed.h>

#include <units.h>

#include <algorithm>
#include <limits>

namespace {

UnitsKey ObsPrefix(uint8_t nStream, const uint256& subject)
{
    return UnitsKey(UNITS_ORACLE_OBS).U8(nStream).Hash(subject);
}

UnitsKey FixKey(uint8_t nStream, const uint256& subject, uint32_t nHeight)
{
    return UnitsKey(UNITS_ORACLE_FIX).U8(nStream).Hash(subject).U32(nHeight);
}

uint32_t SubmitterOfKey(const UnitsKey& key)
{
    // prefix (1) + stream (1) + subject (32) + submitter (4, big-endian)
    const std::vector<unsigned char>& v = key.v;
    if (v.size() != 38)
        return 0;
    return ((uint32_t)v[34] << 24) | ((uint32_t)v[35] << 16) | ((uint32_t)v[36] << 8) | (uint32_t)v[37];
}

uint32_t HeightOfFixKey(const UnitsKey& key)
{
    const std::vector<unsigned char>& v = key.v;
    if (v.size() != 38)
        return 0;
    return ((uint32_t)v[34] << 24) | ((uint32_t)v[35] << 16) | ((uint32_t)v[36] << 8) | (uint32_t)v[37];
}

template <typename T>
bool DecodeValue(const UnitsValue& value, T& obj)
{
    try {
        CDataStream ss(value, SER_DISK, CLIENT_VERSION);
        ss >> obj;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

} // namespace

uint32_t PriceFeedQuorum(uint32_t nActive, const Consensus::GramParams& gp)
{
    const uint32_t nHalf = nActive / 2 + nActive % 2;
    return std::min(gp.nOracleQuorumMax, std::max(gp.nOracleQuorumMin, nHalf));
}

void PriceFeedRecord(CUnitsView& units, uint32_t nSubmitterID, const std::vector<COracleObs>& vObs, int nHeight)
{
    for (const COracleObs& o : vObs) {
        COracleObsRec rec;
        rec.nValue = o.nValue;
        rec.nAux = o.nAux;
        rec.nAux2 = o.nAux2;
        rec.nHeight = nHeight;
        units.Put(UnitsKey(ObsPrefix(o.nStream, o.subject)).U32(nSubmitterID), rec);
    }
}

bool PriceFeedFixAt(const CUnitsView& units, uint8_t nStream, const uint256& subject, int nHeight, uint32_t nWindow,
                    uint32_t nQuorum, const ReporterCounts& fnCounts, CPriceFix& fix)
{
    std::vector<uint64_t> vValue, vAux, vAux2;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(ObsPrefix(nStream, subject), UnitsKey(), SIZE_MAX)) {
        COracleObsRec rec;
        if (!DecodeValue(p.second, rec))
            continue;
        if (rec.nHeight > nHeight || (int64_t)rec.nHeight <= (int64_t)nHeight - (int64_t)nWindow)
            continue;
        if (!fnCounts(SubmitterOfKey(p.first)))
            continue;
        vValue.push_back(rec.nValue);
        vAux.push_back(rec.nAux);
        vAux2.push_back(rec.nAux2);
    }
    if (vValue.empty() || vValue.size() < nQuorum)
        return false;
    fix.nValue = OracleLowerMedian(vValue);
    fix.nAux = OracleLowerMedian(vAux);
    fix.nAux2 = OracleLowerMedian(vAux2);
    fix.nCount = (uint32_t)vValue.size();
    return true;
}

uint32_t PriceFeedActiveOn(const CUnitsView& units, uint8_t nStream, const uint256& subject, int nHeight, uint32_t nBlocks,
                           const ReporterCounts& fnCounts)
{
    uint32_t n = 0;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(ObsPrefix(nStream, subject), UnitsKey(), SIZE_MAX)) {
        COracleObsRec rec;
        if (!DecodeValue(p.second, rec))
            continue;
        if (rec.nHeight > nHeight || (int64_t)rec.nHeight <= (int64_t)nHeight - (int64_t)nBlocks)
            continue;
        if (fnCounts(SubmitterOfKey(p.first)))
            n++;
    }
    return n;
}

void PriceFeedEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp, uint32_t nActive,
                       const ReporterCounts& fnCounts)
{
    (void)nActive;   // review round 1 (G7a): each stream's quorum base is its own recent reporters
    for (uint8_t nStream : {ORACLE_STREAM_GOLD_ECX, ORACLE_STREAM_GOLD_USD}) {
        const uint32_t nQuorum = PriceFeedQuorum(
            PriceFeedActiveOn(units, nStream, uint256(), nHeight, gp.nOracleWindow * gp.nOracleActiveWindows, fnCounts), gp);
        CPriceFix fix;
        if (PriceFeedFixAt(units, nStream, uint256(), nHeight, gp.nOracleWindow, nQuorum, fnCounts, fix))
            units.Put(FixKey(nStream, uint256(), (uint32_t)nHeight), fix);
        // Keep the payout view's span back to the oldest height a payload may bind, and a day; older fixes go (the day
        // medians stay).
        const int64_t nOld = (int64_t)nHeight - (int64_t)std::max<uint32_t>(gp.nPriceViewBlocks + gp.nPriceBackBlocks, 144) - 1;
        if (nOld >= 0 && units.Have(FixKey(nStream, uint256(), (uint32_t)nOld)))
            units.Erase(FixKey(nStream, uint256(), (uint32_t)nOld));
    }

    // A day's last block: its median gold price (sats per gram), for the exit's two-year volatility measure.
    if (nHeight > 0 && (nHeight + 1) % 144 == 0) {
        std::vector<uint64_t> vDay;
        const UnitsKey prefix = UnitsKey(UNITS_ORACLE_FIX).U8(ORACLE_STREAM_GOLD_ECX).Hash(uint256());
        for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(prefix, FixKey(ORACLE_STREAM_GOLD_ECX, uint256(), (uint32_t)(nHeight - 143)), SIZE_MAX)) {
            if (HeightOfFixKey(p.first) > (uint32_t)nHeight)
                break;
            CPriceFix fix;
            if (DecodeValue(p.second, fix))
                vDay.push_back(fix.nValue);
        }
        if (!vDay.empty())
            units.Put(UnitsKey(UNITS_ORACLE_DAY).U32((uint32_t)(nHeight / 144)), OracleLowerMedian(vDay));
    }
}

bool PriceFeedPayoutView(const CUnitsView& units, int nHeight, const Consensus::GramParams& gp, uint64_t& nSatsPerGram)
{
    const int64_t nFrom = std::max<int64_t>(0, (int64_t)nHeight - (int64_t)gp.nPriceViewBlocks + 1);
    std::vector<uint64_t> v;
    const UnitsKey prefix = UnitsKey(UNITS_ORACLE_FIX).U8(ORACLE_STREAM_GOLD_ECX).Hash(uint256());
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(prefix, FixKey(ORACLE_STREAM_GOLD_ECX, uint256(), (uint32_t)nFrom), SIZE_MAX)) {
        if (HeightOfFixKey(p.first) > (uint32_t)nHeight)
            break;
        CPriceFix fix;
        if (DecodeValue(p.second, fix))
            v.push_back(fix.nValue);
    }
    if (v.empty())
        return false;
    nSatsPerGram = OracleLowerMedian(v);
    return true;
}

bool PriceFeedBackingAt(const CUnitsView& units, const uint256& tokenID, int nHeight, const Consensus::GramParams& gp,
                        uint32_t nQuorum, const ReporterCounts& fnCounts, CPriceFix& fix, int& nFixHeight)
{
    if (!PriceFeedFixAt(units, ORACLE_STREAM_BACKING, tokenID, nHeight, gp.nBackingWindow, nQuorum, fnCounts, fix))
        return false;
    // The newest counted report's height: issuing stops once it is older than nBackingStaleBlocks.
    nFixHeight = 0;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(ObsPrefix(ORACLE_STREAM_BACKING, tokenID), UnitsKey(), SIZE_MAX)) {
        COracleObsRec rec;
        if (DecodeValue(p.second, rec) && rec.nHeight <= nHeight && fnCounts(SubmitterOfKey(p.first)))
            nFixHeight = std::max(nFixHeight, (int)rec.nHeight);
    }
    return true;
}

int64_t Log2Q32(uint64_t x)
{
    if (x == 0)
        return 0;
    int n = 63;
    while (!(x >> n))
        n--;
    // z = x / 2^n in Q62, in [1, 2)
    unsigned __int128 z = n <= 62 ? (unsigned __int128)x << (62 - n) : (unsigned __int128)x >> (n - 62);
    int64_t r = (int64_t)n << 32;
    for (int i = 31; i >= 0; i--) {
        z = (z * z) >> 62;
        if (z >= ((unsigned __int128)1 << 63)) {
            z >>= 1;
            r |= (int64_t)1 << i;
        }
    }
    return r;
}

bool PriceFeedExitBand(const CUnitsView& units, uint32_t nDay, const Consensus::GramParams& gp, int& nBand)
{
    if (gp.nExitDays < 2 || nDay < gp.nExitDays)
        return false;
    static const int64_t LN2_Q32 = 2977044472;   // round(ln 2 x 2^32)
    __int128 nS1 = 0;
    unsigned __int128 nS2 = 0;
    uint64_t nPrev = 0;
    for (uint32_t d = nDay - gp.nExitDays; d <= nDay; d++) {
        uint64_t nMedian = 0;
        if (!units.Get(UnitsKey(UNITS_ORACLE_DAY).U32(d), nMedian) || nMedian == 0)
            return false;
        if (d > nDay - gp.nExitDays) {
            const int64_t nLog = (int64_t)(((__int128)(Log2Q32(nMedian) - Log2Q32(nPrev)) * LN2_Q32) >> 32);
            nS1 += nLog;
            nS2 += (unsigned __int128)((__int128)nLog * nLog);
        }
        nPrev = nMedian;
    }
    // sigma^2 = 365 var (var of Q32 logs / 2^64); var x n x (n - 1) = n S2 - S1^2. sigma <= b (bps) <=>
    // 365 x 10^8 x (n S2 - S1^2) <= b^2 x 2^64 x n (n - 1).
    const unsigned __int128 n = gp.nExitDays;
    const unsigned __int128 nVarNN = n * nS2 - (unsigned __int128)(nS1 * nS1);
    const auto fnAtMost = [&](uint32_t nBps) {
        // Both sides scaled down by 2^20 to stay inside 128 bits: LHS <= 3.65e10 x 2^84 / 2^20 ~ 2^99.
        const unsigned __int128 lhs = (unsigned __int128)36500000000ULL * (nVarNN >> 20);
        const unsigned __int128 rhs = (unsigned __int128)nBps * nBps * n * (n - 1) << 44;
        return lhs <= rhs;
    };
    nBand = fnAtMost(gp.nExitCalmBps) ? 0 : fnAtMost(gp.nExitStormBps) ? 1 : 2;
    return true;
}

void PriceFeedExitEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp)
{
    if (nHeight <= 0 || (nHeight + 1) % 144 != 0)
        return;
    int nBand = 0;
    if (!PriceFeedExitBand(units, (uint32_t)(nHeight / 144), gp, nBand))
        return;
    CExitState st;
    units.Get(UnitsKey(UNITS_EXIT), st);
    const CExitState before = st;
    if (st.nStepHeight == 0) {
        st.nStepHeight = (uint32_t)nHeight;   // measurable from today: the first step is a step period away
    } else if ((int64_t)nHeight - (int64_t)st.nStepHeight >= (int64_t)gp.nExitStepBlocks) {
        if (nBand == 0 && st.nStep < 4) {
            st.nStep++;
            st.nStepHeight = (uint32_t)nHeight;
        } else if (nBand == 2 && st.nStep > 0) {
            st.nStep--;
            st.nStepHeight = (uint32_t)nHeight;
        }
    }
    if (st.nStep != before.nStep || st.nStepHeight != before.nStepHeight)
        units.Put(UnitsKey(UNITS_EXIT), st);
}

uint8_t PriceFeedExitStep(const CUnitsView& units)
{
    CExitState st;
    return units.Get(UnitsKey(UNITS_EXIT), st) ? std::min<uint8_t>(st.nStep, 4) : 0;
}

void PriceFeedNoPriceEndBlock(CUnitsView& units, int nHeight, bool fPriced)
{
    if (fPriced || nHeight < 0)
        return;
    uint32_t nLast = 0, nEnd = 0;
    if (units.Get(UnitsKey(UNITS_NOPRICE_LAST), nLast) && units.Get(UnitsKey(UNITS_NOPRICE).U32(nLast), nEnd) &&
            (int64_t)nEnd + 1 == (int64_t)nHeight) {
        units.Put(UnitsKey(UNITS_NOPRICE).U32(nLast), (uint32_t)nHeight);
        return;
    }
    units.Put(UnitsKey(UNITS_NOPRICE).U32((uint32_t)nHeight), (uint32_t)nHeight);
    units.Put(UnitsKey(UNITS_NOPRICE_LAST), (uint32_t)nHeight);
}

uint32_t PriceFeedUnpricedBlocks(const CUnitsView& units, int nFrom, int nTo)
{
    if (nTo <= nFrom)
        return 0;
    const int64_t nLo = (int64_t)nFrom + 1, nHi = nTo;
    uint64_t n = 0;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(UnitsKey(UNITS_NOPRICE), UnitsKey(), SIZE_MAX)) {
        const std::vector<unsigned char>& k = p.first.v;
        if (k.size() != 5)
            continue;
        const int64_t nStart = ((uint32_t)k[1] << 24) | ((uint32_t)k[2] << 16) | ((uint32_t)k[3] << 8) | (uint32_t)k[4];
        if (nStart > nHi)
            break;
        uint32_t nEnd = 0;
        if (!DecodeValue(p.second, nEnd))
            continue;
        const int64_t a = std::max(nStart, nLo), b = std::min((int64_t)nEnd, nHi);
        if (b >= a)
            n += (uint64_t)(b - a + 1);
    }
    return (uint32_t)std::min<uint64_t>(n, std::numeric_limits<uint32_t>::max());
}
