// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// T-o1 gates (docs-local/PHASE_GOLD_ORACLE.md s6): codec round-trip +
// trailing-byte reject both ops; digest field sensitivity (every value field
// moves the digest, the sig does not; prevouts/outputs/branch binding);
// price envelope + genesis-priors consistency; lower-median odd/even/
// duplicate vectors; brake vectors (rise-free, fall-bounded, elapsed cap,
// min-step at tiny scale, first-fix, u128 max-magnitude); leading-8 memcpy
// contract; both-direction unit conversion identity.

#include <oracle.h>

#include <bill.h>           // BillHashOutputs (the shared hashOutputs form)
#include <test/strictsig_util.h>  // A5 malleation vectors
#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <txmempool.h>
#include <undo.h>
#include <version.h>

#include <functional>
#include <map>

#include <boost/test/unit_test.hpp>

#include <cstring>

// Contextual oracle-op validator (validation.cpp, external linkage; the
// CheckSettleOperation test pattern).
bool CheckOracleOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                          const std::function<bool(uint32_t, uint256&)>& fnGetBlockHashAt,
                          const std::function<bool(uint32_t, COracleSubmitter&)>& fnGetSubmitter,
                          const std::function<bool(const std::vector<unsigned char>&)>& fnHaveKey,
                          const CGoldFix& fixPrev, uint32_t nNextSubmitterID,
                          COracleSubmitter& subOut, bool& fFreshBondOut, uint64_t& nPriceOut,
                          bool fMempool = false);

BOOST_FIXTURE_TEST_SUITE(oracle_tests, BasicTestingSetup)

static OracleSubmit FilledSubmit()
{
    OracleSubmit x;
    x.nSubmitterID = 3;
    x.nTargetHeight = 1000;
    x.nPriceMilligrams = 800000000;        // ~800 kg gold per 1000 ECX, mg
    x.nPrevRaw = 790000000;
    x.nPrevBraked = 795000000;
    x.nPrevFixHeight = 999;
    x.nPrevOwnLastSubmitHeight = 998;
    x.hashPrevBlockBind = uint256S("0x11");
    x.vchSig.assign(70, 0xAB);
    return x;
}

static OracleBond FilledBond()
{
    OracleBond x;
    x.nSubmitterID = 0;                    // fresh registration
    x.nTargetHeight = 500;
    x.vchSubmitterPubKey.assign(33, 0x02);
    x.vchSubmitterPubKey[0] = 0x02;
    x.vchSig.assign(70, 0xCD);
    return x;
}

template <typename T>
static std::vector<unsigned char> Encode(const T& x)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << x;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

static CMutableTransaction OracleTx(uint8_t nOp, const std::vector<unsigned char>& payload)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_ORACLE_VERSION;
    mtx.nOracleOp = nOp;
    mtx.vchOraclePayload = payload;
    return mtx;
}

static std::string ShapeReject(const CMutableTransaction& mtx)
{
    CValidationState state;
    if (CheckOracleTransactionShape(CTransaction(mtx), state)) return "";
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(oracle_codec_roundtrip)
{
    {
        OracleSubmit a = FilledSubmit(), b;
        BOOST_CHECK(DecodeOraclePayload(Encode(a), b));
        BOOST_CHECK(Encode(a) == Encode(b));
        std::vector<unsigned char> vch = Encode(a);
        vch.push_back(0x00);               // trailing byte: decode must be exact
        OracleSubmit c;
        BOOST_CHECK(!DecodeOraclePayload(vch, c));
    }
    {
        OracleBond a = FilledBond(), b;
        BOOST_CHECK(DecodeOraclePayload(Encode(a), b));
        BOOST_CHECK(Encode(a) == Encode(b));
        std::vector<unsigned char> vch = Encode(a);
        vch.push_back(0x00);
        OracleBond c;
        BOOST_CHECK(!DecodeOraclePayload(vch, c));
    }
}

BOOST_AUTO_TEST_CASE(oracle_leading8_memcpy_contract)
{
    // The version-wide guard contract: leading 8 bytes of BOTH payloads are
    // {u32 nSubmitterID, u32 nTargetHeight}, extractable by memcpy of the
    // encoded prefix without a full decode.
    OracleSubmit s = FilledSubmit();
    std::vector<unsigned char> vch = Encode(s);
    uint32_t id = 0, ht = 0;
    std::memcpy(&id, vch.data(), 4);
    std::memcpy(&ht, vch.data() + 4, 4);
    BOOST_CHECK_EQUAL(id, s.nSubmitterID);
    BOOST_CHECK_EQUAL(ht, s.nTargetHeight);

    OracleBond b = FilledBond();
    b.nSubmitterID = 7;
    vch = Encode(b);
    std::memcpy(&id, vch.data(), 4);
    std::memcpy(&ht, vch.data() + 4, 4);
    BOOST_CHECK_EQUAL(id, 7U);
    BOOST_CHECK_EQUAL(ht, b.nTargetHeight);
}

BOOST_AUTO_TEST_CASE(oracle_digest_sensitivity)
{
    const uint256 hp = uint256S("0xaa"), ho = uint256S("0xbb");
    OracleSubmit x = FilledSubmit();
    const uint256 base = OracleSubmitSigHash(x, hp, ho);

    // every VALUE field moves the digest
    { OracleSubmit y = x; y.nSubmitterID++;            BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    { OracleSubmit y = x; y.nTargetHeight++;           BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    { OracleSubmit y = x; y.nPriceMilligrams++;        BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    { OracleSubmit y = x; y.nPrevRaw++;                BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    { OracleSubmit y = x; y.nPrevBraked++;             BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    { OracleSubmit y = x; y.nPrevFixHeight++;          BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    { OracleSubmit y = x; y.nPrevOwnLastSubmitHeight++; BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    { OracleSubmit y = x; y.hashPrevBlockBind = uint256S("0x22");
                                                       BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) != base); }
    // prevouts + outputs bound (R-i6)
    BOOST_CHECK(OracleSubmitSigHash(x, uint256S("0xac"), ho) != base);
    BOOST_CHECK(OracleSubmitSigHash(x, hp, uint256S("0xbc")) != base);
    // the sig is EXCLUDED (two-round ceremony survives sig insertion)
    { OracleSubmit y = x; y.vchSig.assign(70, 0xEE);   BOOST_CHECK(OracleSubmitSigHash(y, hp, ho) == base); }

    OracleBond b = FilledBond();
    const uint256 bbase = OracleBondSigHash(b, hp, ho);
    { OracleBond y = b; y.nTargetHeight++;             BOOST_CHECK(OracleBondSigHash(y, hp, ho) != bbase); }
    { OracleBond y = b; y.vchSubmitterPubKey[1] ^= 1;  BOOST_CHECK(OracleBondSigHash(y, hp, ho) != bbase); }
    { OracleBond y = b; y.vchSig.assign(70, 0xEE);     BOOST_CHECK(OracleBondSigHash(y, hp, ho) == bbase); }
    // the two domains never collide
    BOOST_CHECK(OracleSubmitSigHash(x, hp, ho) != OracleBondSigHash(b, hp, ho));
}

BOOST_AUTO_TEST_CASE(oracle_shape_gates)
{
    // clean shapes pass
    BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(FilledSubmit()))), "");
    BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_BOND, Encode(FilledBond()))), "");

    BOOST_CHECK_EQUAL(ShapeReject(OracleTx(9, Encode(FilledSubmit()))), "bad-oracle-op");
    BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, {})), "bad-oracle-payload-size");
    BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT,
        std::vector<unsigned char>(MAX_ORACLE_PAYLOAD + 1, 0))), "bad-oracle-payload-size");
    BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, {0x01, 0x02})), "bad-oracle-payload");

    { OracleSubmit x = FilledSubmit(); x.nSubmitterID = 0;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-submitter-id"); }
    { OracleSubmit x = FilledSubmit(); x.nTargetHeight = 0;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-target-height"); }
    { OracleSubmit x = FilledSubmit(); x.nPriceMilligrams = 0;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-price-range"); }
    { OracleSubmit x = FilledSubmit(); x.nPriceMilligrams = ORACLE_PRICE_MAX + 1;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-price-range"); }
    // genesis-priors consistency [C-4]: nPrevFixHeight == 0 iff both views zero
    { OracleSubmit x = FilledSubmit(); x.nPrevFixHeight = 0;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-genesis-priors"); }
    { OracleSubmit x = FilledSubmit(); x.nPrevFixHeight = 0; x.nPrevRaw = 0; x.nPrevBraked = 0;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), ""); }
    { OracleSubmit x = FilledSubmit(); x.nPrevRaw = 0;   // half-genesis: range gate catches it
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-prior-range"); }
    { OracleSubmit x = FilledSubmit(); x.nPrevBraked = ORACLE_PRICE_MAX + 1;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-prior-range"); }
    { OracleSubmit x = FilledSubmit(); x.vchSig.clear();
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_SUBMIT, Encode(x))), "bad-oracle-sig"); }

    { OracleBond x = FilledBond(); x.nTargetHeight = 0;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_BOND, Encode(x))), "bad-oracle-target-height"); }
    { OracleBond x = FilledBond(); x.vchSubmitterPubKey.assign(32, 0x02);
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_BOND, Encode(x))), "bad-oracle-pubkey"); }
    { OracleBond x = FilledBond(); x.vchSubmitterPubKey[0] = 0x04;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_BOND, Encode(x))), "bad-oracle-pubkey"); }
    // fresh registration binds zero priors [C-3]
    { OracleBond x = FilledBond(); x.nPrevBondHeight = 5;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_BOND, Encode(x))), "bad-oracle-fresh-priors"); }
    { OracleBond x = FilledBond(); x.nSubmitterID = 4; x.nPrevBondHeight = 5;
      BOOST_CHECK_EQUAL(ShapeReject(OracleTx(ORACLE_OP_BOND, Encode(x))), ""); }
}

BOOST_AUTO_TEST_CASE(oracle_lower_median)
{
    BOOST_CHECK_EQUAL(OracleLowerMedian({5}), 5U);
    BOOST_CHECK_EQUAL(OracleLowerMedian({3, 1, 2}), 2U);
    BOOST_CHECK_EQUAL(OracleLowerMedian({4, 1, 3, 2}), 2U);          // even: LOWER middle
    BOOST_CHECK_EQUAL(OracleLowerMedian({7, 7, 7, 1}), 7U);          // duplicates: multiset
    BOOST_CHECK_EQUAL(OracleLowerMedian({1, 7, 7, 7}), 7U);          // order-independent
    BOOST_CHECK_EQUAL(OracleLowerMedian({ORACLE_PRICE_MAX, 1, ORACLE_PRICE_MAX}),
                      ORACLE_PRICE_MAX);                             // no averaging, no wrap
}

BOOST_AUTO_TEST_CASE(oracle_brake_vectors)
{
    const uint32_t PPM = 347;       // main: ~5%/day / 144 blocks
    const uint32_t CAP = 144;

    // first fix ever: braked := raw [C-4]
    BOOST_CHECK_EQUAL(OracleBrakedNext(0, 1000000, 1, PPM, CAP), 1000000U);
    // rises track raw immediately (never opens the arb)
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000000, 2000000, 1, PPM, CAP), 2000000U);
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000000, 1000000, 1, PPM, CAP), 1000000U);
    // falls: one block allows braked*347/1e6
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000000, 1, 1, PPM, CAP), 1000000U - 347U);
    // elapsed scales the allowance, capped at CAP [B-1]
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000000, 1, 10, PPM, CAP), 1000000U - 3470U);
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000000, 1, 100000, PPM, CAP),
                      1000000U - (uint64_t)347 * 144);
    // elapsed 0 is treated as 1 (defensive)
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000000, 1, 0, PPM, CAP), 1000000U - 347U);
    // a small fall inside the allowance lands ON raw, not below
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000000, 999900, 1, PPM, CAP), 999900U);
    // min-step: tiny scale can never freeze [B-2] (1000*347/1e6 floors to 0)
    BOOST_CHECK_EQUAL(OracleBrakedNext(1000, 1, 1, PPM, CAP), 999U);
    // floor never goes below the envelope minimum
    BOOST_CHECK_EQUAL(OracleBrakedNext(2, 1, 1, PPM, CAP), 1U);
    // max-magnitude u128 vector (principle 5): PRICE_MAX * 347 * 144 < 2^81
    const uint64_t big = ORACLE_PRICE_MAX;
    const uint64_t expect = big - (uint64_t)((unsigned __int128)big * 347 * 144 / 1000000);
    BOOST_CHECK_EQUAL(OracleBrakedNext(big, 1, 144, PPM, CAP), expect);
}

BOOST_AUTO_TEST_CASE(oracle_unit_conversion_identity)
{
    // Stored: MILLIGRAMS per 1000 ECX. Operational feeds quote grams per ECX.
    // grams/ECX -> stored: * 1e6 (1000 ECX * 1000 mg/g). Round-trip identity
    // must hold exactly for integer-gram feeds; the inverse direction (ECX
    // per gram - the promotion payout view) is floor division, pinned here
    // so the rounding direction is a tested constant of the system [F7-fid].
    const uint64_t grams_per_ecx = 800;                    // demo-scale rate
    const uint64_t stored = grams_per_ecx * 1000000;       // mg per 1000 ECX
    BOOST_CHECK_EQUAL(stored, 800000000U);
    BOOST_CHECK_EQUAL(stored / 1000000, grams_per_ecx);    // exact round-trip
    // inverse view (promotion): ECX-milliunits per gram = 1e9 / (stored/1e3)
    // floor direction: the redeemer receives the FLOOR (house-conservative).
    const uint64_t mecx_per_gram = (uint64_t)1000000000000ULL / stored;
    BOOST_CHECK_EQUAL(mecx_per_gram, 1250U);               // 1.25 ECX-milli/g at 800 g/ECX
    BOOST_CHECK(stored <= ORACLE_PRICE_MAX);
}

BOOST_AUTO_TEST_CASE(oracle_v17_trailer_roundtrip)
{
    CMutableTransaction mtx = OracleTx(ORACLE_OP_SUBMIT, Encode(FilledSubmit()));
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << CTransaction(mtx);
    CTransaction tx2(deserialize, ss);
    BOOST_CHECK_EQUAL(tx2.nVersion, TRANSACTION_ORACLE_VERSION);
    BOOST_CHECK_EQUAL(tx2.nOracleOp, ORACLE_OP_SUBMIT);
    BOOST_CHECK(tx2.vchOraclePayload == mtx.vchOraclePayload);
}

BOOST_AUTO_TEST_CASE(oracle_params_per_network)
{
    // The nSettleCadence discipline: pin every per-network constant so a
    // chainparams edit is a loud failure, never a silent consensus change.
    const auto main = CreateChainParams(CBaseChainParams::MAIN);
    const auto reg = CreateChainParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(main->GetConsensus().nOracleQuorumMin, 3U);
    BOOST_CHECK_EQUAL(reg->GetConsensus().nOracleQuorumMin, 3U);
    BOOST_CHECK_EQUAL(main->GetConsensus().nOracleBrakePpmPerBlock, 347U);
    BOOST_CHECK_EQUAL(reg->GetConsensus().nOracleBrakePpmPerBlock, 100000U);
    BOOST_CHECK_EQUAL(main->GetConsensus().nOracleBrakeElapsedCap, 144U);
    BOOST_CHECK_EQUAL(reg->GetConsensus().nOracleBrakeElapsedCap, 12U);
    BOOST_CHECK_EQUAL(main->GetConsensus().nOracleUnbondDelay, 2016U);
    BOOST_CHECK_EQUAL(reg->GetConsensus().nOracleUnbondDelay, 16U);
    // Operator-signed 2026-07-28 (ORACLE_WINDOW_PROPOSAL.md rows 2-3).
    BOOST_CHECK_EQUAL(main->GetConsensus().nOracleOpWindow, 6U);
    BOOST_CHECK_EQUAL(reg->GetConsensus().nOracleOpWindow, 3U);
    // k=1 starves the oracle outright under BMM (the candidate for H+1 is
    // templated in the call that connects H). Pin the floor so no future
    // chainparams edit can silently reintroduce the starvation.
    BOOST_CHECK(main->GetConsensus().nOracleOpWindow >= 2U);
    BOOST_CHECK(reg->GetConsensus().nOracleOpWindow >= 2U);
}

// ---- contextual gates (real ECDSA, mock lookups - the settle_tests form)

static CKey MakeKey(unsigned char seed)
{
    std::vector<unsigned char> vch(32, seed);
    CKey key;
    key.Set(vch.begin(), vch.end(), true);
    return key;
}

static std::vector<unsigned char> PK(const CKey& k)
{
    CPubKey p = k.GetPubKey();
    return std::vector<unsigned char>(p.begin(), p.end());
}

static CMutableTransaction BuildBondTx(const CKey& key, uint32_t nID, uint32_t nH,
                                       uint32_t nPrevBond = 0, uint32_t nPrevLast = 0,
                                       uint32_t nPrevUnbond = 0,
                                       const COutPoint& outPrevBond = COutPoint(),
                                       const CScript* pScriptOverride = nullptr)
{
    OracleBond x;
    x.nSubmitterID = nID;
    x.nTargetHeight = nH;
    x.vchSubmitterPubKey = PK(key);
    x.nPrevBondHeight = nPrevBond;
    x.nPrevLastSubmitHeight = nPrevLast;
    x.nPrevUnbondRequestHeight = nPrevUnbond;
    x.outPrevBond = outPrevBond;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_ORACLE_VERSION;
    mtx.nOracleOp = ORACLE_OP_BOND;
    mtx.vin.resize(1);
    // A returning bond must CONSOLIDATE the record's bond coin, so spend it -
    // exactly what the wallet does. Set before signing: the digest binds
    // hashPrevouts.
    mtx.vin[0].prevout = outPrevBond.IsNull() ? COutPoint(uint256S("0x77"), 0) : outPrevBond;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 100000000;
    // Override BEFORE signing: the digest binds hashOutputs, so a post-signing
    // swap would surface as a sig failure and hide the gate under test.
    mtx.vout[0].scriptPubKey = pScriptOverride ? *pScriptOverride
                                               : OracleBondScript(x.vchSubmitterPubKey);
    const CTransaction ctx(mtx);
    key.Sign(OracleBondSigHash(x, OracleHashPrevouts(ctx), BillHashOutputs(ctx)), x.vchSig);
    mtx.vchOraclePayload = Encode(x);
    return mtx;
}

static CMutableTransaction BuildSubmitTx(const CKey& key, uint32_t nID, uint32_t nH,
                                         uint64_t nPrice, const CGoldFix& fixPrev,
                                         uint32_t nOwnPrev, const uint256& hashPrev)
{
    OracleSubmit x;
    x.nSubmitterID = nID;
    x.nTargetHeight = nH;
    x.nPriceMilligrams = nPrice;
    x.nPrevRaw = fixPrev.nRaw;
    x.nPrevBraked = fixPrev.nBraked;
    x.nPrevFixHeight = fixPrev.nFixHeight;
    x.nPrevOwnLastSubmitHeight = nOwnPrev;
    x.hashPrevBlockBind = hashPrev;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_ORACLE_VERSION;
    mtx.nOracleOp = ORACLE_OP_SUBMIT;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0x88"), 1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 546;
    const CTransaction ctx(mtx);
    key.Sign(OracleSubmitSigHash(x, OracleHashPrevouts(ctx), BillHashOutputs(ctx)), x.vchSig);
    mtx.vchOraclePayload = Encode(x);
    return mtx;
}

BOOST_AUTO_TEST_CASE(oracle_contextual_gates)
{
    const int H = 200;
    const uint256 hashPrev = uint256S("0x99");
    CKey k1 = MakeKey(11), k2 = MakeKey(22);

    std::map<uint32_t, COracleSubmitter> db;
    auto fnGet = [&](uint32_t nID, COracleSubmitter& sub) {
        auto it = db.find(nID);
        if (it == db.end()) return false;
        sub = it->second;
        return true;
    };
    auto fnHaveKey = [&](const std::vector<unsigned char>& vchKey) {
        for (const auto& kv : db)
            if (kv.second.vchPubKey == vchKey) return true;
        return false;
    };
    CGoldFix fixNull;
    COracleSubmitter subOut;
    bool fFresh = false;
    uint64_t nPrice = 0;

    // Mock branch: every height resolves to hashPrev except where a test wants
    // a fork. The window anchors at nTargetHeight-1, and every vector here
    // signs at tip H-1 targeting H, so the anchor is H-1.
    auto fnAnchor = [&](uint32_t nH, uint256& hashOut) {
        if ((int)nH > H) return false;
        hashOut = ((int)nH == H - 1) ? hashPrev : uint256S("0xa11ce");
        return true;
    };
    // RunAt lets a vector connect at a height OTHER than its target, which is
    // the whole point of the window.
    auto RunAt = [&](const CMutableTransaction& mtx, const CGoldFix& fix, uint32_t nNext, int nAt) {
        CValidationState state;
        subOut = COracleSubmitter();
        fFresh = false;
        nPrice = 0;
        if (CheckOracleOperation(CTransaction(mtx), state, nAt, fnAnchor, fnGet, fnHaveKey,
                                 fix, nNext, subOut, fFresh, nPrice))
            return std::string("");
        return state.GetRejectReason();
    };
    auto Run = [&](const CMutableTransaction& mtx, const CGoldFix& fix, uint32_t nNext) {
        return RunAt(mtx, fix, nNext, H);
    };

    // fresh BOND connects: id assigned, outpoint pinned at vout 0
    CMutableTransaction bond1 = BuildBondTx(k1, 0, H);
    BOOST_CHECK_EQUAL(Run(bond1, fixNull, 1), "");
    BOOST_CHECK(fFresh);
    BOOST_CHECK_EQUAL(subOut.nSubmitterID, 1U);
    BOOST_CHECK_EQUAL(subOut.nBondHeight, (uint32_t)H);
    BOOST_CHECK(subOut.bondOutpoint == COutPoint(CTransaction(bond1).GetHash(), 0));
    db[1] = subOut;
    db[1].nBondHeight = H - 10;            // pretend it bonded earlier

    // duplicate key rejected
    BOOST_CHECK_EQUAL(Run(BuildBondTx(k1, 0, H), fixNull, 2), "bad-oracle-dup-key");

    // wrong-sig bond rejected (sign with k2, register k1's key)
    {
        CMutableTransaction bad = BuildBondTx(k1, 0, H);
        OracleBond x;
        BOOST_CHECK(DecodeOraclePayload(bad.vchOraclePayload, x));
        const CTransaction cbad(bad);
        k2.Sign(OracleBondSigHash(x, OracleHashPrevouts(cbad), BillHashOutputs(cbad)), x.vchSig);
        bad.vchOraclePayload = Encode(x);
        db.erase(1);
        BOOST_CHECK_EQUAL(Run(bad, fixNull, 1), "bad-oracle-sig-invalid");
        db[1] = subOut;                    // restore (subOut zeroed by Run - rebuild)
        db[1].nSubmitterID = 1;
        db[1].vchPubKey = PK(k1);
        db[1].nBondHeight = H - 10;
    }

    // A5: a malleated-but-still-valid payload sig is rejected end-to-end (not
    // just by the wrapper in isolation). Both axes, at a real op site: the
    // high-S flip and the DER-padded form each verify under legacy Verify yet
    // must be refused by the contextual check now that BOND routes through
    // VerifyStrict. Proves the swap is wired into the validation path.
    {
        CMutableTransaction canon = BuildBondTx(k1, 0, H);
        OracleBond x;
        BOOST_CHECK(DecodeOraclePayload(canon.vchOraclePayload, x));
        const std::vector<unsigned char> sigCanon = x.vchSig;

        for (const std::vector<unsigned char>& sigMal :
             {A5HighSFlip(sigCanon), A5DerPad(sigCanon)}) {
            BOOST_CHECK(sigMal != sigCanon);
            BOOST_CHECK(CPubKey(PK(k1)).Verify(               // legacy accepts it
                OracleBondSigHash(x, OracleHashPrevouts(CTransaction(canon)),
                                  BillHashOutputs(CTransaction(canon))),
                sigMal));
            CMutableTransaction bad = canon;
            OracleBond xm = x;
            xm.vchSig = sigMal;
            bad.vchOraclePayload = Encode(xm);
            db.erase(1);
            BOOST_CHECK_EQUAL(Run(bad, fixNull, 1), "bad-oracle-sig-invalid");
        }
        db[1] = subOut;                    // restore
        db[1].nSubmitterID = 1;
        db[1].vchPubKey = PK(k1);
        db[1].nBondHeight = H - 10;
    }

    // bond output not the escrow form
    {
        CMutableTransaction bad = BuildBondTx(k2, 0, H);
        bad.vout[0].scriptPubKey = CScript() << OP_TRUE;
        BOOST_CHECK_EQUAL(Run(bad, fixNull, 2), "bad-oracle-bond-out");
    }

    // The escrow must carry the REGISTERED key, not merely the right shape:
    // shape alone lets the price-signing key diverge from the bond-owning key,
    // which makes the coin unspendable by its own submitter and, at promotion,
    // means the bond is not the stake of the party being slashed.
    {
        const CScript scriptWrongKey = OracleBondScript(PK(k2));
        BOOST_CHECK_EQUAL(Run(BuildBondTx(k1, 0, H, 0, 0, 0, COutPoint(), &scriptWrongKey),
                              fixNull, 5), "bad-oracle-bond-out-key");
    }

    // returning bond: wrong priors rejected, right priors connect + cancel unbond
    db[1].nUnbondRequestHeight = H - 5;
    BOOST_CHECK_EQUAL(Run(BuildBondTx(k1, 1, H, H - 11, 0, H - 5), fixNull, 0),
                      "bad-oracle-priors-mismatch");
    // The bond OUTPOINT is a prior like the stamps - a returning bond that does
    // not bind the record's current outpoint is rejected, because DisconnectBlock
    // restores that field from the payload and nothing else can supply it.
    db[1].bondOutpoint = COutPoint(uint256S("0xfeed"), 1);
    BOOST_CHECK_EQUAL(Run(BuildBondTx(k1, 1, H, H - 10, 0, H - 5, COutPoint()), fixNull, 0),
                      "bad-oracle-priors-mismatch");
    BOOST_CHECK_EQUAL(Run(BuildBondTx(k1, 1, H, H - 10, 0, H - 5,
                                      COutPoint(uint256S("0xbeef"), 0)), fixNull, 0),
                      "bad-oracle-priors-mismatch");
    BOOST_CHECK_EQUAL(Run(BuildBondTx(k1, 1, H, H - 10, 0, H - 5,
                                      COutPoint(uint256S("0xfeed"), 1)), fixNull, 0), "");
    BOOST_CHECK_EQUAL(subOut.nUnbondRequestHeight, 0U);
    BOOST_CHECK_EQUAL(subOut.nBondHeight, (uint32_t)H);
    // ...and a returning bond that binds the right prior but does NOT SPEND the
    // record's coin is refused. Without this the value ratchet is opt-in: the
    // ratchet only fires on bond coins actually spent, so an unconsolidated
    // re-bond could abandon the old escrow, post a dust vout[0], and repoint
    // the record - a penalty-free unbond.
    {
        CMutableTransaction noConsolidate =
            BuildBondTx(k1, 1, H, H - 10, 0, H - 5, COutPoint(uint256S("0xfeed"), 1));
        noConsolidate.vin[0].prevout = COutPoint(uint256S("0xcafe"), 7);   // funds elsewhere
        // re-sign over the changed prevouts so this tests the rule, not the sig
        OracleBond ob;
        BOOST_CHECK(DecodeOraclePayload(noConsolidate.vchOraclePayload, ob));
        const CTransaction cnc(noConsolidate);
        k1.Sign(OracleBondSigHash(ob, OracleHashPrevouts(cnc), BillHashOutputs(cnc)), ob.vchSig);
        noConsolidate.vchOraclePayload = Encode(ob);
        BOOST_CHECK_EQUAL(Run(noConsolidate, fixNull, 0), "bad-oracle-bond-not-consolidated");
    }
    db[1].bondOutpoint = COutPoint();
    db[1].nUnbondRequestHeight = 0;

    // SUBMIT happy path against the null (genesis) fix
    CMutableTransaction sub1 = BuildSubmitTx(k1, 1, H, 800000000, fixNull, 0, hashPrev);
    BOOST_CHECK_EQUAL(Run(sub1, fixNull, 0), "");
    BOOST_CHECK_EQUAL(nPrice, 800000000U);
    BOOST_CHECK_EQUAL(subOut.nLastSubmitHeight, (uint32_t)H);

    // wrong target height / wrong branch / unknown id / same-block bond
    BOOST_CHECK_EQUAL(Run(BuildSubmitTx(k1, 1, H + 1, 800000000, fixNull, 0, hashPrev),
                          fixNull, 0), "bad-oracle-height");
    BOOST_CHECK_EQUAL(Run(BuildSubmitTx(k1, 1, H, 800000000, fixNull, 0, uint256S("0x9a")),
                          fixNull, 0), "bad-oracle-branch");
    BOOST_CHECK_EQUAL(Run(BuildSubmitTx(k2, 9, H, 800000000, fixNull, 0, hashPrev),
                          fixNull, 0), "bad-oracle-unknown-submitter");
    db[1].nBondHeight = H;
    BOOST_CHECK_EQUAL(Run(sub1, fixNull, 0), "bad-oracle-bond-height");
    db[1].nBondHeight = H - 10;

    // fix priors mismatch: the DB moved after signing
    CGoldFix fixLive;
    fixLive.nRaw = 810000000;
    fixLive.nBraked = 805000000;
    fixLive.nFixHeight = H - 1;
    BOOST_CHECK_EQUAL(Run(sub1, fixLive, 0), "bad-oracle-priors-mismatch");
    // own-stamp prior mismatch
    db[1].nLastSubmitHeight = H - 3;
    BOOST_CHECK_EQUAL(Run(sub1, fixNull, 0), "bad-oracle-priors-mismatch");
    db[1].nLastSubmitHeight = 0;

    // tampered sig dies
    {
        CMutableTransaction bad = sub1;
        OracleSubmit x;
        BOOST_CHECK(DecodeOraclePayload(bad.vchOraclePayload, x));
        x.vchSig[10] ^= 1;
        bad.vchOraclePayload = Encode(x);
        BOOST_CHECK_EQUAL(Run(bad, fixNull, 0), "bad-oracle-sig-invalid");
    }

    // ---- the validity WINDOW (operator-signed 2026-07-28; main k=6)
    // sub1 targets H. It must connect anywhere in [H, H+5] and die at H+6.
    // This is the whole fix: without it, an op signed against tip H-1 could
    // never reach the H candidate, because BMM templates that candidate in the
    // same call that connects H-1.
    {
        const uint32_t k = Params().GetConsensus().nOracleOpWindow;
        BOOST_CHECK_EQUAL(k, 6U);
        BOOST_CHECK_EQUAL(RunAt(sub1, fixNull, 0, H), "");                 // first height
        BOOST_CHECK_EQUAL(RunAt(sub1, fixNull, 0, H + 1), "");             // the block that was starving us
        BOOST_CHECK_EQUAL(RunAt(sub1, fixNull, 0, H + (int)k - 1), "");    // last valid height
        BOOST_CHECK_EQUAL(RunAt(sub1, fixNull, 0, H + (int)k),
                          "bad-oracle-height");                            // expired
        BOOST_CHECK_EQUAL(RunAt(sub1, fixNull, 0, H - 1),
                          "bad-oracle-height");                            // never before its target
    }

    // The anchor is nTargetHeight-1 on the CONNECTING branch, so a fork below
    // the signing tip still rejects - the cross-branch closure the old
    // parent-hash equality gave us, preserved rather than dropped.
    {
        CValidationState state;
        COracleSubmitter subTmp;
        bool fTmp = false;
        uint64_t nTmp = 0;
        auto fnForked = [&](uint32_t nH, uint256& hashOut) {
            if ((int)nH > H + 2) return false;
            hashOut = uint256S("0xf0f0");   // a different branch entirely
            return true;
        };
        BOOST_CHECK(!CheckOracleOperation(CTransaction(sub1), state, H + 1, fnForked,
                                          fnGet, fnHaveKey, fixNull, 0, subTmp, fTmp, nTmp));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-oracle-branch");
    }

    // A missing anchor (pruned/short chain) fails closed, never passes.
    {
        CValidationState state;
        COracleSubmitter subTmp;
        bool fTmp = false;
        uint64_t nTmp = 0;
        auto fnNoAnchor = [](uint32_t, uint256&) { return false; };
        BOOST_CHECK(!CheckOracleOperation(CTransaction(sub1), state, H, fnNoAnchor,
                                          fnGet, fnHaveKey, fixNull, 0, subTmp, fTmp, nTmp));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-oracle-branch");
    }

    // The BOND window, same shape (BOND was the observed starvation casualty).
    {
        CMutableTransaction b = BuildBondTx(k2, 0, H);
        BOOST_CHECK_EQUAL(RunAt(b, fixNull, 9, H + 2), "");
        BOOST_CHECK_EQUAL(RunAt(b, fixNull, 9, H + 6), "bad-oracle-height");
    }
}

// ---- T-o3: bond-coin tagging + spend gate (the settle_tests input-layer form)

BOOST_AUTO_TEST_CASE(oracle_bond_coin_ser_roundtrip)
{
    CKey k1 = MakeKey(41);
    Coin c(CTxOut(100000000, OracleBondScript(PK(k1))), 77, false, false, false, 0);
    c.SetOracleBond();
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << c;
    Coin c2;
    ss >> c2;
    BOOST_CHECK(c2.fOracleBond);
    BOOST_CHECK_EQUAL(c2.nHeight, 77U);
    BOOST_CHECK(c2.out.scriptPubKey == OracleBondScript(PK(k1)));
    // The tag never bleeds into a default-constructed or cleared coin.
    Coin c3;
    BOOST_CHECK(!c3.fOracleBond);
    c.Clear();
    BOOST_CHECK(!c.fOracleBond);
}

// The UNDO record is a second, independent serialization of a Coin, and the
// chainstate round-trip above passing says nothing about it. T-o3 appended the
// tag to coins.h and missed undo.h, so a reorg over any bond consolidation
// restored the coin UNTAGGED - anyone-can-spend script with its only guard
// gone, and a fork between reorged and freshly-synced nodes. Pin both.
BOOST_AUTO_TEST_CASE(oracle_bond_coin_undo_roundtrip)
{
    CKey k1 = MakeKey(42);
    Coin c(CTxOut(250000000, OracleBondScript(PK(k1))), 91, false, false, false, 0);
    c.SetOracleBond();
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << TxInUndoSerializer(&c);
    Coin restored;
    TxInUndoDeserializer des(&restored);
    ss >> des;
    BOOST_CHECK_MESSAGE(restored.fOracleBond,
        "undo record dropped fOracleBond - a reorg would free the bond coin");
    BOOST_CHECK_EQUAL(restored.nHeight, 91U);
    BOOST_CHECK(restored.out.scriptPubKey == OracleBondScript(PK(k1)));
    BOOST_CHECK_EQUAL(restored.out.nValue, 250000000);
    // An untagged coin must stay untagged through the same path.
    Coin plain(CTxOut(5000, CScript() << OP_TRUE), 91, false, false, false, 0);
    CDataStream ss2(SER_DISK, PROTOCOL_VERSION);
    ss2 << TxInUndoSerializer(&plain);
    Coin restored2;
    TxInUndoDeserializer des2(&restored2);
    ss2 >> des2;
    BOOST_CHECK(!restored2.fOracleBond);
}

// The mempool coin view is a THIRD place the tag must appear. Untagged there,
// a plain spend of an UNCONFIRMED bond passes ATMP and then bricks every block
// template at ConnectBlock (the DR-2 permanent-brick class) - free to trigger.
BOOST_AUTO_TEST_CASE(oracle_bond_coin_mempool_view_tag)
{
    CKey k1 = MakeKey(43);
    CMutableTransaction bond = BuildBondTx(k1, 0, 300);
    CTxMemPool pool;
    const CTransaction ctx(bond);
    TestMemPoolEntryHelper entry;
    pool.addUnchecked(ctx.GetHash(), entry.FromTx(bond));

    CCoinsView base;
    CCoinsViewCache cache(&base);
    CCoinsViewMemPool view(&cache, pool);

    Coin coin;
    BOOST_CHECK(view.GetCoin(COutPoint(ctx.GetHash(), 0), coin));
    BOOST_CHECK_MESSAGE(coin.fOracleBond,
        "unconfirmed bond coin untagged in the mempool view - a plain spend "
        "would pass ATMP and brick every subsequent template");
    // Non-bond outputs of the same tx (and other vouts) must NOT be tagged.
    Coin coin1;
    if (view.GetCoin(COutPoint(ctx.GetHash(), 1), coin1))
        BOOST_CHECK(!coin1.fOracleBond);
}

BOOST_AUTO_TEST_CASE(oracle_bond_coin_gate)
{
    CCoinsView base;
    CCoinsViewCache cache(&base);
    CKey k1 = MakeKey(51), k2 = MakeKey(52);
    const uint256 hashPrev = uint256S("0x99");

    // AddCoins on a real BOND tx must tag vout[0] fOracleBond and nothing else
    // (the self-tag rule: connect == rollforward from the tx alone).
    CMutableTransaction bond1 = BuildBondTx(k1, 0, 100);
    AddCoins(cache, CTransaction(bond1), 100, 0, 0);
    const COutPoint bondOut(CTransaction(bond1).GetHash(), 0);
    {
        Coin c;
        BOOST_CHECK(cache.GetCoin(bondOut, c));
        BOOST_CHECK(c.fOracleBond);
        BOOST_CHECK(!c.fHouseEscrow && !c.fPoolEscrow && !c.fNote && !c.fBillEscrow);
    }
    // ...and a SUBMIT tags nothing.
    {
        CGoldFix fixNull;
        CMutableTransaction sub = BuildSubmitTx(k1, 1, 100, 800000000, fixNull, 0, hashPrev);
        AddCoins(cache, CTransaction(sub), 100, 0, 0);
        Coin c;
        BOOST_CHECK(cache.GetCoin(COutPoint(CTransaction(sub).GetHash(), 0), c));
        BOOST_CHECK(!c.fOracleBond);
    }

    // Plain funding coin + a note-tagged coin for the colored-input gate.
    Coin fund(CTxOut(200000000, CScript() << OP_TRUE), 50, false, false, false, 0);
    cache.AddCoin(COutPoint(uint256S("0xf0"), 0), std::move(fund), false);
    Coin note(CTxOut(546, CScript() << OP_TRUE), 50, false, false, false, 0);
    note.SetNote(7, 1000, 0);
    cache.AddCoin(COutPoint(uint256S("0xf1"), 0), std::move(note), false);

    auto InputsReject = [&](const CMutableTransaction& mtx) {
        CValidationState state;
        CAmount fee;
        if (Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee))
            return std::string("");
        return state.GetRejectReason();
    };

    // A plain tx sweeping the anyone-can-spend bond coin is a bond drain.
    {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = bondOut;
        mtx.vout.resize(1);
        mtx.vout[0].nValue = 90000000;
        BOOST_CHECK_EQUAL(InputsReject(mtx), "bad-txns-spend-oracle-bond");
    }

    // A SUBMIT eroding its own bond is rejected with the rest.
    {
        CGoldFix fixNull;
        CMutableTransaction mtx = BuildSubmitTx(k1, 1, 200, 800000000, fixNull, 0, hashPrev);
        mtx.vin[0].prevout = bondOut;
        BOOST_CHECK_EQUAL(InputsReject(mtx), "bad-txns-spend-oracle-bond");
    }

    // Same-key re-bond consolidates: the input layer passes (contextual
    // priors/sig checks are CheckOracleOperation's business, not this gate's).
    {
        CMutableTransaction mtx = BuildBondTx(k1, 1, 200, 90, 0, 0);
        mtx.vin.resize(2);
        mtx.vin[0].prevout = bondOut;
        mtx.vin[1].prevout = COutPoint(uint256S("0xf0"), 0);
        mtx.vout[0].nValue = 150000000;
        BOOST_CHECK_EQUAL(InputsReject(mtx), "");
    }

    // ...but it may not SHRINK the escrow. Without this ratchet a "re-bond" is
    // a penalty-free unbond: spend the 1 BTX bond, re-post vout[0] at a
    // satoshi, take the rest as plain change - and the scaffold's claim that a
    // bond leaves escrow only into another bond is simply false.
    {
        CMutableTransaction mtx = BuildBondTx(k1, 1, 200, 90, 0, 0);
        mtx.vin.resize(1);
        mtx.vin[0].prevout = bondOut;          // a 1.0 BTX bond coin
        mtx.vout.resize(2);
        mtx.vout[0].nValue = 1;                // escrow shrunk to dust
        mtx.vout[1] = CTxOut(99000000, CScript() << OP_TRUE);   // the rest walks
        BOOST_CHECK_EQUAL(InputsReject(mtx), "bad-oracle-bond-value-decrease");
    }
    // Exactly equal is fine (a pure re-bond with no top-up).
    {
        CMutableTransaction mtx = BuildBondTx(k1, 1, 200, 90, 0, 0);
        mtx.vin.resize(1);
        mtx.vin[0].prevout = bondOut;
        mtx.vout[0].nValue = 100000000;
        BOOST_CHECK_EQUAL(InputsReject(mtx), "");
    }

    // Cross-submitter sweep: k2's bond spending k1's bond coin fails the
    // in-script key pin - by script comparison, never a lookup.
    {
        CMutableTransaction mtx = BuildBondTx(k2, 0, 200);
        mtx.vin.resize(2);
        mtx.vin[0].prevout = COutPoint(uint256S("0xf0"), 0);
        mtx.vin[1].prevout = bondOut;
        BOOST_CHECK_EQUAL(InputsReject(mtx), "bad-oracle-bond-input-key");
    }

    // Oracle txs fund from plain value only: a colored coin is rejected.
    {
        CMutableTransaction mtx = BuildBondTx(k2, 0, 200);
        mtx.vin[0].prevout = COutPoint(uint256S("0xf1"), 0);
        BOOST_CHECK_EQUAL(InputsReject(mtx), "bad-oracle-colored-input");
    }
}

BOOST_AUTO_TEST_SUITE_END()
