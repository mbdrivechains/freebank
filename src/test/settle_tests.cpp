// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// T-s1 gates (docs-local/PHASE3_7_SETTLEMENT.md s11): codec round-trip +
// trailing-byte reject; digest vectors (field sensitivity, sig-field
// exclusion, prevouts/outputs binding); CHouse v6-record read defaults
// nLastSettleHeight to 0 (and a future version still hard-fails); u128
// envelope max-magnitude band vectors (standing principle 5).

#include <settle.h>

#include <bill.h>           // BillHashOutputs
#include <chainparams.h>    // CreateChainParams (per-network cadence pins)
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <house.h>
#include <key.h>
#include <note.h>
#include <pool.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <functional>

// Contextual settle-op validator (validation.cpp, external linkage; not in a
// public header). Forward-declared so the eligibility/cadence/priors/signature
// gates can be exercised directly with real ECDSA (the pool_tests pattern).
bool CheckSettleOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                          const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                          CHouse& houseAOut, CHouse& houseBOut);

// The shared overflow envelope must stay shared (settle.h documents equality).
static_assert(SETTLE_MAX_UNITS == POOL_MAX_AMOUNT,
              "SETTLE_MAX_UNITS must equal POOL_MAX_AMOUNT (shared u128 envelope)");

BOOST_FIXTURE_TEST_SUITE(settle_tests, BasicTestingSetup)

static SettleExchange FilledExchange()
{
    SettleExchange x;
    x.nHouseA = 1;
    x.nHouseB = 2;
    x.nMode = 1;
    x.nUnitsANotes = 60000;
    x.nUnitsBNotes = 45000;
    x.nCountANotes = 1;
    x.nCountBNotes = 1;
    x.vchPresentKeyOfANotes.assign(33, 0xAA);
    x.vchPresentKeyOfBNotes.assign(33, 0xBB);
    x.amountResidual = 15000;
    x.nPrevMintedUnitsA = 1200000;
    x.nPrevMintedUnitsB = 900000;
    x.nPrevLastSettleHeightA = 0;
    x.nPrevLastSettleHeightB = 0;
    x.nExpiryHeight = 1072;
    x.vchPresentSigOfANotes.assign(70, 0x01);
    x.vchPresentSigOfBNotes.assign(70, 0x02);
    x.vApproverIndexA = {0};
    x.vApproverSigA = {std::vector<unsigned char>(70, 0x03)};
    x.vApproverIndexB = {0, 1};
    x.vApproverSigB = {std::vector<unsigned char>(70, 0x04),
                       std::vector<unsigned char>(70, 0x05)};
    return x;
}

static std::vector<unsigned char> Encode(const SettleExchange& x)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << x;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

BOOST_AUTO_TEST_CASE(settle_codec_roundtrip)
{
    const SettleExchange a = FilledExchange();
    const std::vector<unsigned char> vch = Encode(a);
    BOOST_CHECK(vch.size() <= MAX_SETTLE_PAYLOAD);

    SettleExchange b;
    BOOST_CHECK(DecodeSettlePayload(vch, b));

    // Byte-exact round trip: re-encode and compare, then spot-check fields.
    BOOST_CHECK(Encode(b) == vch);
    BOOST_CHECK_EQUAL(b.nHouseA, a.nHouseA);
    BOOST_CHECK_EQUAL(b.nHouseB, a.nHouseB);
    BOOST_CHECK_EQUAL(b.nMode, a.nMode);
    BOOST_CHECK_EQUAL(b.nUnitsANotes, a.nUnitsANotes);
    BOOST_CHECK_EQUAL(b.nUnitsBNotes, a.nUnitsBNotes);
    BOOST_CHECK_EQUAL(b.nCountANotes, a.nCountANotes);
    BOOST_CHECK_EQUAL(b.nCountBNotes, a.nCountBNotes);
    BOOST_CHECK(b.vchPresentKeyOfANotes == a.vchPresentKeyOfANotes);
    BOOST_CHECK(b.vchPresentKeyOfBNotes == a.vchPresentKeyOfBNotes);
    BOOST_CHECK_EQUAL(b.amountResidual, a.amountResidual);
    BOOST_CHECK_EQUAL(b.nPrevMintedUnitsA, a.nPrevMintedUnitsA);
    BOOST_CHECK_EQUAL(b.nPrevMintedUnitsB, a.nPrevMintedUnitsB);
    BOOST_CHECK_EQUAL(b.nPrevLastSettleHeightA, a.nPrevLastSettleHeightA);
    BOOST_CHECK_EQUAL(b.nPrevLastSettleHeightB, a.nPrevLastSettleHeightB);
    BOOST_CHECK_EQUAL(b.nExpiryHeight, a.nExpiryHeight);
    BOOST_CHECK(b.vApproverIndexB == a.vApproverIndexB);
    BOOST_CHECK(b.vApproverSigB == a.vApproverSigB);

    // The leading 8 bytes are the two house ids (the ATMP memcpy contract).
    BOOST_REQUIRE(vch.size() >= 8);
    uint32_t nA = 0, nB = 0;
    memcpy(&nA, vch.data(), 4);
    memcpy(&nB, vch.data() + 4, 4);
    BOOST_CHECK_EQUAL(nA, a.nHouseA);
    BOOST_CHECK_EQUAL(nB, a.nHouseB);
}

BOOST_AUTO_TEST_CASE(settle_codec_trailing_bytes_reject)
{
    std::vector<unsigned char> vch = Encode(FilledExchange());
    vch.push_back(0x00);   // one trailing byte: decode must be exact
    SettleExchange b;
    BOOST_CHECK(!DecodeSettlePayload(vch, b));

    // Truncation must also fail (partial payloads never decode).
    std::vector<unsigned char> vchShort = Encode(FilledExchange());
    vchShort.pop_back();
    BOOST_CHECK(!DecodeSettlePayload(vchShort, b));
}

BOOST_AUTO_TEST_CASE(settle_sighash_vectors)
{
    const SettleExchange base = FilledExchange();
    const uint256 hp = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    const uint256 ho = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    const uint256 dBase = SettleExchangeSigHash(base, hp, ho);

    // Deterministic.
    BOOST_CHECK(SettleExchangeSigHash(base, hp, ho) == dBase);

    // Every VALUE field moves the digest.
    {
        SettleExchange m = base; m.nHouseA = 3;                    BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase);
    }
    { SettleExchange m = base; m.nHouseB = 9;                      BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nMode = 0;                        BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nUnitsANotes += 1;                BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nUnitsBNotes += 1;                BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nCountANotes += 1;                BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nCountBNotes += 1;                BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.vchPresentKeyOfANotes[0] ^= 1;    BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.vchPresentKeyOfBNotes[0] ^= 1;    BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.amountResidual += 1;              BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nPrevMintedUnitsA += 1;           BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nPrevMintedUnitsB += 1;           BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nPrevLastSettleHeightA += 1;      BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nPrevLastSettleHeightB += 1;      BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }
    { SettleExchange m = base; m.nExpiryHeight += 1;               BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) != dBase); }

    // SIG/INDEX fields are EXCLUDED: mutating them must NOT move the digest
    // (they authorize the digest; binding them would be circular).
    {
        SettleExchange m = base;
        m.vchPresentSigOfANotes.assign(70, 0xFF);
        m.vchPresentSigOfBNotes.clear();
        m.vApproverIndexA = {5};
        m.vApproverSigA = {std::vector<unsigned char>(70, 0xEE)};
        m.vApproverIndexB.clear();
        m.vApproverSigB.clear();
        BOOST_CHECK(SettleExchangeSigHash(m, hp, ho) == dBase);
    }

    // hashPrevouts and hashOutputs both bind.
    const uint256 hp2 = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");
    BOOST_CHECK(SettleExchangeSigHash(base, hp2, ho) != dBase);
    BOOST_CHECK(SettleExchangeSigHash(base, hp, hp2) != dBase);
}

BOOST_AUTO_TEST_CASE(settle_house_ser_v6_migration)
{
    // A v7 record with a non-zero stamp round-trips.
    CHouse h;
    h.nHouseID = 7;
    h.nMintedUnits = 123456;
    h.nLastAttestHeight = 100;
    h.amountLastAttestReserves = 50000;
    h.nLastSettleHeight = 777;

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << h;
    std::vector<unsigned char> v7bytes(ss.begin(), ss.end());
    {
        CDataStream rs(v7bytes, SER_DISK, PROTOCOL_VERSION);
        CHouse r;
        rs >> r;
        BOOST_CHECK_EQUAL(r.nLastSettleHeight, 777);
        BOOST_CHECK_EQUAL(r.nMintedUnits, h.nMintedUnits);
    }

    // Synthesize the SAME record at v6 layout: the v7 field is appended LAST,
    // so v6 bytes = v7 bytes minus the trailing u32, with the version byte
    // flipped to 6. Read must succeed with nLastSettleHeight defaulting to 0
    // and every other field intact (read-by-stored-version, code-enforced).
    BOOST_REQUIRE(v7bytes.size() > 4);
    BOOST_REQUIRE_EQUAL(v7bytes[0], 7);
    std::vector<unsigned char> v6bytes(v7bytes.begin(), v7bytes.end() - 4);
    v6bytes[0] = 6;
    {
        CDataStream rs(v6bytes, SER_DISK, PROTOCOL_VERSION);
        CHouse r;
        rs >> r;
        BOOST_CHECK_EQUAL(r.nLastSettleHeight, 0);
        BOOST_CHECK_EQUAL(r.nHouseID, h.nHouseID);
        BOOST_CHECK_EQUAL(r.nMintedUnits, h.nMintedUnits);
        BOOST_CHECK_EQUAL(r.nLastAttestHeight, h.nLastAttestHeight);
        BOOST_CHECK_EQUAL(r.amountLastAttestReserves, h.amountLastAttestReserves);
    }

    // A FUTURE version stays a hard read failure (never silently defaulted).
    std::vector<unsigned char> v8bytes = v7bytes;
    v8bytes[0] = 8;
    {
        CDataStream rs(v8bytes, SER_DISK, PROTOCOL_VERSION);
        CHouse r;
        BOOST_CHECK_THROW(rs >> r, std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(settle_par_eligible_predicate)
{
    CHouse h;
    h.status = HOUSE_STATUS_OPEN;
    h.nMintedUnits = 1000000;
    h.amountLastAttestReserves = 150000;   // 1500 bps > floor (1000)
    h.nLastAttestHeight = 1000;

    // Fresh attestation, healthy ratio: eligible.
    BOOST_CHECK(HouseParEligible(h, 1000 + HOUSE_ATTEST_CADENCE));
    // One block past the recency window: ineligible (even though still Open -
    // Open tolerates HOUSE_ATTEST_MISS_N windows; par-clearing does not).
    BOOST_CHECK(!HouseParEligible(h, 1000 + HOUSE_ATTEST_CADENCE + 1));
    // Below the floor: ineligible.
    {
        CHouse b = h;
        b.amountLastAttestReserves = 99999;   // 999 bps < 1000
        BOOST_CHECK(!HouseParEligible(b, 1000 + 10));
    }
    // Exactly at the floor: eligible (>=).
    {
        CHouse b = h;
        b.amountLastAttestReserves = 100000;  // exactly 1000 bps
        BOOST_CHECK(HouseParEligible(b, 1000 + 10));
    }
    // Never-attested house: ineligible once past one cadence from height 0.
    {
        CHouse b = h;
        b.nLastAttestHeight = 0;
        BOOST_CHECK(!HouseParEligible(b, (int)(HOUSE_ATTEST_CADENCE + 1)));
    }
}

BOOST_AUTO_TEST_CASE(settle_band_max_magnitude)
{
    // Principle 5: max-magnitude vectors at the named envelope ceiling.
    const uint64_t U = SETTLE_MAX_UNITS;   // 3*MAX_MONEY < 2^53

    // dU at the FULL envelope (3*MAX_MONEY) with the largest payable residual
    // (MAX_MONEY): far below the band -> the helper must REJECT cleanly, and
    // the point of the vector is that the u128 arithmetic cannot overflow on
    // the way to that answer.
    BOOST_CHECK(!SettleResidualInBand(U, 0, 1, MAX_MONEY));

    // Max payable case: dU == MAX_MONEY, residual == MAX_MONEY (exact par).
    BOOST_CHECK(SettleResidualInBand((uint64_t)MAX_MONEY, 0, 1, MAX_MONEY));

    // Exact band edges at a clean magnitude: parValue = 10^12.
    const uint64_t par = 1000000000000ULL;
    const CAmount lo = (CAmount)(par * (10000 - SETTLE_PAR_BAND_BPS) / 10000);   // 0.995 * par
    const CAmount hi = (CAmount)(par * (10000 + SETTLE_PAR_BAND_BPS) / 10000);   // 1.005 * par
    BOOST_CHECK(SettleResidualInBand(par, 0, 1, lo));         // exactly at the low edge
    BOOST_CHECK(SettleResidualInBand(par, 0, 1, hi));         // exactly at the high edge
    BOOST_CHECK(!SettleResidualInBand(par, 0, 1, lo - 1));    // one sat below
    BOOST_CHECK(!SettleResidualInBand(par, 0, 1, hi + 1));    // one sat above
    BOOST_CHECK(SettleResidualInBand(par, 0, 1, (CAmount)par)); // exact par

    // Envelope violations reject cleanly (never overflow).
    BOOST_CHECK(!SettleResidualInBand(U + 1, 0, 1, MAX_MONEY));
    BOOST_CHECK(!SettleResidualInBand(par, 0, 1, MAX_MONEY + 1));
    BOOST_CHECK(!SettleResidualInBand(par, 0, 1, -1));

    // Mode discipline.
    BOOST_CHECK(SettleResidualInBand(50000, 50000, 0, 0));      // pure swap
    BOOST_CHECK(!SettleResidualInBand(50000, 50000, 0, 1));     // mode 0 with residual
    BOOST_CHECK(!SettleResidualInBand(50000, 50000, 1, 0));     // mode 1 with dU == 0
    BOOST_CHECK(!SettleResidualInBand(60000, 45000, 0, 0));     // dU != 0 must be mode 1
    // Min-residual floor: dU below SETTLE_MIN_RESIDUAL cannot be mode 1.
    BOOST_CHECK(!SettleResidualInBand(50000 + (uint64_t)SETTLE_MIN_RESIDUAL - 1, 50000, 1,
                                      SETTLE_MIN_RESIDUAL - 1));
    BOOST_CHECK(SettleResidualInBand(50000 + (uint64_t)SETTLE_MIN_RESIDUAL, 50000, 1,
                                     SETTLE_MIN_RESIDUAL));
}

BOOST_AUTO_TEST_CASE(settle_tx_trailer_roundtrip)
{
    // v16 trailer serializes and round-trips through CTransaction.
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_SETTLE_VERSION;
    mtx.nSettleOp = SETTLE_OP_EXCHANGE;
    mtx.vchSettlePayload = Encode(FilledExchange());
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 15000;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mtx;
    CMutableTransaction back(deserialize, ss);
    BOOST_CHECK_EQUAL(back.nVersion, TRANSACTION_SETTLE_VERSION);
    BOOST_CHECK_EQUAL(back.nSettleOp, SETTLE_OP_EXCHANGE);
    BOOST_CHECK(back.vchSettlePayload == mtx.vchSettlePayload);
    BOOST_CHECK(CTransaction(back).GetHash() == CTransaction(mtx).GetHash());

    // A non-settle version does NOT carry the trailer.
    CMutableTransaction plain;
    plain.nVersion = 3;
    plain.vin.resize(1);
    plain.vout.resize(1);
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << plain;
    CMutableTransaction pback(deserialize, ss2);
    BOOST_CHECK_EQUAL(pback.nSettleOp, 0);
    BOOST_CHECK(pback.vchSettlePayload.empty());
}

// ---------------------------------------------------------------- T-s2 gates

static std::vector<unsigned char> FreshPubKey()
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

/** A SHAPE-valid mode-1 exchange tx: real compressed keys, 1-coin bundles,
 * dU = 15000 with the residual at exact par, residual output pinned at
 * vout[0]. (Signatures are dummies - verification is contextual, T-s3.) */
static CMutableTransaction ShapeValidTx(SettleExchange& x,
                                        const std::vector<unsigned char>& pkA,
                                        const std::vector<unsigned char>& pkB)
{
    x = SettleExchange();
    x.nHouseA = 1;
    x.nHouseB = 2;
    x.nMode = 1;
    x.nUnitsANotes = 60000;
    x.nUnitsBNotes = 45000;
    x.nCountANotes = 1;
    x.nCountBNotes = 1;
    x.vchPresentKeyOfANotes = pkA;
    x.vchPresentKeyOfBNotes = pkB;
    x.amountResidual = 15000;
    x.nPrevMintedUnitsA = 1200000;
    x.nPrevMintedUnitsB = 900000;
    x.nExpiryHeight = 0;
    x.vchPresentSigOfANotes.assign(70, 0x01);
    x.vchPresentSigOfBNotes.assign(70, 0x02);
    x.vApproverIndexA = {0};
    x.vApproverSigA = {std::vector<unsigned char>(70, 0x03)};
    x.vApproverIndexB = {0, 1};
    x.vApproverSigB = {std::vector<unsigned char>(70, 0x04),
                       std::vector<unsigned char>(70, 0x05)};

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_SETTLE_VERSION;
    mtx.nSettleOp = SETTLE_OP_EXCHANGE;
    mtx.vchSettlePayload = Encode(x);
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xa0"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xb0"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xc0"), 0)));
    mtx.vout.emplace_back(15000, NoteScriptForPubKey(pkB));   // residual (P2PKH shape)
    mtx.vout.emplace_back(12000, NoteScriptForPubKey(pkA));   // plain change
    return mtx;
}

static std::string ShapeReject(const CMutableTransaction& mtx)
{
    CValidationState state;
    if (CheckSettleTransactionShape(CTransaction(mtx), state))
        return "OK";
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(settle_shape_vectors)
{
    const std::vector<unsigned char> pkA = FreshPubKey();
    const std::vector<unsigned char> pkB = FreshPubKey();
    SettleExchange x;

    // Happy path.
    BOOST_CHECK_EQUAL(ShapeReject(ShapeValidTx(x, pkA, pkB)), "OK");

    // Unknown settle op.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); m.nSettleOp = 9;
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-op"); }
    // Trailing payload byte / truncation.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); m.vchSettlePayload.push_back(0);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-payload"); }
    // House order: equal, reversed, zero.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nHouseB = 1; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-house-order"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nHouseA = 5; x.nHouseB = 2; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-house-order"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nHouseA = 0; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-house-order"); }
    // Units range.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nUnitsANotes = 0; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-units-range"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nUnitsBNotes = SETTLE_MAX_UNITS + 1; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-units-range"); }
    // Bundle counts + vin size.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nCountANotes = 0; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-bundle-count"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nCountBNotes = SETTLE_MAX_BUNDLE_INPUTS + 1; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-bundle-count"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); m.vin.resize(1);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-vin-size"); }
    // Presenter keys: wrong length, invalid point.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vchPresentKeyOfANotes.resize(32); m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-presenter-key"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vchPresentKeyOfBNotes.assign(33, 0xAA); m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-presenter-key"); }
    // Presenter sigs: empty, oversized.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vchPresentSigOfANotes.clear(); m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-presenter-sig"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vchPresentSigOfBNotes.assign(81, 0x01); m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-presenter-sig"); }
    // Approver arrays: empty, size mismatch, non-ascending, index out of range.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vApproverIndexA.clear(); x.vApproverSigA.clear(); m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-approvers"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vApproverSigA.push_back(std::vector<unsigned char>(70, 0x06)); m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-approvers"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vApproverIndexB = {1, 1}; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-approvers"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.vApproverIndexA = {(uint32_t)MAX_HOUSE_PARTNERS}; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-approvers"); }
    // Mode discipline.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nMode = 2; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-mode"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nMode = 0; m.vchSettlePayload = Encode(x);   // dU != 0
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-mode"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.nUnitsBNotes = 60000; m.vchSettlePayload = Encode(x);   // dU == 0, mode 1
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-mode"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB);
      x.nMode = 0; x.nUnitsBNotes = 60000; x.amountResidual = 5; m.vchSettlePayload = Encode(x);   // mode 0 + residual
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-mode"); }
    // Band edges: one sat outside either boundary (dU = 15000, band = 50 bps
    // -> [14925, 15075]).
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.amountResidual = 14924; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-band"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); x.amountResidual = 15076; m.vchSettlePayload = Encode(x);
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-band"); }
    // Residual output: wrong value, non-P2PKH, missing.
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); m.vout[0].nValue = 14999;
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-residual-out"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); m.vout[0].scriptPubKey = CScript() << OP_TRUE;
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-residual-out"); }
    { CMutableTransaction m = ShapeValidTx(x, pkA, pkB); m.vout.clear();
      BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-residual-out"); }
}

/** Input-layer harness: houses 1 and 2; vin[0] = the A-issued (house-1) note
 * on the A-presenter key, vin[1] = the B-issued (house-2) note on the
 * B-presenter key, vin[2] = a plain funding coin. */
static CMutableTransaction MakeSettleSetup(CCoinsViewCache& cache, SettleExchange& x,
                                           const std::vector<unsigned char>& pkA,
                                           const std::vector<unsigned char>& pkB)
{
    CMutableTransaction mtx = ShapeValidTx(x, pkA, pkB);

    Coin noteA(CTxOut(1000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
    noteA.SetNote(1, 60000);
    cache.AddCoin(COutPoint(uint256S("0xa0"), 0), std::move(noteA), false);

    Coin noteB(CTxOut(1000, NoteScriptForPubKey(pkB)), 100, false, false, false, 0);
    noteB.SetNote(2, 45000);
    cache.AddCoin(COutPoint(uint256S("0xb0"), 0), std::move(noteB), false);

    Coin fund(CTxOut(40000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
    cache.AddCoin(COutPoint(uint256S("0xc0"), 0), std::move(fund), false);

    return mtx;
}

static std::string InputsReject(const CMutableTransaction& mtx, const CCoinsViewCache& cache)
{
    CValidationState state;
    CAmount fee = 0;
    if (Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee))
        return "OK";
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(settle_input_vectors)
{
    const std::vector<unsigned char> pkA = FreshPubKey();
    const std::vector<unsigned char> pkB = FreshPubKey();
    SettleExchange x;

    // Happy path clears the input layer.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        BOOST_CHECK_EQUAL(InputsReject(MakeSettleSetup(cache, x, pkA, pkB), cache), "OK");
    }
    // Demanded note in a bundle slot.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        CMutableTransaction mtx = MakeSettleSetup(cache, x, pkA, pkB);
        Coin demanded(CTxOut(1000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
        demanded.SetNote(1, 60000, 55);
        cache.AddCoin(COutPoint(uint256S("0xa0"), 0), std::move(demanded), true);
        BOOST_CHECK_EQUAL(InputsReject(mtx, cache), "bad-settle-demanded-note");
    }
    // Wrong issuer in the A slot.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        CMutableTransaction mtx = MakeSettleSetup(cache, x, pkA, pkB);
        Coin wrong(CTxOut(1000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
        wrong.SetNote(3, 60000);
        cache.AddCoin(COutPoint(uint256S("0xa0"), 0), std::move(wrong), true);
        BOOST_CHECK_EQUAL(InputsReject(mtx, cache), "bad-settle-bundle-issuer");
    }
    // Bundle coin on the WRONG presenter key.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        CMutableTransaction mtx = MakeSettleSetup(cache, x, pkA, pkB);
        Coin offkey(CTxOut(1000, NoteScriptForPubKey(pkB)), 100, false, false, false, 0);
        offkey.SetNote(1, 60000);
        cache.AddCoin(COutPoint(uint256S("0xa0"), 0), std::move(offkey), true);
        BOOST_CHECK_EQUAL(InputsReject(mtx, cache), "bad-settle-input-not-presenter");
    }
    // Sum off by one sat of units.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        CMutableTransaction mtx = MakeSettleSetup(cache, x, pkA, pkB);
        Coin off(CTxOut(1000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
        off.SetNote(1, 59999);
        cache.AddCoin(COutPoint(uint256S("0xa0"), 0), std::move(off), true);
        BOOST_CHECK_EQUAL(InputsReject(mtx, cache), "bad-settle-bundle-sum");
    }
    // THE NAMED VECTOR (econ-F6 / J7): the pool's dual-tagged note-side
    // custody coin (fNote + fPoolEscrow) smuggled into a bundle slot. Tag-bit
    // purity must reject it - botching this is LP-lockout grade.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        CMutableTransaction mtx = MakeSettleSetup(cache, x, pkA, pkB);
        Coin custody(CTxOut(1000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
        custody.SetNote(1, 60000);
        custody.SetPoolEscrow(1);
        cache.AddCoin(COutPoint(uint256S("0xa0"), 0), std::move(custody), true);
        BOOST_CHECK_EQUAL(InputsReject(mtx, cache), "bad-settle-tagged-input");
    }
    // A tagged coin in the FUNDING region (a note past the bundles).
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        CMutableTransaction mtx = MakeSettleSetup(cache, x, pkA, pkB);
        Coin extraNote(CTxOut(1000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
        extraNote.SetNote(1, 500);
        cache.AddCoin(COutPoint(uint256S("0xc0"), 0), std::move(extraNote), true);
        BOOST_CHECK_EQUAL(InputsReject(mtx, cache), "bad-settle-tagged-input");
    }
    // REGRESSION: the note-guard exemption must not open a hole - a PLAIN v3
    // tx spending a note coin still rejects with the original guard.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        Coin note(CTxOut(1000, NoteScriptForPubKey(pkA)), 100, false, false, false, 0);
        note.SetNote(1, 60000);
        cache.AddCoin(COutPoint(uint256S("0xd0"), 0), std::move(note), false);
        CMutableTransaction mtx;
        mtx.nVersion = 3;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xd0"), 0)));
        mtx.vout.emplace_back(500, NoteScriptForPubKey(pkB));
        BOOST_CHECK_EQUAL(InputsReject(mtx, cache), "bad-txns-spend-note-coin");
    }
}

// ---------------------------------------------------------------- T-s3 gates

static std::vector<unsigned char> PK(const CKey& k)
{
    const CPubKey p = k.GetPubKey();
    return std::vector<unsigned char>(p.begin(), p.end());
}

static std::vector<unsigned char> SignHash(const CKey& k, const uint256& h)
{
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(k.Sign(h, sig));
    return sig;
}

static CHouse MakeSettleHouse(uint32_t id, const std::vector<std::vector<unsigned char>>& partnerKeys,
                              uint32_t nThresholdM, uint64_t nMinted, CAmount amountReserves,
                              uint32_t nAttestHeight, const std::vector<unsigned char>& redeemPK)
{
    CHouse h;
    h.nHouseID = id;
    h.nThresholdM = nThresholdM;
    for (const auto& pk : partnerKeys) {
        HousePartner p;
        p.vchPubKey = pk;
        p.amountPledge = 100000;
        h.vPartner.push_back(p);
    }
    h.nMintedUnits = nMinted;
    h.amountLastAttestReserves = amountReserves;
    h.nLastAttestHeight = nAttestHeight;
    h.vchRedemptionDestPK = redeemPK;
    return h;
}

/** A fully co-signed exchange against hA/hB at nHeight: priors picked up from
 * the house records, residual routed to the creditor's redemption key, all
 * four signatures real over the shared digest. */
static CMutableTransaction BuildSignedSettle(SettleExchange& x, const CHouse& hA, const CHouse& hB,
                                             const std::vector<CKey>& apprA, const std::vector<CKey>& apprB,
                                             const CKey& presA, const CKey& presB,
                                             uint8_t nMode, uint32_t nExpiryHeight = 0)
{
    x = SettleExchange();
    x.nHouseA = hA.nHouseID;
    x.nHouseB = hB.nHouseID;
    x.nMode = nMode;
    x.nUnitsANotes = 60000;
    x.nUnitsBNotes = nMode == 1 ? 45000 : 60000;
    x.nCountANotes = 1;
    x.nCountBNotes = 1;
    x.vchPresentKeyOfANotes = PK(presA);
    x.vchPresentKeyOfBNotes = PK(presB);
    x.amountResidual = nMode == 1 ? 15000 : 0;
    x.nPrevMintedUnitsA = hA.nMintedUnits;
    x.nPrevMintedUnitsB = hB.nMintedUnits;
    x.nPrevLastSettleHeightA = hA.nLastSettleHeight;
    x.nPrevLastSettleHeightB = hB.nLastSettleHeight;
    x.nExpiryHeight = nExpiryHeight;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_SETTLE_VERSION;
    mtx.nSettleOp = SETTLE_OP_EXCHANGE;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xa0"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xb0"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xc0"), 0)));
    if (nMode == 1)   // dU > 0: A is net debtor, residual to B's declared key
        mtx.vout.emplace_back(15000, NoteScriptForPubKey(hB.vchRedemptionDestPK));
    mtx.vout.emplace_back(12000, NoteScriptForPubKey(PK(presA)));

    // Digest covers value fields + prevouts + outputs (sig fields excluded),
    // so it is computable before the signatures exist.
    const CTransaction ctx(mtx);
    const uint256 sighash = SettleExchangeSigHash(x, SettleHashPrevouts(ctx), BillHashOutputs(ctx));
    for (size_t i = 0; i < apprA.size(); i++) {
        x.vApproverIndexA.push_back((uint32_t)i);
        x.vApproverSigA.push_back(SignHash(apprA[i], sighash));
    }
    for (size_t i = 0; i < apprB.size(); i++) {
        x.vApproverIndexB.push_back((uint32_t)i);
        x.vApproverSigB.push_back(SignHash(apprB[i], sighash));
    }
    x.vchPresentSigOfANotes = SignHash(presA, sighash);
    x.vchPresentSigOfBNotes = SignHash(presB, sighash);
    mtx.vchSettlePayload = Encode(x);
    return mtx;
}

static std::string SettleOpReject(const CMutableTransaction& mtx,
                                  const std::map<uint32_t, CHouse>& houses, int nHeight,
                                  CHouse* pOutA = nullptr, CHouse* pOutB = nullptr)
{
    auto fnGetHouse = [&houses](uint32_t nID, CHouse& h) {
        auto it = houses.find(nID);
        if (it == houses.end()) return false;
        h = it->second;
        return true;
    };
    CValidationState state;
    CHouse outA, outB;
    if (!CheckSettleOperation(CTransaction(mtx), state, nHeight, fnGetHouse, outA, outB))
        return state.GetRejectReason();
    if (pOutA) *pOutA = outA;
    if (pOutB) *pOutB = outB;
    return "OK";
}

BOOST_AUTO_TEST_CASE(settle_contextual_vectors)
{
    // House A: solo (1-of-1). House B: 2-of-2 (exercises the multi-sig quorum).
    CKey kA1; kA1.MakeNewKey(true);
    CKey kB1; kB1.MakeNewKey(true);
    CKey kB2; kB2.MakeNewKey(true);
    CKey presA; presA.MakeNewKey(true);
    CKey presB; presB.MakeNewKey(true);
    CKey redA; redA.MakeNewKey(true);
    CKey redB; redB.MakeNewKey(true);
    const std::vector<CKey> apprA{kA1};
    const std::vector<CKey> apprB{kB1, kB2};
    const int H = 1100;

    const CHouse hA = MakeSettleHouse(1, {PK(kA1)}, 1, 1200000, 150000, 1000, PK(redA));
    const CHouse hB = MakeSettleHouse(2, {PK(kB1), PK(kB2)}, 2, 900000, 100000, 1000, PK(redB));
    const std::map<uint32_t, CHouse> houses{{1, hA}, {2, hB}};
    SettleExchange x;

    // Happy path, mode 1: both records mutate exactly (the s2.6 worked example).
    {
        CHouse outA, outB;
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H, &outA, &outB), "OK");
        BOOST_CHECK_EQUAL(outA.nMintedUnits, 1200000 - 60000);
        BOOST_CHECK_EQUAL(outA.nLastSettleHeight, (uint32_t)H);
        BOOST_CHECK_EQUAL(outB.nMintedUnits, 900000 - 45000);
        BOOST_CHECK_EQUAL(outB.nLastSettleHeight, (uint32_t)H);
    }
    // Happy path, mode 0 (pure swap - no residual output required).
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 0);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H), "OK");
    }
    // Unknown house.
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, {{1, hA}}, H), "bad-settle-unknown-house");
    }
    // Ineligible: attestation older than one cadence (Open still tolerates it;
    // par-clearing does not - the J6 recency conjunct).
    {
        CHouse stale = hB;
        stale.nLastAttestHeight = H - HOUSE_ATTEST_CADENCE - 1;
        CMutableTransaction mtx = BuildSignedSettle(x, hA, stale, apprA, apprB, presA, presB, 1);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, {{1, hA}, {2, stale}}, H), "bad-settle-house-ineligible");
    }
    // Ineligible: attested ratio below the floor.
    {
        CHouse thin = hB;
        thin.amountLastAttestReserves = 89999;   // 999.99 bps < 1000
        CMutableTransaction mtx = BuildSignedSettle(x, hA, thin, apprA, apprB, presA, presB, 1);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, {{1, hA}, {2, thin}}, H), "bad-settle-house-ineligible");
    }
    // Cadence: A settled 50 blocks ago (< nSettleCadence = 144; the suite
    // fixture selects MAIN params).
    {
        CHouse recent = hA;
        recent.nLastSettleHeight = H - 50;
        CMutableTransaction mtx = BuildSignedSettle(x, recent, hB, apprA, apprB, presA, presB, 1);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, {{1, recent}, {2, hB}}, H), "bad-settle-cadence");
    }
    // Priors: the DB record moved after signing (a MINT landed in between).
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        CHouse moved = hA;
        moved.nMintedUnits += 1;
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, {{1, moved}, {2, hB}}, H), "bad-settle-priors-mismatch");
    }
    // Burn exceeding outstanding liabilities (defensive; ratio stays eligible).
    {
        CHouse tiny = MakeSettleHouse(1, {PK(kA1)}, 1, 50000, 150000, 1000, PK(redA));
        CMutableTransaction mtx = BuildSignedSettle(x, tiny, hB, apprA, apprB, presA, presB, 1);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, {{1, tiny}, {2, hB}}, H), "bad-settle-units-exceed-minted");
    }
    // Residual to the WRONG key: dest check fires before signatures.
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        mtx.vout[0].scriptPubKey = NoteScriptForPubKey(PK(redA));   // creditor is B
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H), "bad-settle-residual-dest");
    }
    // Expired authorization.
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1, H - 1);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H), "bad-settle-expired");
    }
    // Tampered approver signature.
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        x.vApproverSigA[0][10] ^= 1;
        mtx.vchSettlePayload = Encode(x);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H), "bad-settle-approver");
    }
    // Quorum short: B is 2-of-2; presenting only one B sig must fail.
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        x.vApproverIndexB.resize(1);
        x.vApproverSigB.resize(1);
        mtx.vchSettlePayload = Encode(x);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H), "bad-settle-approver");
    }
    // Presenter signature from the wrong key (approvers still valid).
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        std::swap(x.vchPresentSigOfANotes, x.vchPresentSigOfBNotes);
        mtx.vchSettlePayload = Encode(x);
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H), "bad-settle-presenter-sig-invalid");
    }
    // Post-signing VALUE tamper: residual bumped 1 sat (still in band, dest and
    // priors fine) - the shared digest moves, every signature dies. This is
    // the atomic-mutual-consent property.
    {
        CMutableTransaction mtx = BuildSignedSettle(x, hA, hB, apprA, apprB, presA, presB, 1);
        x.amountResidual = 15001;
        mtx.vchSettlePayload = Encode(x);
        mtx.vout[0].nValue = 15001;
        BOOST_CHECK_EQUAL(SettleOpReject(mtx, houses, H), "bad-settle-approver");
    }
}

// The cadence is per-network consensus (main 144, regtest 12) and must never
// grow a runtime knob — pin the values so a chainparams edit is a loud test
// failure, not a silent consensus change.
BOOST_AUTO_TEST_CASE(settle_cadence_per_network)
{
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::MAIN)->GetConsensus().nSettleCadence, 144U);
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::REGTEST)->GetConsensus().nSettleCadence, 12U);
}

BOOST_AUTO_TEST_SUITE_END()
