// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>   // BillHashOutputs - the outputs-hash every note sighash binds
#include <note.h>

#include <house.h>
#include <houserate.h>   // g_nHouseRateTestOverride (SA-N3)
#include <issued.h>      // GoldBrassageBps (SA-N3)
#include <token.h>   // NoteTokenKeyset (UR1-7)
#include <units.h>   // CUnitsView (S1X-6)

#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <txmempool.h>
#include <utilstrencodings.h>
#include <version.h>

#include <functional>

#include <boost/test/unit_test.hpp>
#include <units.h>   // CUnitsView (S1X-5)

// Contextual note-op validator (validation.cpp, external linkage; not in a
// public header). Forward-declared so the negative direction of the 3.5 note
// guards can be exercised directly (R-i6 test-quality fixes).
bool CheckNoteOperation(const CTransaction& tx, CValidationState& state, int nHeight, uint64_t nNoteUnitsIn,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CHouse& houseOut, bool& fHouseChanged, bool fMempool = false);

// Stage 0 C1 test shim: the transaction with payload p serialized into its op field (a C1 digest takes the whole tx;
// the payload's signature fields are stripped, so it may be passed before or after they are filled).
template <typename T, typename P>
static CTransaction C1With(const T& tx, std::vector<unsigned char> CMutableTransaction::*field, const P& p)
{
    CMutableTransaction m(tx);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    (m.*field).assign(ss.begin(), ss.end());
    return CTransaction(m);
}

// Stage 0 C1: a MINT tx for house nHouse minting vU, whose input is hp and whose output pays a script made from ho.
static uint256 C1MintSigHash(uint32_t nHouse, const std::vector<uint64_t>& vU, const uint256& hp, const uint256& ho)
{
    CMutableTransaction m;
    m.nVersion = TRANSACTION_NOTE_VERSION;
    m.nNoteOp = NOTE_OP_MINT;
    m.vin.push_back(CTxIn(COutPoint(hp, 0)));
    m.vout.push_back(CTxOut(NOTE_DUST_VALUE, CScript() << std::vector<unsigned char>(ho.begin(), ho.end())));
    NoteMint mi;
    mi.nHouseID = nHouse;
    mi.vUnits = vU;
    return NoteMintSigHash(C1With(m, &CMutableTransaction::vchNotePayload, mi));
}

BOOST_FIXTURE_TEST_SUITE(note_tests, BasicTestingSetup)

static std::vector<unsigned char> FreshPubKey(CKey& key)
{
    key.MakeNewKey(true);
    CPubKey pub = key.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

// A valid MINT tx: one note output of `units` to a holder, approver sig present.
// nAsOfHeight seeds the R-i7 reserve-proof recency field (0 by default; the proof
// set is empty unless a caller fills it).
/** Stage 0 rule A: a MINT's approvers are checked before its caps, so the test MINTs are signed: by this key, the first
 *  partner of the houses the cap tests build (MintApproverPub). */
static const CKey& MintApproverKey()
{
    static CKey key;
    if (!key.IsValid())
        key.MakeNewKey(true);
    return key;
}
static std::vector<unsigned char> MintApproverPub()
{
    const CPubKey pub = MintApproverKey().GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

static CMutableTransaction MakeMintTx(uint32_t nHouseID, uint64_t units, uint32_t nAsOfHeight = 0)
{
    CKey keyHolder;
    std::vector<unsigned char> pubHolder = FreshPubKey(keyHolder);

    NoteMint mint;
    mint.nHouseID = nHouseID;
    mint.vUnits.push_back(units);
    mint.nAsOfHeight = nAsOfHeight;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_MINT;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pubHolder)));
    {   // Stage 0 C1: the approver signs the whole tx (the approver fields are stripped)
        CDataStream ss0(SER_NETWORK, PROTOCOL_VERSION);
        ss0 << mint;
        mtx.vchNotePayload = std::vector<unsigned char>(ss0.begin(), ss0.end());
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(MintApproverKey().Sign(NoteMintSigHash(CTransaction(mtx)), vchSig));
        mint.vApproverIndex.push_back(0);
        mint.vApproverSig.push_back(vchSig);
    }
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mint;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

BOOST_AUTO_TEST_CASE(note_sighash_domain_separation)
{
    std::vector<uint64_t> u{100, 50};
    const uint256 outs = uint256S("aa");
    const uint256 prev = uint256S("dd");
    std::vector<uint256> v;
    // Stage 0 C1: the tx-class digests take the whole transaction; each op keeps its own domain.
    CMutableTransaction t;
    t.nVersion = TRANSACTION_NOTE_VERSION;
    t.nNoteOp = NOTE_OP_TRANSFER;
    t.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    t.vout.push_back(CTxOut(NOTE_DUST_VALUE, CScript() << OP_TRUE));
    NoteTransfer xf;
    xf.nHouseID = 1;
    xf.vUnits = u;
    xf.vchSenderPubKey = std::vector<unsigned char>(33, 0x02);
    { CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << xf; t.vchNotePayload.assign(ss.begin(), ss.end()); }
    const CTransaction tx(t);
    v.push_back(C1MintSigHash(1, u, prev, outs));
    v.push_back(NoteTransferSigHash(tx));
    v.push_back(NoteRedeemSigHash(tx));
    v.push_back(NoteClaimSigHash(tx));
    v.push_back(NoteDemandSigHash(tx));
    v.push_back(NoteProtestSigHash(tx));
    for (size_t i = 0; i < v.size(); i++)
        for (size_t j = i + 1; j < v.size(); j++)
            BOOST_CHECK(v[i] != v[j]);
    // C1 binds every field but the signatures: a payload field, an output, an input's sequence, nLockTime.
    const uint256 h0 = NoteTransferSigHash(tx);
    { CMutableTransaction m = t; NoteTransfer x2 = xf; x2.vUnits[0]++; CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << x2;
      m.vchNotePayload.assign(ss.begin(), ss.end()); BOOST_CHECK(NoteTransferSigHash(CTransaction(m)) != h0); }
    { CMutableTransaction m = t; m.vout[0].nValue++; BOOST_CHECK(NoteTransferSigHash(CTransaction(m)) != h0); }
    { CMutableTransaction m = t; m.vin[0].nSequence--; BOOST_CHECK(NoteTransferSigHash(CTransaction(m)) != h0); }
    { CMutableTransaction m = t; m.nLockTime = 7; BOOST_CHECK(NoteTransferSigHash(CTransaction(m)) != h0); }
    { CMutableTransaction m = t; NoteTransfer x2 = xf; x2.vchSenderSig.assign(70, 0x30); CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
      ss << x2; m.vchNotePayload.assign(ss.begin(), ss.end()); BOOST_CHECK(NoteTransferSigHash(CTransaction(m)) == h0); }

    // Sensitive to every bound field, including the input set (replay guard)
    BOOST_CHECK(C1MintSigHash(1, u, prev, outs) != C1MintSigHash(2, u, prev, outs));
    BOOST_CHECK(C1MintSigHash(1, u, prev, outs) != C1MintSigHash(1, {100, 51}, prev, outs));
    BOOST_CHECK(C1MintSigHash(1, u, prev, outs) != C1MintSigHash(1, u, prev, uint256S("bb")));
    BOOST_CHECK(C1MintSigHash(1, u, prev, outs) != C1MintSigHash(1, u, uint256S("ee"), outs));
}

BOOST_AUTO_TEST_CASE(note_sum_units)
{
    uint64_t total = 0;
    BOOST_CHECK(SumNoteUnits({1, 2, 3}, total) && total == 6);
    BOOST_CHECK(SumNoteUnits({100}, total) && total == 100);
    BOOST_CHECK(!SumNoteUnits({}, total));            // empty
    BOOST_CHECK(!SumNoteUnits({1, 0, 2}, total));     // zero element
    BOOST_CHECK(!SumNoteUnits({(uint64_t)MAX_MONEY, 1}, total)); // overflow past money range
    BOOST_CHECK(SumNoteUnits({(uint64_t)MAX_MONEY}, total) && total == (uint64_t)MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(note_script_roundtrip)
{
    CKey k; std::vector<unsigned char> pub = FreshPubKey(k);
    CScript script = NoteScriptForPubKey(pub);
    CTxDestination dest;
    BOOST_REQUIRE(ExtractDestination(script, dest));
    BOOST_CHECK(boost::get<CKeyID>(&dest) != nullptr);
    BOOST_CHECK(*boost::get<CKeyID>(&dest) == CPubKey(pub).GetID());
}

BOOST_AUTO_TEST_CASE(note_payload_roundtrip)
{
    NoteMint mint;
    mint.nHouseID = 7;
    mint.vUnits = {10, 20, 30};
    mint.vApproverIndex = {0, 2};
    mint.vApproverSig = {std::vector<unsigned char>(70, 1), std::vector<unsigned char>(70, 2)};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mint;
    NoteMint m2;
    BOOST_REQUIRE(DecodeNotePayload(std::vector<unsigned char>(ss.begin(), ss.end()), m2));
    BOOST_CHECK_EQUAL(m2.nHouseID, 7);
    BOOST_CHECK(m2.vUnits == mint.vUnits);
    BOOST_CHECK(m2.vApproverIndex == mint.vApproverIndex);

    // nHouseID is the leading 4 bytes (the mempool guard relies on this)
    std::vector<unsigned char> raw(ss.begin(), ss.end());
    uint32_t leading = 0;
    memcpy(&leading, raw.data(), 4);
    BOOST_CHECK_EQUAL(leading, 7);

    // Trailing bytes rejected
    ss << uint8_t(0xff);
    BOOST_CHECK(!DecodeNotePayload(std::vector<unsigned char>(ss.begin(), ss.end()), m2));

    NoteRedeem r;
    r.nHouseID = 3;
    CKey k; r.vchHolderPubKey = FreshPubKey(k);
    r.vchHolderSig = std::vector<unsigned char>(70, 0x30);
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << r;
    NoteRedeem r2;
    BOOST_REQUIRE(DecodeNotePayload(std::vector<unsigned char>(ss2.begin(), ss2.end()), r2));
    BOOST_CHECK_EQUAL(r2.nHouseID, 3);
    BOOST_CHECK(r2.vchHolderPubKey == r.vchHolderPubKey);
}

BOOST_AUTO_TEST_CASE(note_tx_serialization_roundtrip)
{
    CMutableTransaction mtx = MakeMintTx(1, 100);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mtx;
    CMutableTransaction mtx2;
    ss >> mtx2;
    BOOST_CHECK_EQUAL(mtx2.nVersion, TRANSACTION_NOTE_VERSION);
    BOOST_CHECK_EQUAL(mtx2.nNoteOp, NOTE_OP_MINT);
    BOOST_CHECK(mtx2.vchNotePayload == mtx.vchNotePayload);
    BOOST_CHECK(CTransaction(mtx2).GetHash() == CTransaction(mtx).GetHash());
}

BOOST_AUTO_TEST_CASE(note_shape_valid)
{
    CValidationState state;
    BOOST_CHECK(CheckNoteTransactionShape(CTransaction(MakeMintTx(1, 100)), state));
}

BOOST_AUTO_TEST_CASE(note_shape_rejections)
{
    CValidationState state;

    // v0.2.20: LOCK / UNLOCK are live, but a payload of another op still fails
    // their decode (each op has exactly one encoding)
    {
        CMutableTransaction mtx = MakeMintTx(1, 100);
        mtx.nNoteOp = NOTE_OP_LOCK;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
        mtx.nNoteOp = NOTE_OP_UNLOCK;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
    }
    // Zero-unit mint rejected
    {
        CMutableTransaction mtx = MakeMintTx(1, 100);
        NoteMint bad;
        bad.nHouseID = 1; bad.vUnits = {0};
        bad.vApproverIndex = {0}; bad.vApproverSig = {std::vector<unsigned char>(70, 0x30)};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << bad;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
    }
    // Note output with the wrong base value rejected
    {
        CMutableTransaction mtx = MakeMintTx(1, 100);
        mtx.vout[0].nValue = NOTE_DUST_VALUE + 1;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
    }
    // Note output that is not P2PKH rejected
    {
        CMutableTransaction mtx = MakeMintTx(1, 100);
        mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
    }
    // Fewer outputs than declared units rejected
    {
        CMutableTransaction mtx = MakeMintTx(1, 100);
        NoteMint bad;
        bad.nHouseID = 1; bad.vUnits = {100, 50};   // 2 note outputs declared
        bad.vApproverIndex = {0}; bad.vApproverSig = {std::vector<unsigned char>(70, 0x30)};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << bad;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());   // but only 1 vout
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
    }
    // Mint with no approvers rejected
    {
        CMutableTransaction mtx = MakeMintTx(1, 100);
        NoteMint bad;
        bad.nHouseID = 1; bad.vUnits = {100};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << bad;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
    }
    // Transfer with a bad sender pubkey rejected
    {
        NoteTransfer x;
        x.nHouseID = 1; x.vUnits = {100};
        x.vchSenderPubKey = std::vector<unsigned char>(20, 0x02);   // wrong size = invalid
        x.vchSenderSig = std::vector<unsigned char>(70, 0x30);
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION; mtx.nNoteOp = NOTE_OP_TRANSFER;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << x;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        CKey k; mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(FreshPubKey(k))));
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), state));
    }
}

BOOST_AUTO_TEST_CASE(note_mint_sig_binding)
{
    // An approver signature over the mint sighash breaks if vUnits or outputs change.
    CKey key; key.MakeNewKey(true);
    std::vector<uint64_t> u{100};
    const uint256 outs = uint256S("aa");
    const uint256 prev = uint256S("dd");
    const uint256 sighash = C1MintSigHash(1, u, prev, outs);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    BOOST_CHECK(key.GetPubKey().Verify(sighash, sig));
    BOOST_CHECK(!key.GetPubKey().Verify(C1MintSigHash(1, {101}, prev, outs), sig));
    BOOST_CHECK(!key.GetPubKey().Verify(C1MintSigHash(1, u, prev, uint256S("bb")), sig));
    BOOST_CHECK(!key.GetPubKey().Verify(C1MintSigHash(2, u, prev, outs), sig));
    // Different input set (hashPrevouts) breaks the sig -> mint replay defeated
    BOOST_CHECK(!key.GetPubKey().Verify(C1MintSigHash(1, u, uint256S("ee"), outs), sig));
}

// Interest over nBlocks at the network schedule (10%/yr from block 0).
static CAmount FlatInterest(uint64_t nUnits, uint32_t nBlocks)
{
    return NoteDeferralInterest(nUnits, 0, nBlocks, Params().GetConsensus().vDeferInterestSchedule);
}

BOOST_AUTO_TEST_CASE(note_deferral_interest_math)
{
    // 3.5 D6 / v0.2.18 Q1-Q2: simple, pro-rated by block, at the scheduled
    // rate - 10%/yr (1000 bps) from block 0 on every network.
    // BLOCKS_PER_YEAR = 52560.
    const uint64_t U = 100000000;   // 1 BTX-worth of units
    BOOST_REQUIRE_EQUAL(DeferInterestBpsAt(Params().GetConsensus().vDeferInterestSchedule, 0), 1000u);

    // A full year at 10%
    BOOST_CHECK_EQUAL(FlatInterest(U, BLOCKS_PER_YEAR), U * 10 / 100);
    // Half a year -> half the interest
    BOOST_CHECK_EQUAL(FlatInterest(U, BLOCKS_PER_YEAR / 2), U * 10 / 200);
    // 90 days -> ~2.466% (the formula, exactly)
    BOOST_CHECK_EQUAL(FlatInterest(U, 12960), (uint64_t)U * 1000 * 12960 / (10000 * BLOCKS_PER_YEAR));
    // The window position does not matter on a one-step schedule
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 700000, 700000 + 12960, Params().GetConsensus().vDeferInterestSchedule),
                      FlatInterest(U, 12960));

    // Degenerate inputs pay nothing
    BOOST_CHECK_EQUAL(FlatInterest(0, BLOCKS_PER_YEAR), 0);
    BOOST_CHECK_EQUAL(FlatInterest(U, 0), 0);
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 5000, 4000, Params().GetConsensus().vDeferInterestSchedule), 0);  // reversed
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 0, 1000, {}), 0);                                                  // empty schedule

    // Monotone in time and in principal (a holder never loses by waiting)
    BOOST_CHECK(FlatInterest(U, 1000) <= FlatInterest(U, 1001));
    BOOST_CHECK(FlatInterest(U, 1000) <= FlatInterest(2 * U, 1000));

    // Simple, NOT compounding: two years is exactly twice one year
    BOOST_CHECK_EQUAL(FlatInterest(U, 2 * BLOCKS_PER_YEAR), 2 * FlatInterest(U, BLOCKS_PER_YEAR));

    // The 128-bit path: units near the lambda-max supply over a long wait must
    // not wrap, and interest alone is capped inside the money range.
    const uint64_t bigU = (uint64_t)MAX_MONEY * 3;
    BOOST_CHECK(FlatInterest(bigU, BLOCKS_PER_YEAR) <= (CAmount)MAX_MONEY);
    BOOST_CHECK(FlatInterest(bigU, 100 * BLOCKS_PER_YEAR) <= (CAmount)MAX_MONEY);
    BOOST_CHECK_EQUAL(NoteDeferralInterest(bigU, 0, 0xffffffffu, {{0, 0xffffffffu}}), (CAmount)MAX_MONEY);
    // ...and for a realistic principal the value is exact, not clamped
    BOOST_CHECK_EQUAL(FlatInterest((uint64_t)MAX_MONEY, BLOCKS_PER_YEAR),
                      (CAmount)((uint64_t)MAX_MONEY * 10 / 100));
}

BOOST_AUTO_TEST_CASE(note_deferral_interest_schedule_piecewise)
{
    // v0.2.18: the rate is a HEIGHT SCHEDULE; a later release may append a
    // step. Interest is computed piecewise, each block at its own rate.
    const uint64_t U = 100000000;
    const std::vector<Consensus::DeferInterestStep> v = {{0, 1000}, {100000, 500}, {200000, 2000}};
    BOOST_CHECK_EQUAL(DeferInterestBpsAt(v, 0), 1000u);
    BOOST_CHECK_EQUAL(DeferInterestBpsAt(v, 99999), 1000u);
    BOOST_CHECK_EQUAL(DeferInterestBpsAt(v, 100000), 500u);
    BOOST_CHECK_EQUAL(DeferInterestBpsAt(v, 199999), 500u);
    BOOST_CHECK_EQUAL(DeferInterestBpsAt(v, 200000), 2000u);
    BOOST_CHECK_EQUAL(DeferInterestBpsAt(v, 0xffffffffu), 2000u);

    const auto Exact = [&](uint64_t bpsBlocks) {   // one floor over the summed bps*blocks
        return (CAmount)(((unsigned __int128)U * bpsBlocks) / ((unsigned __int128)10000 * BLOCKS_PER_YEAR));
    };
    // Entirely inside one segment = the flat formula at that segment's rate
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 10, 10 + BLOCKS_PER_YEAR, v), U * 10 / 100);
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 120000, 120000 + BLOCKS_PER_YEAR, v), U * 5 / 100);
    // Straddling one boundary: 10,000 blocks at 10% then 10,000 at 5%
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 90000, 110000, v), Exact(1000ull * 10000 + 500ull * 10000));
    // Straddling two boundaries: 1,000 @10% + 100,000 @5% + 3,000 @20%
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 99000, 203000, v),
                      Exact(1000ull * 1000 + 500ull * 100000 + 2000ull * 3000));
    // Additive across a split point (up to the single final floor)
    const CAmount a = NoteDeferralInterest(U, 90000, 150000, v);
    const CAmount b = NoteDeferralInterest(U, 150000, 210000, v);
    const CAmount ab = NoteDeferralInterest(U, 90000, 210000, v);
    BOOST_CHECK(ab >= a + b && ab <= a + b + 1);
    // A boundary exactly at the window edge
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 100000, 100000 + BLOCKS_PER_YEAR, v), U * 5 / 100);
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 100000 - BLOCKS_PER_YEAR, 100000, v), U * 10 / 100);
    // Blocks before the first step accrue nothing (schedules start at 0 on
    // every network, so this range is empty in practice)
    const std::vector<Consensus::DeferInterestStep> vLate = {{1000, 1000}};
    BOOST_CHECK_EQUAL(NoteDeferralInterest(U, 0, 2000, vLate), Exact(1000ull * 1000));
    BOOST_CHECK_EQUAL(DeferInterestBpsAt(vLate, 999), 0u);
}

BOOST_AUTO_TEST_CASE(note_demand_shape)
{
    CKey keyHolder;
    NoteDemand dem;
    dem.nHouseID = 1;
    dem.vchHolderPubKey = FreshPubKey(keyHolder);
    dem.vchHolderSig = std::vector<unsigned char>(70, 0x30);
    dem.vUnits.push_back(1000);

    auto MakeDemandTx = [](const NoteDemand& d) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_DEMAND;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << d;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        // The notes are RE-ISSUED: one dust P2PKH note output per unit entry
        for (size_t i = 0; i < d.vUnits.size(); i++)
            mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(d.vchHolderPubKey)));
        return mtx;
    };

    CValidationState state;
    BOOST_CHECK(CheckNoteTransactionShape(CTransaction(MakeDemandTx(dem)), state));

    // Zero / empty unit vectors rejected
    {
        NoteDemand bad = dem;
        bad.vUnits.clear();
        CValidationState s;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeDemandTx(bad)), s));
        NoteDemand bad2 = dem;
        bad2.vUnits[0] = 0;
        CValidationState s2;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeDemandTx(bad2)), s2));
    }
    // Bad holder key / sig
    {
        NoteDemand bad = dem;
        bad.vchHolderPubKey = std::vector<unsigned char>(20, 0x02);
        CValidationState s;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeDemandTx(bad)), s));
        NoteDemand bad2 = dem;
        bad2.vchHolderSig.clear();
        CValidationState s2;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeDemandTx(bad2)), s2));
    }
    // The demand digest is its own domain (Stage 0 C1: over the whole transaction).
    const CTransaction txd(MakeDemandTx(dem));
    BOOST_CHECK(NoteDemandSigHash(txd) != NoteRedeemSigHash(txd));
}

BOOST_AUTO_TEST_CASE(claim_sats_entitlement_math)
{
    // The failed-house claim (Gram notes, R2-int-10): min(floor(U*pot/snapshot), floor((U-gold)*price/1000)), 128-bit,
    // capped at MAX_MONEY. Replaces the tests of the retired NoteClaimEntitlement/DepositClaimEntitlement (FB-2a), which
    // were this with price 1000 (1 sat a mg) and no gold.
    const uint64_t P1 = 1000;
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(500, 0, 100, 1000, P1), 50);      // under-collateralised: 10% recovery
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(1000, 0, 100, 1000, P1), 100);    // the whole snapshot takes the pot
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(1, 0, 100, 1000, P1), 0);         // floor dust
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(500, 0, 5000, 1000, P1), 500);    // over-collateralised: par caps it
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(250, 0, 1000, 1000, P1), 250);    // exactly collateralised
    // Degenerate inputs
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(0, 0, 100, 1000, P1), 0);
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(500, 0, 0, 1000, P1), 0);
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(500, 0, 100, 0, P1), 0);
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(500, 0, 100, 1000, 0), 0);        // no snapshot price
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(500, 500, 100, 1000, P1), 0);     // gold covers it all
    // The price: par is (U - gold) x price / 1000 sats
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(1000, 0, 1000000, 1000, 250000), 250000);     // 250 sat/mg, pot ample
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(1000, 400, 1000000, 1000, 250000), 150000);   // 400 mg in gold first
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(1000, 0, 100000, 1000, 250000), 100000);      // pro-rata binds
    // The uint64-overflow regime: U and pot near the money bounds (product ~2^104), and the MAX_MONEY cap
    const uint64_t bigU = (uint64_t)MAX_MONEY * 3;
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(bigU, 0, MAX_MONEY, bigU, P1), MAX_MONEY);
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(bigU / 3, 0, MAX_MONEY, bigU, P1), MAX_MONEY / 3);
    BOOST_CHECK_EQUAL(ClaimSatsEntitlement(bigU, 0, MAX_MONEY, bigU, 1000000), MAX_MONEY);
    // Split claims never take more than the pot (floor rounds down)
    {
        CAmount paid = 0;
        for (int i = 0; i < 10; i++)
            paid += ClaimSatsEntitlement(100, 0, 999, 1000, P1);
        BOOST_CHECK(paid <= 999);
    }
    // The junior tranche: deposits claim against pot - SeniorSatsReserved(notes), so they never reach the notes' par.
    // pot 1e6, notes 800000 mg at 1 sat/mg -> 800000 reserved; a 500000-principal deposit gets the 200000 left.
    {
        const CAmount pot = 1000000;
        const CAmount reserved = SeniorSatsReserved(800000, 0, pot, P1);
        BOOST_CHECK_EQUAL(reserved, 800000);
        const CAmount take = ClaimSatsEntitlement(500000, 0, pot - reserved, 500000, P1);
        BOOST_CHECK_EQUAL(take, 200000);
        BOOST_CHECK(pot - take >= reserved);
        BOOST_CHECK_EQUAL(SeniorSatsReserved(800000, 0, 500000, P1), 500000);   // capped at the pot
        BOOST_CHECK_EQUAL(SeniorSatsReserved(1001, 0, pot, P1 + 1), 1003);     // rounds up: ceil(1001 x 1001 / 1000)
        BOOST_CHECK_EQUAL(SeniorSatsReserved(800, 800, pot, P1), 0);           // gold covers the senior claim
    }
}

BOOST_AUTO_TEST_CASE(note_residual_share_math)
{
    // Pro-rata residual by pledge; sum over partners never exceeds residual
    BOOST_CHECK_EQUAL(HouseResidualShare(100, 900, 300), 300);
    BOOST_CHECK_EQUAL(HouseResidualShare(200, 900, 300), 600);
    BOOST_CHECK_EQUAL(HouseResidualShare(0, 900, 300), 0);
    BOOST_CHECK_EQUAL(HouseResidualShare(100, 0, 300), 0);
    BOOST_CHECK_EQUAL(HouseResidualShare(100, 900, 0), 0);
    {
        // Floor rounding: three equal partners, indivisible residual
        const CAmount r = HouseResidualShare(100, 1000, 300);
        BOOST_CHECK_EQUAL(r, 333);
        BOOST_CHECK(3 * r <= 1000);   // dust swept by the last settler, not minted
    }
    // 128-bit regime
    BOOST_CHECK_EQUAL(HouseResidualShare(MAX_MONEY, MAX_MONEY, MAX_MONEY), MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(note_claim_sig_binding)
{
    // Claim digest: a distinct domain from redeem, over the whole transaction (Stage 0 C1).
    CMutableTransaction t;
    t.nVersion = TRANSACTION_NOTE_VERSION;
    t.nNoteOp = NOTE_OP_CLAIM;
    t.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    t.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    const CTransaction tx(t);
    BOOST_CHECK(NoteClaimSigHash(tx) != NoteRedeemSigHash(tx));
    t.vout[0].nValue++;
    BOOST_CHECK(NoteClaimSigHash(CTransaction(t)) != NoteClaimSigHash(tx));
}

// A shape-valid CLAIM tx around the given payload
static CMutableTransaction MakeClaimTx(const NoteClaim& claim)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_CLAIM;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << claim;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(5000, CScript() << OP_TRUE)); // payout placeholder
    return mtx;
}

BOOST_AUTO_TEST_CASE(note_claim_shape)
{
    CKey keyHolder;
    NoteClaim claim;
    claim.nHouseID = 1;
    claim.fEscrowChange = 0;
    claim.vchHolderPubKey = FreshPubKey(keyHolder);
    claim.vchHolderSig = std::vector<unsigned char>(70, 0x30);

    CValidationState state;
    BOOST_CHECK(CheckNoteTransactionShape(CTransaction(MakeClaimTx(claim)), state));

    // Escrow-change flag demands vout[1]
    {
        NoteClaim c2 = claim;
        c2.fEscrowChange = 1;
        CValidationState s;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeClaimTx(c2)), s));
        CMutableTransaction mtx = MakeClaimTx(c2);
        mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
        CValidationState s2;
        BOOST_CHECK(CheckNoteTransactionShape(CTransaction(mtx), s2));
    }
    // Bad flag value / bad pubkey / bad sig sizes
    {
        NoteClaim bad = claim;
        bad.fEscrowChange = 2;
        CValidationState s;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeClaimTx(bad)), s));
        NoteClaim bad2 = claim;
        bad2.vchHolderPubKey = std::vector<unsigned char>(20, 0x02);
        CValidationState s2;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeClaimTx(bad2)), s2));
        NoteClaim bad3 = claim;
        bad3.vchHolderSig = std::vector<unsigned char>(81, 0x30);
        CValidationState s3;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(MakeClaimTx(bad3)), s3));
    }
    // Out-of-range op codes rejected; LOCK with a CLAIM payload fails its decode
    {
        CMutableTransaction mtx = MakeClaimTx(claim);
        mtx.nNoteOp = NOTE_OP_CLAIM + 1;
        CValidationState s;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), s));
        mtx.nNoteOp = NOTE_OP_LOCK;
        CValidationState s2;
        BOOST_CHECK(!CheckNoteTransactionShape(CTransaction(mtx), s2));
    }
}

// ---------------------------------------------------------------------------
// R-i6: negative direction of the 3.5 note-op status guards. These fire before
// any ECDSA in their branch, so a placeholder holder/approver signature reaches
// the guard; the exact reject reason is asserted (no false pass via an earlier
// guard). Post-signature floors (interest-short, brassage-*) need a real holder
// signature over the exact sighash and are covered by the integration gates.
// ---------------------------------------------------------------------------

namespace {
// A minimal effectively-DEFERRED house (option clause invoked, within window).
static CHouse MakeDeferredHouse(uint32_t nHouseID)
{
    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "noteguard";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1500;
    house.amountLastAttestReserves = 100 * COIN;
    house.nDeferInvokedHeight = 1500;   // effectively DEFERRED within the window
    return house;
}
} // namespace

BOOST_AUTO_TEST_CASE(note_claim_waits_for_collection_and_refuses_closed)
{
    // v0.2.28 (FAILED_HOUSE_DESIGN.md B, E): an insolvent house's holders are paid once its loan book has run off (or
    // the collection window has passed), and never once it is CLOSEd. The gates fire before the holder signature.
    CHouse house = MakeDeferredHouse(1);
    house.nDeferInvokedHeight = 0;
    house.status = HOUSE_STATUS_INSOLVENT;
    house.nInsolventHeight = 1500;
    HousePartner pt;
    pt.vchPubKey = std::vector<unsigned char>(33, 0x02);
    pt.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(pt);

    NoteClaim c;
    c.nHouseID = 1;
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    c.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    c.vchHolderSig = std::vector<unsigned char>(70, 0x30);
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_CLAIM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(100, NoteScriptForPubKey(c.vchHolderPubKey)));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << c;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());

    auto reason = [&](const CHouse& h) {
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 1) { out = h; return true; } return false; };
        auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
        auto fnNoBlock = [](uint32_t, uint256&) { return false; };
        CValidationState state; CHouse houseOut; bool fChanged = false;
        CheckNoteOperation(CTransaction(mtx), state, 1600, 100, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock, houseOut, fChanged);
        return state.GetRejectReason();
    };
    CHouse hCollecting = house;
    hCollecting.nLoanBookFace = 5000;                  // a bill still in the book, inside the window
    BOOST_CHECK_EQUAL(reason(hCollecting), "bad-note-claim-collecting");
    BOOST_CHECK_EQUAL(reason(house), "bad-note-claim-sig");   // book empty: the gates open, the junk sig fails
    CHouse hClosed = house;
    hClosed.vPartner[0].status = HOUSE_PARTNER_SETTLED;
    BOOST_CHECK_EQUAL(reason(hClosed), "bad-note-claim-house-closed");
}

BOOST_AUTO_TEST_CASE(note_mint_rejected_when_house_not_open)
{
    // A suspended (Deferred) house may not issue: no new liabilities while it has
    // stopped paying the old ones.
    CHouse house = MakeDeferredHouse(1);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1600), HOUSE_STATUS_DEFERRED);
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 1) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };

    auto fnNoBlock = [](uint32_t, uint256&) { return false; };
    CMutableTransaction mtx = MakeMintTx(1, 100);
    CValidationState state; CHouse houseOut; bool fChanged = false;
    BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1600, 0, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock, houseOut, fChanged));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-mint-house-not-open");
}

BOOST_AUTO_TEST_CASE(note_redeem_rejected_while_deferred)
{
    // Par redemption of UNDEMANDED notes stops while the option clause is
    // invoked - the holder queues (NOTE_OP_DEMAND) instead. This is the
    // flagship suspension guard; assert the CONSENSUS reason, not the wallet
    // mirror. v0.2.18: the guard reads the input coins' demand tag (a demanded
    // note MAY be paid while suspended), so it fires after the holder
    // signature - the redeem here is fully signed.
    CHouse house = MakeDeferredHouse(1);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1600), HOUSE_STATUS_DEFERRED);
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 1) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };

    NoteRedeem redeem;
    redeem.nHouseID = 1;
    redeem.fBrassage = 0;
    CKey keyHolder; keyHolder.MakeNewKey(true);
    CPubKey pub = keyHolder.GetPubKey();
    redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(100, NoteScriptForPubKey(redeem.vchHolderPubKey)));
    { CDataStream sC1(SER_NETWORK, PROTOCOL_VERSION); sC1 << redeem; mtx.vchNotePayload.assign(sC1.begin(), sC1.end()); }   // Stage 0 C1
    BOOST_REQUIRE(keyHolder.Sign(NoteRedeemSigHash(CTransaction(mtx)), redeem.vchHolderSig));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());

    auto fnNoBlock = [](uint32_t, uint256&) { return false; };
    CValidationState state; CHouse houseOut; bool fChanged = false;
    BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1600, 100, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock, houseOut, fChanged));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-redeem-deferred");
}

BOOST_AUTO_TEST_CASE(uf4_1_state_verdicts_score_zero_in_the_mempool)
{
    // UF4-1 (testing's ultra on review-fixed s4, security Low): a verdict that reads chain state (the house record, its
    // status, the height) can differ between an honest sender's tip and ours one block apart. The same refusal on
    // both paths; DoS 0 on the mempool path (fMempool), 100 in a block.
    const CHouse deferred = MakeDeferredHouse(1);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(deferred, 1600), HOUSE_STATUS_DEFERRED);
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    auto fnNoBlock = [](uint32_t, uint256&) { return false; };
    auto check = [&](const CMutableTransaction& mtx, const CHouse* pHouse, uint64_t nUnitsIn, const std::string& strReason) {
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (pHouse && id == 1) { out = *pHouse; return true; } return false; };
        for (bool fMempool : {false, true}) {
            CValidationState state; CHouse houseOut; bool fChanged = false;
            BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1600, nUnitsIn, fnGetHouse, fnNoCoin, fnNoCoin,
                                            fnNoBlock, houseOut, fChanged, fMempool));
            int nDoS = -1;
            BOOST_CHECK(state.IsInvalid(nDoS));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), strReason);
            BOOST_CHECK_MESSAGE(nDoS == (fMempool ? 0 : 100), strReason << " fMempool=" << fMempool << " nDoS=" << nDoS);
        }
    };

    // A MINT on a house this node hasn't connected yet (its creating block is one ahead).
    check(MakeMintTx(1, 100), nullptr, 0, "bad-note-unknown-house");
    // A MINT on a house that suspended in the block we have and the sender doesn't.
    check(MakeMintTx(1, 100), &deferred, 0, "bad-note-mint-house-not-open");

    // A signed REDEEM of an undemanded note while the house is suspended.
    {
        NoteRedeem redeem;
        redeem.nHouseID = 1;
        redeem.fBrassage = 0;
        CKey keyHolder; keyHolder.MakeNewKey(true);
        const CPubKey pub = keyHolder.GetPubKey();
        redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_REDEEM;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(100, NoteScriptForPubKey(redeem.vchHolderPubKey)));
        { CDataStream sC1(SER_NETWORK, PROTOCOL_VERSION); sC1 << redeem; mtx.vchNotePayload.assign(sC1.begin(), sC1.end()); }   // Stage 0 C1
        BOOST_REQUIRE(keyHolder.Sign(NoteRedeemSigHash(CTransaction(mtx)), redeem.vchHolderSig));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        check(mtx, &deferred, 100, "bad-note-redeem-deferred");
    }

    // A CLAIM on a house that isn't insolvent at our tip.
    {
        NoteClaim c;
        c.nHouseID = 1;
        CKey key; key.MakeNewKey(true);
        const CPubKey pub = key.GetPubKey();
        c.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
        c.vchHolderSig = std::vector<unsigned char>(70, 0x30);
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_CLAIM;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(100, NoteScriptForPubKey(c.vchHolderPubKey)));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << c;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        check(mtx, &deferred, 100, "bad-note-claim-not-insolvent");
    }
}

BOOST_AUTO_TEST_CASE(uf4_1_guard_rescores_only_an_active_mempool_refusal)
{
    // MempoolRefusalScoresZero: an active guard turns a refusal into the same refusal at DoS 0, keeping the code,
    // reason, corruption flag and debug message; it leaves a pass, a run-time error, the block path and a state that
    // was already invalid on entry as they were.
    auto refuse = [](CValidationState& state, bool fActive, bool fCorrupt) {
        const MempoolRefusalScoresZero guard(state, fActive);
        return state.DoS(100, false, REJECT_INVALID, "bad-test-verdict", fCorrupt, "debug detail");
    };
    int nDoS = -1;
    {
        CValidationState state;
        refuse(state, true, true);
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 0);
        BOOST_CHECK_EQUAL(state.GetRejectCode(), (unsigned int)REJECT_INVALID);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-test-verdict");
        BOOST_CHECK(state.CorruptionPossible());
        BOOST_CHECK_EQUAL(state.GetDebugMessage(), "debug detail");
    }
    {
        CValidationState state;   // the block path
        refuse(state, false, false);
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 100);
        BOOST_CHECK(!state.CorruptionPossible());
    }
    {
        CValidationState state;   // already invalid on entry: the caller's score stands
        state.DoS(100, false, REJECT_INVALID, "bad-earlier");
        refuse(state, true, false);
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 200);
    }
    {
        CValidationState state;   // a run-time error stays an error
        {
            const MempoolRefusalScoresZero guard(state, true);
            state.Error("disk");
        }
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "disk");
    }
    {
        CValidationState state;   // a pass stays valid
        { const MempoolRefusalScoresZero guard(state, true); }
        BOOST_CHECK(state.IsValid());
    }
}

BOOST_AUTO_TEST_CASE(note_mint_rho_liveness_gate)
{
    // Gram-notes release: the till cap is the house's counted gold till (the test fixture emulates it from the
    // attested figure), exact on-chain, so the R-i7 liveness proof and its as-of vectors are gone. What stays: a
    // well-capitalised house with too little till can't mint.
    CHouse house;
    house.nHouseID = 5;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;      // lambda = 3.0
    house.nThresholdM = 1;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;              // fresh cadence -> effective Open
    house.amountLastAttestReserves = 100 * COIN; // ample PUBLISHED reserve, so the
                                                 // under-reserved case below isolates
                                                 // the LIVENESS half: proven = 0.
    HousePartner p;
    p.vchPubKey = MintApproverPub();             // Stage 0 rule A: MakeMintTx's approver
    p.amountPledge = 100 * COIN;                 // ample capital cap
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);

    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1000), HOUSE_STATUS_OPEN);

    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 5) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    auto fnBlock = [](uint32_t, uint256& h) { h = uint256S("beef"); return true; };

    // A till of 1 sat-equivalent (emulated 0 mg) can't back even 100 units.
    house.amountLastAttestReserves = 1;
    {
        CMutableTransaction mtx = MakeMintTx(5, 100, /*nAsOfHeight=*/999);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1000, 0, fnGetHouse, fnNoCoin, fnNoCoin, fnBlock, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-mint-under-reserved");
    }
}

// ---------------------------------------------------------------------------
// DR-2: the deferral-interest window is capped at the episode END (the recovery
// height), and the permanent brassage exemption on demanded notes is retired.
// These need a REAL holder signature (both floors are post-signature), so the
// tx is built outputs-first, signed over the exact sighash, then dispatched.
// ---------------------------------------------------------------------------

namespace {
// A signed REDEEM of nUnits demanded-at-D notes, paying amountPayout to the
// holder (single output; fBrassage=0). fnGetCoin serves one demanded note coin.
static CMutableTransaction MakeDemandedRedeemTx(uint32_t nHouseID, uint64_t nUnits,
                                                const CKey& keyHolder, CAmount amountPayout)
{
    const CPubKey pub = keyHolder.GetPubKey();
    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = 0;
    redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("d0d0"), 0)));
    mtx.vout.push_back(CTxOut(amountPayout, NoteScriptForPubKey(redeem.vchHolderPubKey)));

    { CDataStream sC1(SER_NETWORK, PROTOCOL_VERSION); sC1 << redeem; mtx.vchNotePayload.assign(sC1.begin(), sC1.end()); }   // Stage 0 C1
    keyHolder.Sign(NoteRedeemSigHash(CTransaction(mtx)), redeem.vchHolderSig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}
} // namespace

BOOST_AUTO_TEST_CASE(note_redeem_interest_reopen_window)
{
    // v0.2.18 Q8 (replaces the DR-2 "capped at episode end" rule): demand at
    // D=10000, reopen at E=15256 (0.1yr). Paid within W of E while open ->
    // interest D..E (10%/yr x 0.1yr on 1M = 10,000 sats). Paid later -> it
    // accrued until paid (the old cap would have frozen it at E for ever).
    const uint64_t U = 1000000;
    const uint32_t D = 10000, E = 15256;
    const uint32_t W = Params().GetConsensus().nDemandWindow;

    CHouse house;
    house.nHouseID = 7;
    house.houseID = uint256S("cafe");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "dr2cap";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nMintedUnits = 2000000;
    house.amountLastAttestReserves = 2000000;         // ratio 10000 bps -> no spread
    house.nDeferEndedHeight = E;                      // the reopen stamp

    CKey keyHolder; keyHolder.MakeNewKey(true);
    const CPubKey pubHolder = keyHolder.GetPubKey();   // named once (two GetPubKey() temporaries = garbage range)
    const std::vector<unsigned char> vchHolder(pubHolder.begin(), pubHolder.end());
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 7) { out = house; return true; } return false; };
    auto fnDemandedCoin = [&](const COutPoint&, Coin& coin) {
        coin = Coin(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchHolder)), (int)D, false, false, false, uint256());
        coin.SetNote(7, U, D);                        // demanded at D
        return true;
    };
    auto fnNoBlock = [](uint32_t, uint256&) { return false; };

    const CAmount amountCapped = FlatInterest(U, E - D);
    BOOST_REQUIRE_EQUAL(amountCapped, 10000);

    // In time (H = E + W): the floor is principal + interest to E, exactly.
    {
        const int H = (int)(E + W);
        house.nLastAttestHeight = H - 10;             // fresh cadence
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
        CMutableTransaction mtx = MakeDemandedRedeemTx(7, U, keyHolder, (CAmount)U + amountCapped);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(CheckNoteOperation(CTransaction(mtx), state, H, U, fnGetHouse, fnDemandedCoin, fnDemandedCoin, fnNoBlock, houseOut, fChanged));
        BOOST_CHECK(fChanged);
        BOOST_CHECK_EQUAL(houseOut.nMintedUnits, house.nMintedUnits - U);
        CMutableTransaction mtx2 = MakeDemandedRedeemTx(7, U, keyHolder, (CAmount)U + amountCapped - 1);
        CValidationState state2; CHouse houseOut2; bool fChanged2 = false;
        BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx2), state2, H, U, fnGetHouse, fnDemandedCoin, fnDemandedCoin, fnNoBlock, houseOut2, fChanged2));
        BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-note-redeem-interest-short");
    }
    // Long after (H = 60000): this is a PLAIN demand, so (Q8 follow-up "b")
    // the clock stopped at E + W: the floor is interest D..E+W exactly - more
    // than the in-time amount, and nothing for the blocks after E + W.
    {
        const int H = 60000;
        house.nLastAttestHeight = H - 10;
        const CAmount amountCap = FlatInterest(U, E + W - D);
        BOOST_REQUIRE(amountCap > amountCapped);
        BOOST_REQUIRE(FlatInterest(U, (uint32_t)H - D) > amountCap);
        CMutableTransaction mtx = MakeDemandedRedeemTx(7, U, keyHolder, (CAmount)U + amountCap);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(CheckNoteOperation(CTransaction(mtx), state, H, U, fnGetHouse, fnDemandedCoin, fnDemandedCoin, fnNoBlock, houseOut, fChanged));
        CMutableTransaction mtx2 = MakeDemandedRedeemTx(7, U, keyHolder, (CAmount)U + amountCap - 1);
        CValidationState state2; CHouse houseOut2; bool fChanged2 = false;
        BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx2), state2, H, U, fnGetHouse, fnDemandedCoin, fnDemandedCoin, fnNoBlock, houseOut2, fChanged2));
        BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-note-redeem-interest-short");
    }
}

BOOST_AUTO_TEST_CASE(note_demand_accrual_window_modes)
{
    // v0.2.18 Q8 follow-up "a+b" (D-2026-10-02-1): the accrual window for each
    // kind of demand tag. D = demand, E = latest reopen, W = demand window.
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint32_t D = 10000, E = 15000;
    const uint32_t tagPlain = NoteDemandTag(D, NOTE_DEMAND_MODE_PLAIN);
    const uint32_t tagB3 = NoteDemandTag(D, NOTE_DEMAND_MODE_PREAUTH);
    const uint32_t tagQueue = NoteDemandTag(D, NOTE_DEMAND_MODE_PREAUTH_QUEUE);

    // The tag bits: the height reads back masked; the queue marker is distinct.
    BOOST_CHECK_EQUAL(NoteDemandHeightOf(tagQueue), D);
    BOOST_CHECK(NoteDemandIsPreAuth(tagQueue) && NoteDemandIsQueue(tagQueue));
    BOOST_CHECK(NoteDemandIsPreAuth(tagB3) && !NoteDemandIsQueue(tagB3));
    BOOST_CHECK(!NoteDemandIsPreAuth(tagPlain) && !NoteDemandIsQueue(tagPlain));
    BOOST_CHECK(NoteDemandAccruesFromDemand(tagPlain));
    BOOST_CHECK(NoteDemandAccruesFromDemand(tagQueue));
    BOOST_CHECK(!NoteDemandAccruesFromDemand(tagB3));
    BOOST_CHECK_EQUAL(NoteDemandHeightOf(tagQueue | NOTE_DEMAND_PROTESTED_BIT), D);

    CHouse open;
    open.nDeferEndedHeight = E;                        // reopened at E, open now
    CHouse never;                                      // never suspended
    CHouse again = open;
    again.nDeferInvokedHeight = E + 2 * W;             // suspended again later

    auto win = [&](const CHouse& h, uint32_t tag, uint32_t H) {
        uint32_t s = 0, e = 0;
        NoteDemandAccrualWindow(h, tag, H, W, s, e);
        return std::make_pair(s, e);
    };
    // Paid within W of the reopen: every kind stops at E (queue kinds from D,
    // the B3 formal demand from its lapse D + W).
    BOOST_CHECK(win(open, tagPlain, E + W) == std::make_pair(D, E));
    BOOST_CHECK(win(open, tagQueue, E + W) == std::make_pair(D, E));
    BOOST_CHECK(win(open, tagB3, E + W) == std::make_pair(D + W, E));
    // Paid later with the house still open: queue kinds stop at E + W ("b";
    // also closes the late-upgrade side door), the B3 formal demand runs on.
    BOOST_CHECK(win(open, tagPlain, E + 5 * W) == std::make_pair(D, E + W));
    BOOST_CHECK(win(open, tagQueue, E + 5 * W) == std::make_pair(D, E + W));
    BOOST_CHECK(win(open, tagB3, E + 5 * W) == std::make_pair(D + W, E + 5 * W));
    // Paid while suspended again: accrues to payment (no freezing a clock by
    // reopening briefly).
    BOOST_CHECK(win(again, tagQueue, E + 3 * W) == std::make_pair(D, E + 3 * W));
    BOOST_CHECK(win(again, tagPlain, E + 3 * W) == std::make_pair(D, E + 3 * W));
    // No reopen since the demand: to payment.
    BOOST_CHECK(win(never, tagQueue, D + 100) == std::make_pair(D, D + 100));
    BOOST_CHECK(win(never, tagB3, D + 3 * W) == std::make_pair(D + W, D + 3 * W));

    // The interest itself (review fix): a queue demand paid during a LATER
    // suspension that began after the holder's week (I = E + 2W > E + W) earns
    // D..E+W plus I..payment - not the open gap between them.
    const uint64_t U = 1000000;
    const Consensus::Params& cp = Params().GetConsensus();
    const uint32_t P = E + 3 * W;
    for (uint32_t tag : {tagQueue, tagPlain}) {
        BOOST_CHECK_EQUAL(NoteDemandInterest(again, tag, U, P, cp),
                          FlatInterest(U, E + W - D) + FlatInterest(U, P - (E + 2 * W)));
        BOOST_CHECK(NoteDemandInterest(again, tag, U, P, cp) < FlatInterest(U, P - D));
    }
    // Re-suspended INSIDE the week: continuous D..payment (no freezing a clock).
    CHouse quick = open;
    quick.nDeferInvokedHeight = E + W / 2;
    BOOST_CHECK_EQUAL(NoteDemandInterest(quick, tagQueue, U, P, cp), FlatInterest(U, P - D));
    // A B3 formal demand is not a queue demand: unchanged, to payment.
    BOOST_CHECK_EQUAL(NoteDemandInterest(again, tagB3, U, P, cp), FlatInterest(U, P - (D + W)));
}

BOOST_AUTO_TEST_CASE(note_redeem_demanded_note_pays_brassage)
{
    // DR-2: the demand tag no longer waives the spread. House recovered at E,
    // then hit a NEW below-floor stress; a demanded-at-D holder exiting through
    // that new race owes the spread like everyone else (pre-DR-2: exempt
    // forever). fBrassage=0 with a spread owed -> the exact brassage reject.
    const uint64_t U = 1000000;
    const uint32_t D = 10000, E = 15256;
    const int H = 60000;

    CHouse house;
    house.nHouseID = 8;
    house.houseID = uint256S("beadcafe");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "dr2spread";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nMintedUnits = 1000000;
    house.nLastAttestHeight = H - 10;                 // fresh cadence
    house.amountLastAttestReserves = 50000;           // ratio 500 bps: theta < 500 < rho -> spread owed
    house.nStressSinceHeight = H - 5;                 // the new, post-recovery stress
    house.nDeferEndedHeight = E;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
    BOOST_REQUIRE(HouseBrassageBps(house) > 0);

    CKey keyHolder; keyHolder.MakeNewKey(true);
    const CPubKey pubHolder = keyHolder.GetPubKey();   // named once (two GetPubKey() temporaries = garbage range)
    const std::vector<unsigned char> vchHolder(pubHolder.begin(), pubHolder.end());
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 8) { out = house; return true; } return false; };
    auto fnDemandedCoin = [&](const COutPoint&, Coin& coin) {
        coin = Coin(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchHolder)), (int)D, false, false, false, uint256());
        coin.SetNote(8, U, D);
        return true;
    };
    auto fnNoBlock = [](uint32_t, uint256&) { return false; };

    // Clear the interest floor (paid long after the reopen: accrues D..H) so
    // the brassage guard is what fires.
    const CAmount amountPayout = (CAmount)U + FlatInterest(U, (uint32_t)H - D);
    CMutableTransaction mtx = MakeDemandedRedeemTx(8, U, keyHolder, amountPayout);
    CValidationState state; CHouse houseOut; bool fChanged = false;
    BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, H, U, fnGetHouse, fnDemandedCoin, fnDemandedCoin, fnNoBlock, houseOut, fChanged));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-redeem-brassage-missing");
}

// v0.2.19: the shared payload-pure note tagger (ApplyNoteCoinTags). One tx per
// op that tags outputs, with a payload but no signatures (tagging reads only the
// payload).
template <typename T>
static CMutableTransaction MakeNoteOpTx(uint8_t nOp, const T& payload, size_t nOuts)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = nOp;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("02"), nOp)));
    for (size_t i = 0; i < nOuts; i++)
        mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE + i, CScript() << OP_TRUE));
    return mtx;
}

static std::vector<CMutableTransaction> TaggerVectors()
{
    std::vector<CMutableTransaction> v;
    NoteMint m; m.nHouseID = 7; m.vUnits = {100, 200};
    v.push_back(MakeNoteOpTx(NOTE_OP_MINT, m, 3));                  // vout[2] = change
    NoteTransfer x; x.nHouseID = 7; x.vUnits = {300}; x.nDemandHeight = 77;
    v.push_back(MakeNoteOpTx(NOTE_OP_TRANSFER, x, 2));
    NoteDemand d; d.nHouseID = 7; d.vUnits = {400, 500}; d.fPreAuth = NOTE_DEMAND_MODE_PREAUTH;
    v.push_back(MakeNoteOpTx(NOTE_OP_DEMAND, d, 3));                // fresh: stamp = connect height
    NoteDemand u; u.nHouseID = 7; u.vUnits = {600}; u.fPreAuth = NOTE_DEMAND_MODE_PREAUTH_QUEUE; u.nPriorDemandHeight = 60;
    v.push_back(MakeNoteOpTx(NOTE_OP_DEMAND, u, 2));                // upgrade: stamp = prior height
    NoteProtest pro; pro.nHouseID = 7; pro.vUnits = {700}; pro.nDemandTag = 77 | NOTE_DEMAND_PROTESTED_BIT;
    v.push_back(MakeNoteOpTx(NOTE_OP_PROTEST, pro, 2));
    NoteRedeem r; r.nHouseID = 7; r.fBrassage = 1;
    v.push_back(MakeNoteOpTx(NOTE_OP_REDEEM, r, 3));                // vout[1] = brassage escrow
    NoteClaim c; c.nHouseID = 7; c.fEscrowChange = 1;
    v.push_back(MakeNoteOpTx(NOTE_OP_CLAIM, c, 3));                 // vout[1] = escrow change
    NoteLock lk; lk.nHouseID = 7; lk.nUnits = 50; lk.vChangeUnits = {800};
    v.push_back(MakeNoteOpTx(NOTE_OP_LOCK, lk, 2));                 // vout[0] = change note, vout[1] = plain
    NoteUnlock ul; ul.nHouseID = 7; ul.vUnits = {900, 950};
    v.push_back(MakeNoteOpTx(NOTE_OP_UNLOCK, ul, 3));               // vout[2] = plain change
    return v;
}

static void CheckSameTag(const Coin& a, const Coin& b)
{
    BOOST_CHECK_EQUAL(a.fNote, b.fNote);
    BOOST_CHECK_EQUAL(a.fHouseEscrow, b.fHouseEscrow);
    BOOST_CHECK_EQUAL(a.nHouseID, b.nHouseID);
    BOOST_CHECK_EQUAL(a.nNoteUnits, b.nNoteUnits);
    BOOST_CHECK_EQUAL(a.nDemandHeight, b.nDemandHeight);
}

BOOST_AUTO_TEST_CASE(note_coin_tagger_matches_addcoins)
{
    const int H = 500;
    for (const CMutableTransaction& mtx : TaggerVectors()) {
        const CTransaction tx(mtx);
        CCoinsView dummy;
        CCoinsViewCache cache(&dummy);
        AddCoins(cache, tx, H);
        for (uint32_t n = 0; n < tx.vout.size(); n++) {
            Coin want(tx.vout[n], H, false, false, false, uint256());
            ApplyNoteCoinTags(tx, n, want, true, H);
            CheckSameTag(cache.AccessCoin(COutPoint(tx.GetHash(), n)), want);
        }
    }
    // The values themselves, connected at H.
    const std::vector<CMutableTransaction> v = TaggerVectors();
    auto tag = [&](size_t i, uint32_t n) {
        Coin coin(v[i].vout[n], H, false, false, false, uint256());
        ApplyNoteCoinTags(CTransaction(v[i]), n, coin, true, H);
        return coin;
    };
    BOOST_CHECK(tag(0, 1).fNote && tag(0, 1).nNoteUnits == 200 && tag(0, 1).nDemandHeight == 0);
    BOOST_CHECK(!tag(0, 2).fNote);
    BOOST_CHECK_EQUAL(tag(1, 0).nDemandHeight, 77U);
    BOOST_CHECK_EQUAL(tag(2, 1).nDemandHeight, NoteDemandTag(H, NOTE_DEMAND_MODE_PREAUTH));
    BOOST_CHECK(!tag(2, 2).fNote);
    BOOST_CHECK_EQUAL(tag(3, 0).nDemandHeight, NoteDemandTag(60, NOTE_DEMAND_MODE_PREAUTH_QUEUE));
    BOOST_CHECK_EQUAL(tag(4, 0).nDemandHeight, 77U | NOTE_DEMAND_PROTESTED_BIT);
    BOOST_CHECK(!tag(5, 0).fNote && !tag(5, 0).fHouseEscrow);
    BOOST_CHECK(tag(5, 1).fHouseEscrow && tag(5, 1).nHouseID == 7);
    BOOST_CHECK(tag(6, 1).fHouseEscrow && tag(6, 1).nHouseID == 7);
    // v0.2.20: a lock's change and an unlock's notes are plain undemanded notes
    BOOST_CHECK(tag(7, 0).fNote && tag(7, 0).nNoteUnits == 800 && tag(7, 0).nDemandHeight == 0);
    BOOST_CHECK(!tag(7, 1).fNote);
    BOOST_CHECK(tag(8, 1).fNote && tag(8, 1).nNoteUnits == 950 && tag(8, 1).nDemandHeight == 0);
    BOOST_CHECK(!tag(8, 2).fNote);
}

BOOST_AUTO_TEST_CASE(note_mempool_view_tags)
{
    // C6 protest-mempool-tag-gap: an unconfirmed PROTEST's notes were untagged in
    // the mempool view, so a plain spend passed mempool acceptance and failed
    // ConnectBlock. The view now tags exactly as the shared tagger does unconfirmed.
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    const std::vector<CMutableTransaction> v = TaggerVectors();
    for (const CMutableTransaction& mtx : v)
        pool.addUnchecked(mtx.GetHash(), entry.FromTx(mtx));
    CCoinsView dummy;
    CCoinsViewCache cache(&dummy);
    CCoinsViewMemPool view(&cache, pool);
    for (const CMutableTransaction& mtx : v) {
        const CTransaction tx(mtx);
        for (uint32_t n = 0; n < tx.vout.size(); n++) {
            Coin got, want(tx.vout[n], MEMPOOL_HEIGHT, false, false, false, uint256());
            BOOST_CHECK(view.GetCoin(COutPoint(tx.GetHash(), n), got));
            ApplyNoteCoinTags(tx, n, want, false, 0);
            CheckSameTag(got, want);
        }
    }
    Coin coin;
    BOOST_CHECK(view.GetCoin(COutPoint(v[4].GetHash(), 0), coin));       // PROTEST: tagged, real tag
    BOOST_CHECK(coin.fNote && coin.nHouseID == 7 && coin.nDemandHeight == (77U | NOTE_DEMAND_PROTESTED_BIT));
    BOOST_CHECK(view.GetCoin(COutPoint(v[2].GetHash(), 0), coin));       // fresh DEMAND: stamp unknown, 0
    BOOST_CHECK(coin.fNote && coin.nDemandHeight == 0);
    BOOST_CHECK(view.GetCoin(COutPoint(v[3].GetHash(), 0), coin));       // upgrade: prior height is in the payload
    BOOST_CHECK_EQUAL(coin.nDemandHeight, NoteDemandTag(60, NOTE_DEMAND_MODE_PREAUTH_QUEUE));
    BOOST_CHECK(view.GetCoin(COutPoint(v[5].GetHash(), 1), coin));       // escrow: house id 0, nothing chains
    BOOST_CHECK(coin.fHouseEscrow && coin.nHouseID == 0);
}


// ---------------------------------------------------------------------------
// v0.2.20 Chaumian token records (D-2026-10-08-1, docs-local/MINT_RECORD_SPEC.md):
// NOTE_OP_LOCK (the mint record) and NOTE_OP_UNLOCK (the burn record).
// ---------------------------------------------------------------------------

namespace {
struct TokenHouse {
    CKey keyPartner, keyHolder, keyOther;
    std::vector<unsigned char> pubPartner, pubHolder, pubOther;
    CHouse house;
    TokenHouse()
    {
        pubPartner = FreshPubKey(keyPartner);
        pubHolder = FreshPubKey(keyHolder);
        pubOther = FreshPubKey(keyOther);
        house.nHouseID = 3;
        house.houseID = uint256S("70c3");
        house.nTier = HOUSE_TIER_MULTI_PARTNER;
        house.nThresholdM = 1;
        house.strClassID = "tokens";
        house.nDenomMgGold = 1000;
        house.status = HOUSE_STATUS_OPEN;
        house.nRegisteredHeight = 1000;
        house.nLastAttestHeight = 1599;               // effectively Open at 1600
        house.amountLastAttestReserves = 100 * COIN;
        house.nMintedUnits = 1000000;
        HousePartner p;
        p.vchPubKey = pubPartner;
        p.amountPledge = 10 * COIN;
        p.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(p);
    }
    std::function<bool(uint32_t, CHouse&)> Get() const
    {
        const CHouse h = house;
        return [h](uint32_t id, CHouse& out) { if (id != h.nHouseID) return false; out = h; return true; };
    }
};

// LOCK nUnits out of one note coin of nIn units (change back to the holder), with a plain fee input; both signers
// sign the same digest unless told to forge.
static CMutableTransaction MakeLockTx(const TokenHouse& t, uint64_t nUnits, uint64_t nIn,
                                      bool fGoodHolder = true, bool fGoodHouse = true)
{
    NoteLock lock;
    lock.nHouseID = t.house.nHouseID;
    lock.nUnits = nUnits;
    lock.vchHolderPubKey = t.pubHolder;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_LOCK;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0a"), 0)));   // the note
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0b"), 1)));   // fee
    if (nIn > nUnits) {
        lock.vChangeUnits.push_back(nIn - nUnits);
        mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(t.pubHolder)));
    }
    const uint256 h = NoteLockSigHash(C1With(mtx, &CMutableTransaction::vchNotePayload, lock));   // Stage 0 C1
    BOOST_REQUIRE((fGoodHolder ? t.keyHolder : t.keyOther).Sign(h, lock.vchHolderSig));
    std::vector<unsigned char> sig;
    BOOST_REQUIRE((fGoodHouse ? t.keyPartner : t.keyOther).Sign(h, sig));
    lock.vApproverIndex.push_back(0);
    lock.vApproverSig.push_back(sig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << lock;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

static CMutableTransaction MakeUnlockTx(const TokenHouse& t, uint64_t nUnits, bool fGoodHouse = true)
{
    NoteUnlock unlock;
    unlock.nHouseID = t.house.nHouseID;
    unlock.vUnits.push_back(nUnits);
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_UNLOCK;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0c"), 0)));   // fee
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(t.pubHolder)));
    const uint256 h = NoteUnlockSigHash(C1With(mtx, &CMutableTransaction::vchNotePayload, unlock));   // Stage 0 C1
    std::vector<unsigned char> sig;
    BOOST_REQUIRE((fGoodHouse ? t.keyPartner : t.keyOther).Sign(h, sig));
    unlock.vApproverIndex.push_back(0);
    unlock.vApproverSig.push_back(sig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << unlock;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

static std::string TokenOp(const CMutableTransaction& mtx, const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                           CHouse* pOut = nullptr, int nHeight = 1600)
{
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    auto fnNoBlock = [](uint32_t, uint256&) { return false; };
    CValidationState state;
    CHouse houseOut;
    bool fChanged = false;
    if (!CheckNoteOperation(CTransaction(mtx), state, nHeight, 1000, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock,
            houseOut, fChanged))
        return state.GetRejectReason();
    if (!fChanged)
        return "unchanged";
    if (pOut)
        *pOut = houseOut;
    return "OK";
}

static std::string TokenShape(const CMutableTransaction& mtx)
{
    CValidationState state;
    return CheckNoteTransactionShape(CTransaction(mtx), state) ? "OK" : state.GetRejectReason();
}
} // namespace

BOOST_AUTO_TEST_CASE(token_record_shape)
{
    TokenHouse t;
    BOOST_CHECK_EQUAL(TokenShape(MakeLockTx(t, 300, 300)), "OK");     // no change
    BOOST_CHECK_EQUAL(TokenShape(MakeLockTx(t, 300, 1000)), "OK");    // change note at vout[0]
    BOOST_CHECK_EQUAL(TokenShape(MakeUnlockTx(t, 200)), "OK");

    auto withLock = [](CMutableTransaction mtx, const std::function<void(NoteLock&)>& f) {
        NoteLock l; BOOST_REQUIRE(DecodeNotePayload(mtx.vchNotePayload, l)); f(l);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << l;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        return mtx;
    };
    BOOST_CHECK_EQUAL(TokenShape(withLock(MakeLockTx(t, 300, 300), [](NoteLock& l) { l.nUnits = 0; })), "bad-note-lock-units");
    BOOST_CHECK_EQUAL(TokenShape(withLock(MakeLockTx(t, 300, 300), [](NoteLock& l) { l.vchHolderPubKey.pop_back(); })), "bad-note-lock-auth");
    BOOST_CHECK_EQUAL(TokenShape(withLock(MakeLockTx(t, 300, 300), [](NoteLock& l) { l.vApproverIndex.clear(); l.vApproverSig.clear(); })), "bad-note-lock-approvers");
    BOOST_CHECK_EQUAL(TokenShape(withLock(MakeLockTx(t, 300, 300), [](NoteLock& l) { l.vChangeUnits = {0}; })), "bad-note-lock-change-units");
    {
        CMutableTransaction mtx = MakeLockTx(t, 300, 1000);
        mtx.vout[0].nValue = NOTE_DUST_VALUE + 1;            // a change note must be dust-valued
        BOOST_CHECK_EQUAL(TokenShape(mtx), "bad-note-output-value");
    }
    {
        CMutableTransaction mtx = MakeUnlockTx(t, 200);
        mtx.vout.clear();
        BOOST_CHECK_EQUAL(TokenShape(mtx), "bad-note-vout-size");
    }
}

BOOST_AUTO_TEST_CASE(token_lock_and_unlock_records)
{
    TokenHouse t;
    // The mint record: 300 of a 1000-unit note into the backing; the notes stay a liability.
    CHouse after;
    BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), t.Get(), &after), "OK");
    BOOST_CHECK_EQUAL(after.nTokenUnits, 300U);
    BOOST_CHECK_EQUAL(after.nMintedUnits, t.house.nMintedUnits);

    // The burn record, against that backing: 200 out, then not more than the 100 left.
    t.house = after;
    CHouse after2;
    BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 200), t.Get(), &after2), "OK");
    BOOST_CHECK_EQUAL(after2.nTokenUnits, 100U);
    BOOST_CHECK_EQUAL(after2.nMintedUnits, t.house.nMintedUnits);
    t.house = after2;
    BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 101), t.Get()), "bad-note-unlock-over-locked");
    BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 100), t.Get()), "OK");
    // Nothing locked: nothing to burn.
    t.house.nTokenUnits = 0;
    BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 1), t.Get()), "bad-note-unlock-over-locked");
}

BOOST_AUTO_TEST_CASE(token_records_need_their_signatures)
{
    TokenHouse t;
    // A lock needs BOTH the holder and the house (Q1).
    BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000, false, true), t.Get()), "bad-note-lock-sig");
    BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000, true, false), t.Get()), "bad-note-lock-approver");
    // An unlock needs the house.
    t.house.nTokenUnits = 500;
    BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 200, false), t.Get()), "bad-note-unlock-approver");
    // Approvals are bound to the exact tx: the lock's signatures don't carry to another input set.
    CMutableTransaction mtx = MakeLockTx(t, 300, 1000);
    mtx.vin[1].prevout = COutPoint(uint256S("0d"), 0);
    BOOST_CHECK_EQUAL(TokenOp(mtx, t.Get()), "bad-note-lock-sig");
}

BOOST_AUTO_TEST_CASE(token_lock_house_rules)
{
    // Members-only houses can't run a mint (Q2).
    {
        TokenHouse t;
        t.house.nFlags = HOUSE_FLAG_MEMBERS_ONLY;
        BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), t.Get()), "bad-note-lock-members-only");
    }
    // No new tokens while suspended or failed (Q3). v0.2.21 (claim design draft 3, Michael 2026-10-08: "no burns in
    // suspension"): no burns either, from suspension on; while merely Stressed, burns stay allowed.
    {
        TokenHouse t;
        t.house.nDeferInvokedHeight = 1590;
        t.house.nTokenUnits = 500;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(t.house, 1600), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), t.Get()), "bad-note-lock-house-status");
        BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 200), t.Get()), "bad-note-unlock-house-status");
    }
    {
        TokenHouse t;
        t.house.status = HOUSE_STATUS_INSOLVENT;
        t.house.nTokenUnits = 500;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(t.house, 1600), HOUSE_STATUS_INSOLVENT);
        BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), t.Get()), "bad-note-lock-house-status");
        BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 200), t.Get()), "bad-note-unlock-house-status");
    }
    {
        TokenHouse t;
        t.house.status = HOUSE_STATUS_WOUNDDOWN;
        BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), t.Get()), "bad-note-lock-house-status");
    }
    // A stressed house may still convert notes it already issued (a lock issues no new liability).
    {
        TokenHouse t;
        t.house.nStressSinceHeight = 1595;
        t.house.nTokenUnits = 500;
        if (HouseEffectiveStatus(t.house, 1600) == HOUSE_STATUS_STRESSED) {
            BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), t.Get()), "OK");
            BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 200), t.Get()), "OK");   // and burns stay open while stressed
        }
    }
    // Defence in depth: the backing never exceeds the outstanding notes.
    {
        TokenHouse t;
        t.house.nMintedUnits = 250;
        BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), t.Get()), "bad-note-lock-over-outstanding");
    }
    // Unknown house.
    {
        TokenHouse t;
        auto fnNone = [](uint32_t, CHouse&) { return false; };
        BOOST_CHECK_EQUAL(TokenOp(MakeLockTx(t, 300, 1000), fnNone), "bad-note-unknown-house");
        BOOST_CHECK_EQUAL(TokenOp(MakeUnlockTx(t, 1), fnNone), "bad-note-unknown-house");
    }
}

BOOST_AUTO_TEST_CASE(token_lock_inputs)
{
    // tx_verify: who may spend the notes a lock takes, conservation, and where change may go.
    TokenHouse t;
    auto inputs = [&](const CMutableTransaction& mtx, uint32_t nTag, const std::vector<unsigned char>& pubNote,
                      uint64_t nNoteUnits) {
        CCoinsView base;
        CCoinsViewCache cache(&base);
        Coin note(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pubNote)), 100, false, false, false, uint256());
        note.SetNote(t.house.nHouseID, nNoteUnits, nTag);
        cache.AddCoin(COutPoint(uint256S("0a"), 0), std::move(note), false);
        Coin fee(CTxOut(100000, GetScriptForDestination(CPubKey(t.pubHolder).GetID())), 100, false, false, false, uint256());
        cache.AddCoin(COutPoint(uint256S("0b"), 1), std::move(fee), false);
        CValidationState state;
        CAmount nFee = 0;
        return Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, nFee) ? std::string("OK") : state.GetRejectReason();
    };
    BOOST_CHECK_EQUAL(inputs(MakeLockTx(t, 300, 1000), 0, t.pubHolder, 1000), "OK");
    BOOST_CHECK_EQUAL(inputs(MakeLockTx(t, 1000, 1000), 0, t.pubHolder, 1000), "OK");
    // in != locked + change
    BOOST_CHECK_EQUAL(inputs(MakeLockTx(t, 300, 1000), 0, t.pubHolder, 900), "bad-note-lock-conservation");
    // someone else's note
    BOOST_CHECK_EQUAL(inputs(MakeLockTx(t, 300, 1000), 0, t.pubOther, 1000), "bad-note-input-not-holder");
    // a demanded note carries an interest clock a token can't carry
    BOOST_CHECK_EQUAL(inputs(MakeLockTx(t, 300, 1000), 1500, t.pubHolder, 1000), "bad-note-lock-demanded");
    // change only back to the holder (a lock is not a transfer)
    {
        CMutableTransaction mtx = MakeLockTx(t, 300, 1000);
        mtx.vout[0].scriptPubKey = NoteScriptForPubKey(t.pubOther);
        BOOST_CHECK_EQUAL(inputs(mtx, 0, t.pubHolder, 1000), "bad-note-lock-change-not-holder");
    }
    // an unlock spends no notes
    {
        CMutableTransaction mtx = MakeUnlockTx(t, 200);
        mtx.vin[0].prevout = COutPoint(uint256S("0b"), 1);         // the fee coin the view holds
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0a"), 0)));
        BOOST_CHECK_EQUAL(inputs(mtx, 0, t.pubHolder, 1000), "bad-txns-spend-note-coin");
    }
}

// v0.2.21 one-step lock: the customer signs its inputs before the house adds its partners' signatures to the payload.
// Since v1.0.2 an input's signature hash binds nNoteOp and the payload minus its signature fields (creditbind.h), so
// the approvals can land later. Pin both halves: the approvals leave the input sighash alone (or the customer's
// signatures break when the house approves), and the rest of the lock moves it (or a relay could rewrite it).
BOOST_AUTO_TEST_CASE(note_lock_approvals_outside_input_sighash)
{
    CKey key;
    key.MakeNewKey(true);
    const CScript script = GetScriptForDestination(key.GetPubKey().GetID());
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_LOCK;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0a"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0b"), 1)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, script));
    NoteLock lock;
    lock.nHouseID = 1;
    lock.nUnits = 1000;
    lock.vchHolderPubKey = ToByteVector(key.GetPubKey());
    lock.vchHolderSig = std::vector<unsigned char>(71, 0x30);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << lock;
    mtx.vchNotePayload.assign(ss.begin(), ss.end());
    const uint256 txidBefore = CTransaction(mtx).GetHash();
    const uint256 h0 = SignatureHash(script, CTransaction(mtx), 0, SIGHASH_ALL, NOTE_DUST_VALUE, SIGVERSION_BASE);
    const uint256 h1 = SignatureHash(script, CTransaction(mtx), 1, SIGHASH_ALL, 50000, SIGVERSION_BASE);

    // The house adds its approvals: the payload grows, the inputs' signature hashes do not move.
    lock.vApproverIndex = {0, 1};
    lock.vApproverSig = {std::vector<unsigned char>(71, 0x31), std::vector<unsigned char>(71, 0x32)};
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << lock;
    mtx.vchNotePayload.assign(ss2.begin(), ss2.end());
    BOOST_CHECK(SignatureHash(script, CTransaction(mtx), 0, SIGHASH_ALL, NOTE_DUST_VALUE, SIGVERSION_BASE) == h0);
    BOOST_CHECK(SignatureHash(script, CTransaction(mtx), 1, SIGHASH_ALL, 50000, SIGVERSION_BASE) == h1);
    // ... while the txid does (the payload is part of the transaction).
    BOOST_CHECK(CTransaction(mtx).GetHash() != txidBefore);
    // The lock itself and the op are bound.
    {
        CMutableTransaction m2 = mtx;
        NoteLock moved = lock;
        moved.nUnits += 1;
        CDataStream ss3(SER_NETWORK, PROTOCOL_VERSION);
        ss3 << moved;
        m2.vchNotePayload.assign(ss3.begin(), ss3.end());
        BOOST_CHECK(SignatureHash(script, CTransaction(m2), 0, SIGHASH_ALL, NOTE_DUST_VALUE, SIGVERSION_BASE) != h0);
        m2 = mtx;
        m2.nNoteOp = NOTE_OP_UNLOCK;
        BOOST_CHECK(SignatureHash(script, CTransaction(m2), 0, SIGHASH_ALL, NOTE_DUST_VALUE, SIGVERSION_BASE) != h0);
    }

    // The payload's own digest is what binds the lock: it changes with the outputs.
    const uint256 d0 = NoteLockSigHash(CTransaction(mtx));
    mtx.vout[0].nValue += 1;
    BOOST_CHECK(NoteLockSigHash(CTransaction(mtx)) != d0);
}

// testing (2026-11-10): UR1-7 (ultra s1 #7; Michael signed it off 2026-11-10, freebank
// docs-local/CONSENSUS_SIGNOFF_2026-11-10.md item 7). The note family's approver-array shape - MINT's inline copy and
// CheckNoteApproverShape for LOCK, UNLOCK and TOKEN_KEYSET - has no MAX_HOUSE_PARTNERS bound, while the house, bill and
// settle copies all do. A payload naming more approvers than any house can have partners must fail at shape.
// FAILS on master a00fb05 (65 approvers pass shape for all four ops); passes once the bound is added. The 64-approver
// control must pass shape both before and after.
namespace {
template <typename T>
void UR17SetApprovers(T& p, size_t n)
{
    p.vApproverIndex.clear();
    p.vApproverSig.clear();
    for (size_t i = 0; i < n; i++) {
        p.vApproverIndex.push_back((uint32_t)i);                        // strictly ascending
        p.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30)); // shape checks the size only
    }
}

template <typename T>
std::string UR17ShapeReason(uint8_t nOp, const T& payload, const std::vector<CTxOut>& vout)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = nOp;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vchNotePayload.assign(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("17"), 0)));
    mtx.vout = vout;
    CValidationState state;
    return CheckNoteTransactionShape(CTransaction(mtx), state) ? std::string() : state.GetRejectReason();
}
} // namespace

BOOST_AUTO_TEST_CASE(ur1_7_note_approver_count_bounded_at_shape)
{
    CKey keyHolder, keyPost, keyToken;
    const std::vector<unsigned char> pubHolder = FreshPubKey(keyHolder);
    const std::vector<unsigned char> pubPost = FreshPubKey(keyPost);
    const std::vector<unsigned char> pubToken = FreshPubKey(keyToken);
    const std::vector<CTxOut> vNoteOut{CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pubHolder))};
    const std::vector<CTxOut> vNone;

    for (const size_t n : {MAX_HOUSE_PARTNERS, MAX_HOUSE_PARTNERS + 1}) {
        NoteMint mint;
        mint.nHouseID = 1;
        mint.vUnits = {100};
        UR17SetApprovers(mint, n);

        NoteLock lock;
        lock.nHouseID = 1;
        lock.nUnits = 100;
        lock.vchHolderPubKey = pubHolder;
        lock.vchHolderSig = std::vector<unsigned char>(70, 0x30);
        UR17SetApprovers(lock, n);

        NoteUnlock unlock;
        unlock.nHouseID = 1;
        unlock.vUnits = {100};
        UR17SetApprovers(unlock, n);

        NoteTokenKeyset ks;
        ks.nHouseID = 1;
        ks.vchPostingPubKey = pubPost;
        ks.vKey.push_back(TokenKey(0, pubToken));
        UR17SetApprovers(ks, n);

        const std::vector<std::pair<std::string, std::string>> vResult = {
            {"MINT", UR17ShapeReason(NOTE_OP_MINT, mint, vNoteOut)},
            {"LOCK", UR17ShapeReason(NOTE_OP_LOCK, lock, vNone)},
            {"UNLOCK", UR17ShapeReason(NOTE_OP_UNLOCK, unlock, vNoteOut)},
            {"TOKEN_KEYSET", UR17ShapeReason(NOTE_OP_TOKEN_KEYSET, ks, vNone)},
        };
        for (const auto& r : vResult) {
            if (n <= MAX_HOUSE_PARTNERS) {
                BOOST_CHECK_MESSAGE(r.second.empty(), "UR1-7 control: " + r.first + " with " + std::to_string(n) +
                                    " approvers was refused at shape: " + r.second);
            } else {
                BOOST_CHECK_MESSAGE(r.second.find("approvers") != std::string::npos,
                                    "UR1-7: " + r.first + " with " + std::to_string(n) + " approvers (more than "
                                    "MAX_HOUSE_PARTNERS) passed note shape" +
                                    (r.second.empty() ? std::string() : " or failed for another reason: " + r.second));
            }
        }
    }
}

// testing (2026-11-10): stage A SA-N4 (security 11-08; consensus, on freebankd's second sign-off list for Michael).
// tx_verify's input/structure arm covers NOTE_OP_SWAP_DONE, _PAY and _PROTEST but not NOTE_OP_SWAP_EXPIRE, and none
// of the four refuses a stray output to a house escrow script or to the noteholders' fund: such an output enters the UTXO
// set untagged, an anyone-can-spend coin (the escrow lock is <house_id> OP_DROP OP_TRUE). None of these ops pays into
// escrow or the fund, so each must refuse both. FAILS on master a00fb05 (all accepted); passes once SWAP_EXPIRE joins
// the arm and stray escrow/fund outputs are refused. The control (no stray output) must pass before and after.
namespace {
template <typename T>
std::string SAN4Inputs(uint8_t nOp, const T& payload, const CScript* pStray)
{
    CCoinsView base;
    CCoinsViewCache cache(&base);
    const COutPoint fund(uint256S("54a4"), 0);
    cache.AddCoin(fund, Coin(CTxOut(100000, GetScriptForDestination(CKeyID(uint160(std::vector<unsigned char>(20, 0x54))))), 100, false, false, false,
                             uint256()), false);
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = nOp;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vchNotePayload.assign(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(fund));
    mtx.vout.push_back(CTxOut(90000, GetScriptForDestination(CKeyID(uint160(std::vector<unsigned char>(20, 0x55))))));
    if (pStray)
        mtx.vout.push_back(CTxOut(1000, *pStray));
    CValidationState state;
    CAmount fee = 0;
    return Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee)
               ? std::string() : (state.GetRejectReason().empty() ? std::string("(refused)") : state.GetRejectReason());
}
} // namespace

BOOST_AUTO_TEST_CASE(testing_sa_n4_swap_ops_refuse_stray_escrow_and_fund_outputs)
{
    const uint256 hashLock = uint256S("5a4e");
    NoteSwapExpire ex; ex.nHouseID = 3; ex.hashLock = hashLock; ex.nRateNamed = 1000;
    NoteSwapDone dn; dn.nHouseID = 3; dn.hashLock = hashLock; dn.vchPreimage.assign(32, 0x11);
    NoteSwapPay pay; pay.nHouseID = 3; pay.hashLock = hashLock; pay.nRateNamed = 1000; pay.fWasProtested = 0;
    NoteSwapProtest pr; pr.nHouseID = 3; pr.hashLock = hashLock;
    const CScript scriptEscrow = HouseEscrowScript(uint256S("f00d"));
    const CScript scriptFund = MutualFundScript();
    const std::vector<std::pair<std::string, const CScript*>> vStray = {
        {"a house escrow script", &scriptEscrow}, {"the noteholders' fund script", &scriptFund}};

    struct Op { const char* name; std::function<std::string(const CScript*)> run; };
    const std::vector<Op> vOp = {
        {"SWAP_EXPIRE", [&](const CScript* p) { return SAN4Inputs(NOTE_OP_SWAP_EXPIRE, ex, p); }},
        {"SWAP_DONE", [&](const CScript* p) { return SAN4Inputs(NOTE_OP_SWAP_DONE, dn, p); }},
        {"SWAP_PAY", [&](const CScript* p) { return SAN4Inputs(NOTE_OP_SWAP_PAY, pay, p); }},
        {"SWAP_PROTEST", [&](const CScript* p) { return SAN4Inputs(NOTE_OP_SWAP_PROTEST, pr, p); }},
    };
    for (const Op& op : vOp) {
        const std::string strControl = op.run(nullptr);
        BOOST_CHECK_MESSAGE(strControl.empty(), std::string("SA-N4 control: ") + op.name + " with plain inputs and "
                            "outputs was refused: " + strControl);
        for (const auto& stray : vStray) {
            const std::string strStray = op.run(stray.second);
            BOOST_CHECK_MESSAGE(!strStray.empty(), std::string("SA-N4: ") + op.name + " with a stray output to " +
                                stray.first + " was accepted (an untagged anyone-can-spend coin)");
        }
    }
}

// testing (2026-11-10): stage A SA-N3 (security 11-08; consensus, on freebankd's second sign-off list for Michael). A
// holder-signed REDEEM that names no rate (nRateNamed 0) is valued at no price, so it owes no brassage spread
// (validation.cpp: nBrassageBps = nRedeemPrice ? owed : 0). At an Open house the spread is 0 anyway; at a Stressed house
// the spread is what keeps a run from draining the pot the other holders rely on, and naming 0 skips it. The fix: at a
// house that owes a spread, a REDEEM must pay it (so it can't name rate 0). The unit-test rate override
// (g_nHouseRateTestOverride) routes rate-0 redemptions through BoundHouseRate and hides this, so the test switches it
// off. FAILS on master a00fb05 (accepted at the Stressed house); passes with the fix. The Open-house control (rate 0, no
// spread owed) must stay accepted.
BOOST_AUTO_TEST_CASE(testing_sa_n3_stressed_redeem_cannot_skip_brassage)
{
    const uint64_t U = 1000000;
    const int H = 20000;
    CKey keyHolder; keyHolder.MakeNewKey(true);
    const CPubKey pubHolder = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchHolder(pubHolder.begin(), pubHolder.end());

    CHouse house;
    house.nHouseID = 7;
    house.houseID = uint256S("5a43");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "san3";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nMintedUnits = 10 * U;
    house.nLastAttestHeight = H - 10;               // a fresh cadence
    house.amountLastAttestReserves = 1000;          // a thin till: a spread is owed once the house isn't Open
    HousePartner p;
    p.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p.amountPledge = 100 * COIN;
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);

    auto fnNoteCoin = [&](const COutPoint&, Coin& coin) {
        coin = Coin(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchHolder)), H - 100, false, false, false, uint256());
        coin.SetNote(7, U, 0);                       // an ordinary (undemanded) note
        return true;
    };
    auto fnNoBlock = [](uint32_t, uint256&) { return false; };
    const uint64_t nOverridePrev = g_nHouseRateTestOverride;
    g_nHouseRateTestOverride = 0;                    // let a rate-0 redemption take its real path

    for (const bool fStressed : {false, true}) {
        CHouse h = house;
        if (fStressed) {                             // an unpaid protest a few blocks ago: Stressed, its cure running
            h.nProtestOpen = 1;
            h.nProtestHeight = H - 5;
            h.nProtestDemandHeight = H - 50;
        }
        auto fnGetHouse = [&h](uint32_t id, CHouse& out) { if (id != 7) return false; out = h; return true; };
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(h, H), fStressed ? HOUSE_STATUS_STRESSED : HOUSE_STATUS_OPEN);
        const uint32_t nSpreadBps = GoldBrassageBps(h, H);
        if (fStressed)
            BOOST_REQUIRE_MESSAGE(nSpreadBps > 0, "SA-N3 setup: the Stressed house owes no spread");
        CMutableTransaction mtx = MakeDemandedRedeemTx(7, U, keyHolder, (CAmount)U);   // nRateNamed 0, no spread output
        CValidationState state; CHouse houseOut; bool fChanged = false;
        const bool fOk = CheckNoteOperation(CTransaction(mtx), state, H, U, fnGetHouse, fnNoteCoin, fnNoteCoin, fnNoBlock,
                                            houseOut, fChanged);
        if (!fStressed) {
            BOOST_CHECK_MESSAGE(fOk, "SA-N3 control: a rate-0 REDEEM at an Open house (no spread owed) was refused: " +
                                state.GetRejectReason());
        } else {
            BOOST_CHECK_MESSAGE(!fOk, "SA-N3: a REDEEM naming rate 0 at a Stressed house that owes a " +
                                std::to_string(nSpreadBps) + " bps spread was accepted with no spread paid");
        }
    }
    g_nHouseRateTestOverride = nOverridePrev;
}

// testing (2026-11-25): S1X-31 (Claude max run 3 #8; security: Medium; Michael's yes 11-25, "If you need it yes", in
// gateway docs/security/reviews/2026-11-08-multi-model-review.md): refuse a new SWAP while a REDEEM at that house would
// owe a spread. At a Stressed house whose till is below the 2% floor, or a suspended (Deferred) one, a holder could leave
// at par through a SWAP (SWAP_PAY prices at the bid, no spread term) and skip the spread a REDEEM pays into the stayers'
// pot. FAILS on master (both SWAPs accepted); passes once such a SWAP is refused (any reason). Controls, which hold
// before and after: a SWAP at the Open house with the same thin till, and at a Stressed house whose till is above the
// floor (no spread owed), are accepted; at the Stressed house below the floor a REDEEM that names no rate is refused
// (SA-N3: the spread is owed there). Open swaps settle as now (not exercised here).
BOOST_AUTO_TEST_CASE(s1x_31_no_new_swap_where_a_redeem_would_owe_a_spread)
{
    const uint64_t U = 1000000;
    const int H = 20000;
    CKey keyHolder; keyHolder.MakeNewKey(true);
    const CPubKey pubHolder = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchHolder(pubHolder.begin(), pubHolder.end());
    const std::vector<unsigned char> vchP2PKH = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");

    // SA-N3's house: a thin till, so a spread is owed once it isn't Open.
    CHouse base;
    base.nHouseID = 7;
    base.houseID = uint256S("5a43");
    base.nTier = HOUSE_TIER_MULTI_PARTNER;
    base.nThresholdM = 1;
    base.strClassID = "s1x31";
    base.nDenomMgGold = 1000;
    base.status = HOUSE_STATUS_OPEN;
    base.nRegisteredHeight = 1000;
    base.nMintedUnits = 10 * U;
    base.nLastAttestHeight = H - 10;
    base.amountLastAttestReserves = 1000;
    HousePartner p;
    p.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p.amountPledge = 100 * COIN;
    p.status = HOUSE_PARTNER_ACTIVE;
    base.vPartner.push_back(p);

    CHouse hStressedThin = base;                     // an unpaid protest a few blocks ago: Stressed, its cure running
    hStressedThin.nProtestOpen = 1;
    hStressedThin.nProtestHeight = H - 5;
    hStressedThin.nProtestDemandHeight = H - 50;
    CHouse hStressedRich = hStressedThin;            // the same, its till well above the floor
    hStressedRich.amountLastAttestReserves = 1000 * COIN;
    CHouse hDeferred = base;                         // the option clause invoked: suspended
    hDeferred.nDeferInvokedHeight = H - 100;

    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(base, H), HOUSE_STATUS_OPEN);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(hStressedThin, H), HOUSE_STATUS_STRESSED);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(hStressedRich, H), HOUSE_STATUS_STRESSED);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(hDeferred, H), HOUSE_STATUS_DEFERRED);
    BOOST_REQUIRE_EQUAL(GoldBrassageBps(base, H), 0U);
    const uint32_t nSpreadBps = GoldBrassageBps(hStressedThin, H);
    BOOST_REQUIRE_MESSAGE(nSpreadBps > 0, "S1X-31 setup: the Stressed thin-till house owes no spread");
    BOOST_REQUIRE_MESSAGE(GoldBrassageBps(hStressedRich, H) == 0, "S1X-31 setup: the Stressed rich house owes a spread");

    // The token the swap pays and the chain clock, in a units view (as s1x_15's SWAP section).
    CUnitsView units(nullptr);
    CHouseCharter charter;
    CCharterToken tok;
    tok.nChainID = 1;
    tok.vchContract = std::vector<unsigned char>(20, 0xc0);
    tok.nDecimals = 18;
    tok.nGramsNum = 1;
    tok.nGramsDen = 1;
    tok.nAddedTime = 1;
    charter.vToken.push_back(tok);
    units.Put(HouseCharterKey(7), charter);
    CChainClock clock;
    clock.nHeight = (uint32_t)(H - 1);
    clock.nMonoTime = clock.nActiveTime = (int64_t)H * 600;
    units.Put(ChainClockKey(), clock);
    UnitsCheckScope scope(&units);

    auto fnNoBlock = [](uint32_t, uint256&) { return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    auto swapReject = [&](const CHouse& h) {
        NoteSwap sw;
        sw.nHouseID = 7;
        sw.nUnits = U;
        sw.vchHolderPubKey = vchHolder;
        sw.nChainID = 1;
        sw.vchContract = tok.vchContract;
        sw.vchEthAddress = std::vector<unsigned char>(20, 0xe7);
        sw.hashLock = uint256S("5131");
        sw.nRateNamed = 0;   // the unit tests' rate override names the bid
        sw.vchPayoutScript = vchP2PKH;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_SWAP;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("5a31"), 0)));
        mtx.vout.push_back(CTxOut(10000, CScript(vchP2PKH.begin(), vchP2PKH.end())));   // fee change
        BOOST_REQUIRE(keyHolder.Sign(NoteSwapSigHash(C1With(mtx, &CMutableTransaction::vchNotePayload, sw)), sw.vchHolderSig));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << sw;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        auto fnGetHouse = [&h](uint32_t id, CHouse& out) { if (id != 7) return false; out = h; return true; };
        CValidationState state; CHouse houseOut; bool fChanged = false;
        return CheckNoteOperation(CTransaction(mtx), state, H, U, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock,
                                  houseOut, fChanged) ? std::string() : state.GetRejectReason();
    };

    // Controls: no spread owed, so a SWAP is accepted.
    BOOST_CHECK_MESSAGE(swapReject(base).empty(), "S1X-31 control: a SWAP at the Open house was refused: " + swapReject(base));
    BOOST_CHECK_MESSAGE(swapReject(hStressedRich).empty(),
                        "S1X-31 control: a SWAP at a Stressed house above the till floor (no spread owed) was refused: " +
                        swapReject(hStressedRich));
    // The rule.
    BOOST_CHECK_MESSAGE(!swapReject(hStressedThin).empty(),
                        "S1X-31: a SWAP at a Stressed house that owes a " + std::to_string(nSpreadBps) +
                        " bps spread was accepted: the holder leaves at the bid and skips the spread a REDEEM pays");
    BOOST_CHECK_MESSAGE(!swapReject(hDeferred).empty(),
                        "S1X-31: a SWAP at a Deferred (suspended) house was accepted: the holder leaves at the bid while "
                        "a REDEEM is suspended");

    // Control: at the Stressed thin-till house a REDEEM owes the spread (SA-N3: one naming no rate is refused).
    {
        const uint64_t nOverridePrev = g_nHouseRateTestOverride;
        g_nHouseRateTestOverride = 0;
        auto fnNoteCoin = [&](const COutPoint&, Coin& coin) {
            coin = Coin(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchHolder)), H - 100, false, false, false, uint256());
            coin.SetNote(7, U, 0);
            return true;
        };
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id != 7) return false; out = hStressedThin; return true; };
        CMutableTransaction mtx = MakeDemandedRedeemTx(7, U, keyHolder, (CAmount)U);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        const bool fOk = CheckNoteOperation(CTransaction(mtx), state, H, U, fnGetHouse, fnNoteCoin, fnNoteCoin, fnNoBlock,
                                            houseOut, fChanged);
        g_nHouseRateTestOverride = nOverridePrev;
        BOOST_CHECK_MESSAGE(!fOk, "S1X-31 control: a REDEEM naming no rate at the Stressed thin-till house was accepted "
                            "(it owes a " + std::to_string(nSpreadBps) + " bps spread)");
    }
}

// ---------------------------------------------------------------------------
// UF4-1 (ultra on review-fixed/s4, 2026-11-23). A note op's status, height and cap verdicts can
// flip from one block to the next with no tx in between: lazy insolvency (nNoCureHeight, window expiry), a deferral,
// a till cap that moves with height. Two honest nodes one block apart then disagree about the same relayed tx, and
// net_processing bans the relaying peer for any nDoS > 0 out of AcceptToMemoryPool. So on the mempool path
// (fMempool = true) such a refusal must score 0, as swap-house-closed and swap-protest-status already do and as
// protest-prior does with fMempool ? 0 : 100 (the UR3-3 rule). At connect (fMempool = false) the 100 stays.
// ---------------------------------------------------------------------------
namespace {
struct NoteVerdict { bool fOk; std::string strReason; int nDoS; };
static NoteVerdict CheckNoteVerdict(const CMutableTransaction& mtx, const CHouse& h, int nHeight, uint64_t nUnitsIn,
                                    bool fMempool, const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                                    const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin)
{
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == h.nHouseID) { out = h; return true; } return false; };
    CValidationState state; CHouse houseOut; bool fChanged = false;
    NoteVerdict v;
    v.fOk = CheckNoteOperation(CTransaction(mtx), state, nHeight, nUnitsIn, fnGetHouse, fnGetCoin, fnGetCoin,
                               fnGetBlockHash, houseOut, fChanged, fMempool);
    v.strReason = state.GetRejectReason();
    v.nDoS = 0;
    state.IsInvalid(v.nDoS);
    return v;
}

// The well-capitalised, freshly attested Open house of note_mint_rho_liveness_gate.
static CHouse MakeOpenMintHouse()
{
    CHouse house;
    house.nHouseID = 5;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    house.amountLastAttestReserves = 100 * COIN;
    HousePartner p;
    p.vchPubKey = MintApproverPub();   // Stage 0 rule A: MakeMintTx's approver
    p.amountPledge = 100 * COIN;
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);
    return house;
}
} // namespace

BOOST_AUTO_TEST_CASE(uf4_1_status_height_and_cap_refusals_ban_no_peer_in_the_mempool)
{
    const std::function<bool(const COutPoint&, Coin&)> fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    const std::function<bool(uint32_t, uint256&)> fnNoBlock = [](uint32_t, uint256&) { return false; };
    const std::function<bool(uint32_t, uint256&)> fnBlock = [](uint32_t, uint256& h) { h = uint256S("beef"); return true; };

    // (1) MINT across a height-only boundary: no cure is left from height 1001, so the house is Open at 1000 and
    // Insolvent at 1001 with nothing confirmed in between. A peer one block behind relays a MINT valid at its tip.
    {
        CHouse house = MakeOpenMintHouse();
        house.nNoCureHeight = 1001;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, 1000), HOUSE_STATUS_OPEN);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, 1001), HOUSE_STATUS_INSOLVENT);
        const CMutableTransaction mtx = MakeMintTx(5, 100, /*nAsOfHeight=*/999);
        BOOST_CHECK(CheckNoteVerdict(mtx, house, 1000, 0, true, fnBlock, fnNoCoin).strReason != "bad-note-mint-house-not-open");
        const NoteVerdict pool = CheckNoteVerdict(mtx, house, 1001, 0, true, fnBlock, fnNoCoin);
        BOOST_CHECK_EQUAL(pool.strReason, "bad-note-mint-house-not-open");
        BOOST_CHECK_MESSAGE(pool.nDoS == 0, "mempool mint-house-not-open scores " << pool.nDoS << ", want 0 (UF4-1)");
        BOOST_CHECK_EQUAL(CheckNoteVerdict(mtx, house, 1001, 0, false, fnBlock, fnNoCoin).nDoS, 100);
    }

    // (5, security 11-23) The attestation-deadline case is in house_tests.cpp
    // (uf4_1_deferred_house_attest_at_its_silence_deadline_bans_no_peer): since the gram-notes release a missed
    // attestation no longer stresses an OPEN house, so the deadline that bites is a deferred house's silence clock.

    // (2) CLAIM across the same boundary, the other way: the sender is one block ahead (the house is lazily Insolvent
    // at its spend height 1600), the receiver one block behind (1599, not yet insolvent). Any holder can send this.
    {
        CHouse house = MakeDeferredHouse(1);
        house.nDeferInvokedHeight = 0;
        house.nNoCureHeight = 1600;
        HousePartner pt;
        pt.vchPubKey = std::vector<unsigned char>(33, 0x02);
        pt.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(pt);
        BOOST_REQUIRE(HouseEffectiveStatus(house, 1599) != HOUSE_STATUS_INSOLVENT);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, 1600), HOUSE_STATUS_INSOLVENT);

        NoteClaim c;
        c.nHouseID = 1;
        CKey key; key.MakeNewKey(true);
        const CPubKey pub = key.GetPubKey();
        c.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
        c.vchHolderSig = std::vector<unsigned char>(70, 0x30);
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_CLAIM;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(100, NoteScriptForPubKey(c.vchHolderPubKey)));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << c;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());

        BOOST_CHECK(CheckNoteVerdict(mtx, house, 1600, 100, true, fnNoBlock, fnNoCoin).strReason != "bad-note-claim-not-insolvent");
        const NoteVerdict pool = CheckNoteVerdict(mtx, house, 1599, 100, true, fnNoBlock, fnNoCoin);
        BOOST_CHECK_EQUAL(pool.strReason, "bad-note-claim-not-insolvent");
        BOOST_CHECK_MESSAGE(pool.nDoS == 0, "mempool claim-not-insolvent scores " << pool.nDoS << ", want 0 (UF4-1)");
        BOOST_CHECK_EQUAL(CheckNoteVerdict(mtx, house, 1599, 100, false, fnNoBlock, fnNoCoin).nDoS, 100);
    }

    // (3) MINT over the till cap (TillCapUnits reads the height and the house's counters).
    {
        CHouse house = MakeOpenMintHouse();
        house.amountLastAttestReserves = 1;
        const CMutableTransaction mtx = MakeMintTx(5, 100, /*nAsOfHeight=*/999);
        const NoteVerdict pool = CheckNoteVerdict(mtx, house, 1000, 0, true, fnBlock, fnNoCoin);
        BOOST_CHECK_EQUAL(pool.strReason, "bad-note-mint-under-reserved");
        BOOST_CHECK_MESSAGE(pool.nDoS == 0, "mempool mint-under-reserved scores " << pool.nDoS << ", want 0 (UF4-1)");
        BOOST_CHECK_EQUAL(CheckNoteVerdict(mtx, house, 1000, 0, false, fnBlock, fnNoCoin).nDoS, 100);
    }

    // (4) REDEEM of undemanded notes while the house is Deferred (a status that a confirmed DEFER or the silence
    // window changes between blocks). Fully signed, so the refusal is the deferral gate's.
    {
        CHouse house = MakeDeferredHouse(1);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, 1600), HOUSE_STATUS_DEFERRED);
        NoteRedeem redeem;
        redeem.nHouseID = 1;
        redeem.fBrassage = 0;
        CKey keyHolder; keyHolder.MakeNewKey(true);
        const CPubKey pub = keyHolder.GetPubKey();
        redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_REDEEM;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(100, NoteScriptForPubKey(redeem.vchHolderPubKey)));
        { CDataStream sC1(SER_NETWORK, PROTOCOL_VERSION); sC1 << redeem; mtx.vchNotePayload.assign(sC1.begin(), sC1.end()); }   // Stage 0 C1
        BOOST_REQUIRE(keyHolder.Sign(NoteRedeemSigHash(CTransaction(mtx)), redeem.vchHolderSig));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        const NoteVerdict pool = CheckNoteVerdict(mtx, house, 1600, 100, true, fnNoBlock, fnNoCoin);
        BOOST_CHECK_EQUAL(pool.strReason, "bad-note-redeem-deferred");
        BOOST_CHECK_MESSAGE(pool.nDoS == 0, "mempool redeem-deferred scores " << pool.nDoS << ", want 0 (UF4-1)");
        BOOST_CHECK_EQUAL(CheckNoteVerdict(mtx, house, 1600, 100, false, fnNoBlock, fnNoCoin).nDoS, 100);
    }
}


// ---------------------------------------------------------------------------
// S1X-6 (s1 measuring run, 2026-11-23; security: Medium, blocks mainnet). A swap paid short drops
// its whole amount from the house's pending swaps (SwapSettle), so CapitalCapUnits and TillCapUnits give the room
// back, while the unpaid grams stay in the shortfall ledger and MaterializeInsolvency counts them in nInsolventUnits for
// the 90-day lapse. A house (its own swap holder: mint, swap, cut the bid, pay short) can re-mint into that room and
// the insiders' shortfall claims dilute every noteholder. Agreed fix (security 11-23): both caps subtract the live
// shortfall beside pending swaps, with MaterializeInsolvency's lapse. Each case: the cap set exactly (the test hook),
// minted N, room R = cap - N; (a) control, nothing owed: a MINT of R passes the cap and R + 1 is refused (the cap binds
// here); (b) R pending in swaps instead: R is refused (the rule as built, the reference); (c) a live shortfall of S paid
// the block before: R is refused and R - S passes; (d) the same shortfall paid just past the lapse: R passes.
// (c)'s refusal FAILS on master 4686200.
// ---------------------------------------------------------------------------
namespace {
struct S1X6Scope {
    std::function<void(const CHouse&, int, CHouseCapital&)> fnPrev;
    CUnitsView units;
    std::unique_ptr<UnitsCheckScope> pScope;
    S1X6Scope(uint32_t nHouseID, uint64_t nCapMg, uint64_t nTillMg, uint64_t nPending, uint64_t nShortfallMg,
              int64_t nPaidClock)
        : fnPrev(g_fnCapitalForChecksTestOverride), units(nullptr)
    {
        g_fnCapitalForChecksTestOverride = [nCapMg, nTillMg](const CHouse&, int, CHouseCapital& cap) {
            cap.nEscrowMg = nCapMg;
            cap.nCapacityMg = nCapMg;
            cap.nTillMg = nTillMg;
        };
        if (nPending)
            units.Put(SwapPendingKey(nHouseID), nPending);
        if (nShortfallMg) {
            CShortfallLedger led;
            led.vEntry.push_back(std::make_pair(nPaidClock, nShortfallMg));
            units.Put(ShortfallLedgerKey(nHouseID), led);
        }
        pScope.reset(new UnitsCheckScope(&units));
    }
    ~S1X6Scope()
    {
        pScope.reset();
        g_fnCapitalForChecksTestOverride = fnPrev;
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(s1x_6_live_shortfall_uses_issuing_room_until_it_lapses)
{
    const int H = 20000;
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(H);
    const int64_t nLapse = (int64_t)gp.nShortfallLapseSecs / 600;   // as MaterializeInsolvency reads it
    BOOST_REQUIRE(nLapse > 0 && ClockAtHeight(H) - nLapse - 1 > 0);
    const std::function<bool(const COutPoint&, Coin&)> fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    const std::function<bool(uint32_t, uint256&)> fnBlock = [](uint32_t, uint256& h) { h = uint256S("beef"); return true; };

    const uint64_t N = 50000, S = 20000;
    // Capital: capacity 100,000 mg, the till far above it. Till: the till cap 100,000 mg, the capital far above it.
    const uint64_t nTillFor100k = 100000 * (uint64_t)gp.nTillMinBps / 10000;   // TillCapUnits = till x 10000 / bps
    BOOST_REQUIRE_EQUAL(nTillFor100k * 10000 / gp.nTillMinBps, 100000u);
    struct Cap { const char* name; uint64_t nCapMg; uint64_t nTillMg; const char* strReason; };
    const Cap caps[] = {{"capital cap", 100000, 100 * 100000, "bad-note-mint-over-cap"},
                        {"till cap", 100 * 100000, nTillFor100k, "bad-note-mint-under-reserved"}};
    for (const Cap& cap : caps) {
        const uint64_t R = 100000 - N;
        CHouse house = MakeOpenMintHouse();
        house.nLastAttestHeight = H;                                    // fresh: effectively Open at H
        house.nMintedUnits = N;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
        auto fnVerdict = [&](uint64_t nPending, int64_t nPaidClock, uint64_t nMint) {
            S1X6Scope scope(house.nHouseID, cap.nCapMg, cap.nTillMg, nPending, nPaidClock >= 0 ? S : 0, nPaidClock);
            return CheckNoteVerdict(MakeMintTx(house.nHouseID, nMint, /*nAsOfHeight=*/H - 1), house, H, 0, false,
                                    fnBlock, fnNoCoin);
        };
        const std::string strCap = cap.name;
        // (a) control: the cap binds exactly at R.
        {
            const NoteVerdict v = fnVerdict(0, -1, R);
            BOOST_CHECK_MESSAGE(v.strReason != cap.strReason, "S1X-6 control (" + strCap + "): a MINT of the full room " +
                                std::to_string(R) + " was refused at the cap");
            BOOST_CHECK_MESSAGE(fnVerdict(0, -1, R + 1).strReason == cap.strReason, "S1X-6 control (" + strCap +
                                "): a MINT of room + 1 got past the cap: the case does not test this cap");
        }
        // (b) reference: R pending in swaps uses the room up (GOLD_B §4: "as the notes they were").
        BOOST_CHECK_MESSAGE(fnVerdict(R, -1, R).strReason == cap.strReason, "S1X-6 reference (" + strCap +
                            "): a MINT of R with R pending in swaps got past the cap");
        // (c) a live shortfall of S, paid the block before: the room is R - S.
        {
            const NoteVerdict v = fnVerdict(0, ClockAtHeight(H - 1), R);
            BOOST_CHECK_MESSAGE(v.strReason == cap.strReason, "S1X-6 (" + strCap + "): a MINT of the full room " +
                                std::to_string(R) + " was accepted past the cap while the house owes a live " +
                                std::to_string(S) + " mg swap shortfall that MaterializeInsolvency would count (went on "
                                "to: " + (v.strReason.empty() ? std::string("accepted") : v.strReason) + ")");
            BOOST_CHECK_MESSAGE(fnVerdict(0, ClockAtHeight(H - 1), R - S).strReason != cap.strReason, "S1X-6 (" + strCap +
                                "): a MINT of R - S was refused at the cap: the shortfall took more than its own room");
        }
        // (d) the same shortfall, paid just past the 90-day lapse: no longer a claim, the room is back.
        BOOST_CHECK_MESSAGE(fnVerdict(0, ClockAtHeight(H) - nLapse - 1, R).strReason != cap.strReason, "S1X-6 (" + strCap +
                            "): a MINT of R was refused after the shortfall lapsed");
    }
}

// S1X-5 (security 2026-11-23: Medium).
// MaterializeInsolvency freezes the house's pending swaps into nInsolventUnits at the FIRST waterfall op; a swap still
// pending then can be DONE afterwards (the holder reveals s), and its share of the pot is then claimed by nobody. The
// agreed gate (security's shape, freebankd 2026-11-24): before MaterializeInsolvency at each of the six snapshot sites,
// refuse with a reason ending "-swaps-pending", ban score 0, unless the house's pending swaps are 0 or
// ClockSince(E, h) > ceil(nSwapDeadlineSecs / 600), E = the failure height.
// Every case uses a house that failed by the stress path and was never materialized (status still Open), so the op
// under test IS the first waterfall op. Another holder's swap was opened at O = E - 10, its deadline O x 600 s +
// nSwapDeadlineSecs + 234 s (not a multiple of 600 s); the chain clock's active time at height h is h x 600 s.
// Only what both designs (the swap's own deadline; E + the full deadline) agree on is asserted:
//   (1) h1 = the last height whose active time is below that swap's deadline: refused "-swaps-pending", score 0 - FAILS
//       on master 71b3558 (the op reaches the later gate);
//   (2) h2 with ClockSince(E, h2) = ceil(nSwapDeadlineSecs / 600) + 1, the swap still pending: the same verdict as with
//       no swap at all (the gate is open);
//   (3) h1 with the swap settled DONE (nothing pending): the same verdict as with no swap at all.
// Each fixture's later verdict is a stray escrow output (the first check after the snapshot), so it doesn't depend on
// the pending amount the snapshot counts.
// This replaces testing/s1x-5 182df99's case, whose swap deadline sat past E + 72 h (no real swap opened before the
// failure can) and whose house was already materialized.
// ---------------------------------------------------------------------------
namespace {
struct S1X5Timeline {
    uint32_t E, O, h1, h2;
    int64_t nDeadline;
    explicit S1X5Timeline(uint32_t nE)
    {
        const uint32_t D = Params().GetConsensus().GramAt((int)nE).nSwapDeadlineSecs;
        E = nE;
        O = nE - 10;
        nDeadline = (int64_t)O * 600 + D + 234;
        h1 = (uint32_t)((nDeadline - 1) / 600);   // the last height whose active time (h x 600) is below the deadline
        h2 = nE + (D + 599) / 600 + 1;            // ClockSince(E, h2) = ceil(D / 600) + 1
    }
};

// What the checks read at height h: the chain clock, and (nSwap 1) another holder's swap pending, or (nSwap 2) the same
// swap settled DONE at h. nSwap 0: no swap.
void S1X5Units(CUnitsView& units, uint32_t nHouseID, const S1X5Timeline& t, int h, int nSwap)
{
    CChainClock clock;
    clock.nHeight = (uint32_t)(h - 1);
    clock.nMonoTime = clock.nActiveTime = (int64_t)h * 600;
    units.Put(ChainClockKey(), clock);
    if (nSwap == 0)
        return;
    const uint256 hashLock = uint256S("5150");
    CSwapRecord rec;
    rec.nHouseID = nHouseID;
    rec.nUnits = 20000;
    rec.nBid0 = 1000;
    rec.nDemandHeight = t.O;
    rec.nDeadlineActive = t.nDeadline;
    rec.vchPayoutScript = ParseHex("76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac");
    SwapOpen(units, hashLock, rec);
    if (nSwap == 2)
        SwapSettle(units, hashLock, SWAP_DONE, 0, (int64_t)h * 600, h, 12960);
}

// The stress-path failure of token_tests' FailedHouse, kept unmaterialized.
CHouse S1X5FailedHouse(uint32_t nHouseID)
{
    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "s1x5";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 100;
    house.nLastAttestHeight = 200;
    house.nStressSinceHeight = 200 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1;   // stored origin, as FailedHouse
    house.amountLastAttestReserves = 100 * COIN;
    house.nMintedUnits = 100000;
    HousePartner pt;
    pt.vchPubKey = std::vector<unsigned char>(33, 0x02);
    pt.amountPledge = 10 * COIN;
    pt.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(pt);
    return house;
}

bool S1X5EndsPending(const std::string& s)
{
    static const std::string suffix = "-swaps-pending";
    return s.size() > suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}
} // namespace

BOOST_AUTO_TEST_CASE(s1x_5_note_claim_waits_for_swaps_pending_at_the_failure)
{
    BOOST_REQUIRE(g_fClockIsHeightForTests);
    const CHouse house = S1X5FailedHouse(1);
    const uint32_t E = HouseInsolventSince(house, 1000000);
    BOOST_REQUIRE(E > 20);
    BOOST_REQUIRE_EQUAL(house.status, HOUSE_STATUS_OPEN);   // never materialized: this claim is the first waterfall op
    const S1X5Timeline t(E);
    BOOST_REQUIRE(t.h1 >= E && (int64_t)t.h1 * 600 < t.nDeadline && (int64_t)(t.h1 + 1) * 600 >= t.nDeadline);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)t.h1), HOUSE_STATUS_INSOLVENT);

    // A holder's claim, correctly signed (the sig check comes before the snapshot), with a stray escrow output at vout[0]
    // so that past the snapshot it is refused the same way whatever the snapshot counted.
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    NoteClaim c;
    c.nHouseID = 1;
    c.fEscrowChange = 0;
    c.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_CLAIM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(100, HouseEscrowScript(house.houseID)));
    { CDataStream sC1(SER_NETWORK, PROTOCOL_VERSION); sC1 << c; mtx.vchNotePayload.assign(sC1.begin(), sC1.end()); }   // Stage 0 C1
    BOOST_REQUIRE(key.Sign(NoteClaimSigHash(CTransaction(mtx)), c.vchHolderSig));
    { CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << c; mtx.vchNotePayload.assign(ss.begin(), ss.end()); }

    auto verdict = [&](int h, int nSwap, int& nDoS) {
        CUnitsView units(nullptr);
        S1X5Units(units, 1, t, h, nSwap);
        UnitsCheckScope scope(&units);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 1) { out = house; return true; } return false; };
        auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
        auto fnNoBlock = [](uint32_t, uint256&) { return false; };
        CValidationState state; CHouse houseOut; bool fChanged = false;
        CheckNoteOperation(CTransaction(mtx), state, h, 100, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock, houseOut, fChanged);
        nDoS = 0;
        state.IsInvalid(nDoS);
        return state.GetRejectReason();
    };
    int nDoS = 0, nUnused = 0;
    const std::string strControl1 = verdict((int)t.h1, 0, nUnused), strControl2 = verdict((int)t.h2, 0, nUnused);
    BOOST_REQUIRE_MESSAGE(!S1X5EndsPending(strControl1) && !S1X5EndsPending(strControl2),
                          "S1X-5 setup: with no swap at all the claim was held: " + strControl1 + " / " + strControl2);
    const std::string strHeld = verdict((int)t.h1, 1, nDoS);
    BOOST_CHECK_MESSAGE(S1X5EndsPending(strHeld), "S1X-5 note CLAIM: the first waterfall claim passed the snapshot while "
                        "a swap opened before the failure could still be DONE (height " + std::to_string(t.h1) +
                        ", " + std::to_string(t.h1 - E) + " blocks after the failure): got '" + strHeld + "'");
    if (S1X5EndsPending(strHeld))
        BOOST_CHECK_MESSAGE(nDoS == 0, "S1X-5 note CLAIM: the hold scores " << nDoS << ", want 0 (it is time, not malice)");
    BOOST_CHECK_EQUAL(verdict((int)t.h2, 1, nUnused), strControl2);   // E + the full deadline: the gate is open
    BOOST_CHECK_EQUAL(verdict((int)t.h1, 2, nUnused), strControl1);   // the swap DONE: nothing pending, open
}

BOOST_AUTO_TEST_CASE(s1x_5_swap_claim_waits_for_swaps_pending_at_the_failure)
{
    // The claimant's own swap was paid short within the lapse before the failure (a shortfall claim), so it is not
    // pending; ANOTHER holder's swap is (as above). SWAP_CLAIM needs no signature; vout[0] is a stray escrow output.
    BOOST_REQUIRE(g_fClockIsHeightForTests);
    const CHouse house = S1X5FailedHouse(1);
    const uint32_t E = HouseInsolventSince(house, 1000000);
    BOOST_REQUIRE(E > 700);   // the claimant's swap opened 600 blocks before the failure
    const S1X5Timeline t(E);
    BOOST_REQUIRE(t.h1 >= E && (int64_t)t.h1 * 600 < t.nDeadline);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)t.h1), HOUSE_STATUS_INSOLVENT);

    const uint256 hashMine = uint256S("a11ce");
    CSwapRecord mine;
    mine.nHouseID = 1;
    mine.nUnits = 30000;
    mine.nBid0 = 1000;
    mine.nDemandHeight = E - 600;
    mine.nDeadlineActive = (int64_t)(E - 600) * 600 + 259200;
    mine.vchPayoutScript = ParseHex("76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac");
    mine.nStatus = SWAP_PAID;
    mine.nShortfallMg = 5000;
    mine.nSettleClock = (int64_t)E - 5;   // within the lapse before E (the height clock)
    mine.nSettleTime = (int64_t)(E - 5) * 600;

    NoteSwapClaim c;
    c.nHouseID = 1;
    c.hashLock = hashMine;
    c.fEscrowChange = 0;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_SWAP_CLAIM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("02"), 0)));
    mtx.vout.push_back(CTxOut(100, HouseEscrowScript(house.houseID)));
    { CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << c; mtx.vchNotePayload.assign(ss.begin(), ss.end()); }

    auto verdict = [&](int h, int nSwap, int& nDoS) {
        CUnitsView units(nullptr);
        S1X5Units(units, 1, t, h, nSwap);
        units.Put(SwapKey(hashMine), mine);   // not added to pending: a paid swap left it at SwapSettle
        UnitsCheckScope scope(&units);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 1) { out = house; return true; } return false; };
        auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
        auto fnNoBlock = [](uint32_t, uint256&) { return false; };
        CValidationState state; CHouse houseOut; bool fChanged = false;
        CheckNoteOperation(CTransaction(mtx), state, h, 0, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock, houseOut, fChanged);
        nDoS = 0;
        state.IsInvalid(nDoS);
        return state.GetRejectReason();
    };
    int nDoS = 0, nUnused = 0;
    const std::string strControl1 = verdict((int)t.h1, 0, nUnused), strControl2 = verdict((int)t.h2, 0, nUnused);
    BOOST_REQUIRE_MESSAGE(!S1X5EndsPending(strControl1) && !S1X5EndsPending(strControl2),
                          "S1X-5 setup: with no other swap the SWAP_CLAIM was held: " + strControl1 + " / " + strControl2);
    BOOST_REQUIRE_MESSAGE(strControl1.find("swap-claim-lapsed") == std::string::npos &&
                          strControl1.find("swap-unknown") == std::string::npos &&
                          strControl1.find("not-insolvent") == std::string::npos,
                          "S1X-5 setup: the SWAP_CLAIM stopped before the snapshot site: " + strControl1);
    const std::string strHeld = verdict((int)t.h1, 1, nDoS);
    BOOST_CHECK_MESSAGE(S1X5EndsPending(strHeld), "S1X-5 SWAP_CLAIM: the first waterfall op passed the snapshot while "
                        "another swap opened before the failure could still be DONE: got '" + strHeld + "'");
    if (S1X5EndsPending(strHeld))
        BOOST_CHECK_MESSAGE(nDoS == 0, "S1X-5 SWAP_CLAIM: the hold scores " << nDoS << ", want 0");
    BOOST_CHECK_EQUAL(verdict((int)t.h2, 1, nUnused), strControl2);
    BOOST_CHECK_EQUAL(verdict((int)t.h1, 2, nUnused), strControl1);
}

BOOST_AUTO_TEST_SUITE_END()

