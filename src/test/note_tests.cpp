// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>   // BillHashOutputs - the outputs-hash every note sighash binds
#include <note.h>

#include <house.h>

#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <utilstrencodings.h>
#include <version.h>

#include <functional>

#include <boost/test/unit_test.hpp>

// Contextual note-op validator (validation.cpp, external linkage; not in a
// public header). Forward-declared so the negative direction of the 3.5 note
// guards can be exercised directly (R-i6 test-quality fixes).
bool CheckNoteOperation(const CTransaction& tx, CValidationState& state, int nHeight, uint64_t nNoteUnitsIn,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CHouse& houseOut, bool& fHouseChanged);

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
static CMutableTransaction MakeMintTx(uint32_t nHouseID, uint64_t units, uint32_t nAsOfHeight = 0)
{
    CKey keyHolder;
    std::vector<unsigned char> pubHolder = FreshPubKey(keyHolder);

    NoteMint mint;
    mint.nHouseID = nHouseID;
    mint.vUnits.push_back(units);
    mint.nAsOfHeight = nAsOfHeight;
    mint.vApproverIndex.push_back(0);
    mint.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_MINT;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mint;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pubHolder)));
    return mtx;
}

BOOST_AUTO_TEST_CASE(note_sighash_domain_separation)
{
    std::vector<uint64_t> u{100, 50};
    const uint256 outs = uint256S("aa");
    const uint256 prev = uint256S("dd");
    std::vector<uint256> v;
    v.push_back(NoteMintSigHash(1, u, prev, outs));
    v.push_back(NoteTransferSigHash(1, u, outs));
    v.push_back(NoteRedeemSigHash(1, 150, outs));
    for (size_t i = 0; i < v.size(); i++)
        for (size_t j = i + 1; j < v.size(); j++)
            BOOST_CHECK(v[i] != v[j]);

    // Sensitive to every bound field, including the input set (replay guard)
    BOOST_CHECK(NoteMintSigHash(1, u, prev, outs) != NoteMintSigHash(2, u, prev, outs));
    BOOST_CHECK(NoteMintSigHash(1, u, prev, outs) != NoteMintSigHash(1, {100, 51}, prev, outs));
    BOOST_CHECK(NoteMintSigHash(1, u, prev, outs) != NoteMintSigHash(1, u, prev, uint256S("bb")));
    BOOST_CHECK(NoteMintSigHash(1, u, prev, outs) != NoteMintSigHash(1, u, uint256S("ee"), outs));
    BOOST_CHECK(NoteRedeemSigHash(1, 150, outs) != NoteRedeemSigHash(1, 151, outs));
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

    // Reserved bearer op-codes are inert (rejected)
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
    const uint256 sighash = NoteMintSigHash(1, u, prev, outs);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    BOOST_CHECK(key.GetPubKey().Verify(sighash, sig));
    BOOST_CHECK(!key.GetPubKey().Verify(NoteMintSigHash(1, {101}, prev, outs), sig));
    BOOST_CHECK(!key.GetPubKey().Verify(NoteMintSigHash(1, u, prev, uint256S("bb")), sig));
    BOOST_CHECK(!key.GetPubKey().Verify(NoteMintSigHash(2, u, prev, outs), sig));
    // Different input set (hashPrevouts) breaks the sig -> mint replay defeated
    BOOST_CHECK(!key.GetPubKey().Verify(NoteMintSigHash(1, u, uint256S("ee"), outs), sig));
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
    // The demand sighash is its own domain and binds units + outputs
    const uint256 outs = uint256S("aa");
    BOOST_CHECK(NoteDemandSigHash(1, {1000}, outs) != NoteRedeemSigHash(1, 1000, outs));
    BOOST_CHECK(NoteDemandSigHash(1, {1000}, outs) != NoteDemandSigHash(2, {1000}, outs));
    BOOST_CHECK(NoteDemandSigHash(1, {1000}, outs) != NoteDemandSigHash(1, {1001}, outs));
    BOOST_CHECK(NoteDemandSigHash(1, {1000}, outs) != NoteDemandSigHash(1, {1000}, uint256S("bb")));
}

BOOST_AUTO_TEST_CASE(note_claim_entitlement_math)
{
    // min(U, floor(U*pot/units)) with a 128-bit intermediate (D5).
    // Under-collateralized: pot 100, units 1000 -> 10% recovery
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(500, 100, 1000), 50);
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(1000, 100, 1000), 100);   // full burn takes the pot
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(1, 100, 1000), 0);        // floor dust
    // Over-collateralized: par cap, never more than U
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(500, 5000, 1000), 500);
    // Exactly collateralized
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(250, 1000, 1000), 250);
    // Degenerate inputs
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(0, 100, 1000), 0);
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(500, 0, 1000), 0);
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(500, 100, 0), 0);
    // The uint64-overflow regime the 128-bit path exists for: U and pot near
    // the money bounds (product ~2^104)
    const uint64_t bigU = (uint64_t)MAX_MONEY * 3;                    // lambda-max units
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(bigU, MAX_MONEY, bigU), MAX_MONEY);
    BOOST_CHECK_EQUAL(NoteClaimEntitlement(bigU / 3, MAX_MONEY, bigU), MAX_MONEY / 3);
    // Sum of split claims never exceeds the pot (floor rounds down)
    {
        const CAmount pot = 999;
        const uint64_t units = 1000;
        CAmount paid = 0;
        for (int i = 0; i < 10; i++)
            paid += NoteClaimEntitlement(100, pot, units);
        BOOST_CHECK(paid <= pot);
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
    // Claim sighash: distinct domain from redeem; binds house, U, outputs
    const uint256 outs = uint256S("aa");
    BOOST_CHECK(NoteClaimSigHash(1, 150, outs) != NoteRedeemSigHash(1, 150, outs));
    BOOST_CHECK(NoteClaimSigHash(1, 150, outs) != NoteClaimSigHash(2, 150, outs));
    BOOST_CHECK(NoteClaimSigHash(1, 150, outs) != NoteClaimSigHash(1, 151, outs));
    BOOST_CHECK(NoteClaimSigHash(1, 150, outs) != NoteClaimSigHash(1, 150, uint256S("bb")));
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
    // Reserved bearer ops still rejected; op range now ends at CLAIM
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
    BOOST_REQUIRE(keyHolder.Sign(NoteRedeemSigHash(1, 100, BillHashOutputs(mtx)), redeem.vchHolderSig));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());

    auto fnNoBlock = [](uint32_t, uint256&) { return false; };
    CValidationState state; CHouse houseOut; bool fChanged = false;
    BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1600, 100, fnGetHouse, fnNoCoin, fnNoCoin, fnNoBlock, houseOut, fChanged));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-redeem-deferred");
}

BOOST_AUTO_TEST_CASE(note_mint_rho_liveness_gate)
{
    // R-i7 (DR-1): the reserve cap is the reserves PROVEN LIVE in the mint, not a
    // stored snapshot. An Open, well-capitalised house with an EMPTY reserve
    // proof proves zero reserves -> cap 0 -> any mint is under-reserved. This is
    // the mint-side of the DR-1 fix: a house cannot mint against reserves it did
    // not prove it currently holds.
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
    p.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p.amountPledge = 100 * COIN;                 // ample capital cap
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);

    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1000), HOUSE_STATUS_OPEN);

    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 5) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    auto fnBlock = [](uint32_t, uint256& h) { h = uint256S("beef"); return true; };

    // Fresh as-of, empty proof -> proven reserves 0 -> under-reserved (not stale).
    {
        CMutableTransaction mtx = MakeMintTx(5, 100, /*nAsOfHeight=*/999);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1000, 0, fnGetHouse, fnNoCoin, fnNoCoin, fnBlock, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-mint-under-reserved");
    }
    // A future as-of height is refused before the proof is even examined.
    {
        CMutableTransaction mtx = MakeMintTx(5, 100, /*nAsOfHeight=*/1000);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1000, 0, fnGetHouse, fnNoCoin, fnNoCoin, fnBlock, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-mint-reserve-future");
    }
    // A stale as-of height (older than the staleness window) is refused too.
    {
        CMutableTransaction mtx = MakeMintTx(5, 100, /*nAsOfHeight=*/100);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckNoteOperation(CTransaction(mtx), state, 1000, 0, fnGetHouse, fnNoCoin, fnNoCoin, fnBlock, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-note-mint-reserve-stale");
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

    keyHolder.Sign(NoteRedeemSigHash(nHouseID, nUnits, BillHashOutputs(mtx)), redeem.vchHolderSig);
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

BOOST_AUTO_TEST_SUITE_END()
