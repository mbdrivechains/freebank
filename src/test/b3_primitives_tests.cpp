// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// B3 T-b1 — BEARER PAR-REDEMPTION PRIMITIVES.
// Sheet: docs-local/B3_BEARER_REDEMPTION_PROPOSAL.md rev 4 (signed 2026-08-04).
//
// This increment adds NO behaviour: payload shapes, two digests, a coin-tag
// mask, and CHouse v9. What it must prove is that none of it can silently
// corrupt what already exists — the T-d1 discipline, where the load-bearing
// case is the LEGACY record round-trip, not the happy path.

#include <bill.h>
#include <house.h>
#include <note.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <utilstrencodings.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(b3_primitives_tests, BasicTestingSetup)

namespace {

template <typename T>
std::vector<unsigned char> Ser(const T& obj)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << obj;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

template <typename T>
bool Deser(const std::vector<unsigned char>& vch, T& out)
{
    try {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> out;
        // Trailing bytes are a REJECT, not slack: a payload that decodes with
        // remainder is a second encoding of the same object, and consensus
        // records must have exactly one.
        return ss.empty();
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<unsigned char> Bytes(const char* hex) { return ParseHex(hex); }

} // namespace

// ---------------------------------------------------------------- the mask
// D-i (signed): the pre-auth marker is the HIGH BIT of the coin's
// nDemandHeight, chosen so the Coin serialization is untouched and no datadir
// needs a -reindex. The whole safety of that choice rests on the mask helpers
// being exact at the boundaries.
BOOST_AUTO_TEST_CASE(preauth_mask_boundaries)
{
    // plain heights round-trip and are never mistaken for pre-auth. The
    // ceiling is 2^30 - 1 since T-b3: the PROTESTED marker took bit 30, so
    // NoteDemandHeightOf masks BOTH tag bits (this test's first revision
    // asserted the one-bit 2^31 ceiling and correctly failed on the widening).
    const uint32_t plains[] = {0u, 1u, 2u, 1008u, 160000u, 0x3FFFFFFEu, 0x3FFFFFFFu};
    for (uint32_t h : plains) {
        BOOST_CHECK(!NoteDemandIsPreAuth(h));
        BOOST_CHECK(!NoteDemandIsProtested(h));
        BOOST_CHECK_EQUAL(NoteDemandHeightOf(h), h);
        BOOST_CHECK_EQUAL(NoteDemandTag(h, false), h);
        const uint32_t tag = NoteDemandTag(h, true);
        BOOST_CHECK(NoteDemandIsPreAuth(tag));
        BOOST_CHECK(!NoteDemandIsProtested(tag));        // pre-auth alone is not protested
        BOOST_CHECK_EQUAL(NoteDemandHeightOf(tag), h);   // the height survives tagging
        // ...and survives the protest marker on top (the PROTEST re-issue tag)
        const uint32_t marked = tag | NOTE_DEMAND_PROTESTED_BIT;
        BOOST_CHECK(NoteDemandIsPreAuth(marked));
        BOOST_CHECK(NoteDemandIsProtested(marked));
        BOOST_CHECK_EQUAL(NoteDemandHeightOf(marked), h);
    }
    // the bits themselves
    BOOST_CHECK_EQUAL(NOTE_DEMAND_PREAUTH_BIT, 0x80000000u);
    BOOST_CHECK_EQUAL(NOTE_DEMAND_PROTESTED_BIT, 0x40000000u);
    BOOST_CHECK_EQUAL(NOTE_DEMAND_TAG_BITS, 0xC0000000u);
    BOOST_CHECK(NoteDemandIsPreAuth(0x80000000u));
    BOOST_CHECK_EQUAL(NoteDemandHeightOf(0x80000000u), 0u);
    // UNDEMANDED must stay undemanded under both readings: 0 is the sentinel
    // every existing site keys on ("coin.nDemandHeight != 0"), so a pre-auth
    // tag at height 0 must still read as demanded.
    BOOST_CHECK_EQUAL(NoteDemandTag(0, false), 0u);
    BOOST_CHECK(NoteDemandTag(0, true) != 0u);
    // the usable height range is not narrowed in any way that matters: the
    // largest plain height is ~1.07bn blocks, ~20k years at 10 minutes.
    BOOST_CHECK_EQUAL(NoteDemandHeightOf(NoteDemandTag(0x3FFFFFFFu, true)), 0x3FFFFFFFu);
}

// ------------------------------------------------------------- the digests
BOOST_AUTO_TEST_CASE(preauth_and_protest_digests_are_domain_separated)
{
    const uint32_t H = 3;
    std::vector<uint64_t> vUnits;
    vUnits.push_back(1000);
    vUnits.push_back(2500);
    const std::vector<unsigned char> script = Bytes("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
    const uint256 outs = uint256S("beef");

    const uint256 demand  = NoteDemandSigHash(H, vUnits, outs);
    const uint256 preauth = NotePreAuthSigHash(H, vUnits, script);
    const uint256 protest = NoteProtestSigHash(H, vUnits, outs);

    // THE POINT: a pre-auth signature must not be replayable as a demand
    // signature or vice versa. They authorise different things - one a
    // re-issue, one a payout the holder will not be present to sign - so a
    // shared digest would let one be lifted into the other's slot.
    BOOST_CHECK(demand != preauth);
    BOOST_CHECK(demand != protest);
    BOOST_CHECK(preauth != protest);

    // every input is bound
    BOOST_CHECK(preauth != NotePreAuthSigHash(H + 1, vUnits, script));
    std::vector<uint64_t> vOther;
    vOther.push_back(1000);
    vOther.push_back(2501);
    BOOST_CHECK(preauth != NotePreAuthSigHash(H, vOther, script));
    BOOST_CHECK(preauth != NotePreAuthSigHash(H, vUnits, Bytes("76a900")));
    // and it does NOT bind hashOutputs - by design: the discharge that
    // satisfies it does not exist when this is signed. Pinning the SCRIPT is
    // what makes a unilateral discharge possible at all.
    BOOST_CHECK_EQUAL(preauth.ToString(), NotePreAuthSigHash(H, vUnits, script).ToString());
    // protest binds outputs (it is an ordinary same-tx authorisation)
    BOOST_CHECK(protest != NoteProtestSigHash(H, vUnits, uint256S("dead")));
}

// --------------------------------------------------------------- payloads
BOOST_AUTO_TEST_CASE(demand_payload_roundtrip_both_modes)
{
    for (int mode = 0; mode < 2; mode++) {
        NoteDemand d;
        d.nHouseID = 7;
        d.vUnits.push_back(500);
        d.vchHolderPubKey = Bytes("02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
        d.vchHolderSig = Bytes("3044deadbeef");
        d.fPreAuth = (uint8_t)mode;
        if (mode) {
            d.vchPayoutScript = Bytes("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
            d.vchPreAuthSig = Bytes("3045cafebabe");
        }
        const std::vector<unsigned char> vch = Ser(d);
        NoteDemand back;
        BOOST_REQUIRE(Deser(vch, back));
        BOOST_CHECK_EQUAL(back.nHouseID, d.nHouseID);
        BOOST_CHECK(back.vUnits == d.vUnits);
        BOOST_CHECK(back.vchHolderPubKey == d.vchHolderPubKey);
        BOOST_CHECK(back.vchHolderSig == d.vchHolderSig);
        BOOST_CHECK_EQUAL(back.fPreAuth, d.fPreAuth);
        BOOST_CHECK(back.vchPayoutScript == d.vchPayoutScript);
        BOOST_CHECK(back.vchPreAuthSig == d.vchPreAuthSig);
        BOOST_CHECK(Ser(back) == vch);            // canonical: re-encode is byte-identical

        std::vector<unsigned char> trailing = vch;
        trailing.push_back(0x00);
        NoteDemand junk;
        BOOST_CHECK(!Deser(trailing, junk));      // trailing byte rejected
    }
}

BOOST_AUTO_TEST_CASE(protest_payload_roundtrip_and_priors)
{
    NoteProtest p;
    p.nHouseID = 11;
    p.vUnits.push_back(4200);
    p.vUnits.push_back(1);
    p.vchHolderPubKey = Bytes("03112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00");
    p.vchHolderSig = Bytes("3045feedface");
    p.nPrevProtestOpen = 2;
    p.nPrevProtestHeight = 90210;
    p.nPrevProtestDemandHeight = 90000;

    const std::vector<unsigned char> vch = Ser(p);
    NoteProtest back;
    BOOST_REQUIRE(Deser(vch, back));
    BOOST_CHECK_EQUAL(back.nHouseID, p.nHouseID);
    BOOST_CHECK(back.vUnits == p.vUnits);
    // The priors are the whole undo contract: a protest that cannot restore the
    // exact prior counter is a reorg that silently changes the insolvency clock.
    BOOST_CHECK_EQUAL(back.nPrevProtestOpen, p.nPrevProtestOpen);
    BOOST_CHECK_EQUAL(back.nPrevProtestHeight, p.nPrevProtestHeight);
    BOOST_CHECK_EQUAL(back.nPrevProtestDemandHeight, p.nPrevProtestDemandHeight);
    BOOST_CHECK(Ser(back) == vch);

    std::vector<unsigned char> trailing = vch;
    trailing.push_back(0xff);
    NoteProtest junk;
    BOOST_CHECK(!Deser(trailing, junk));
}

// --------------------------------------------------------- CHouse v8 -> v9
// THE LOAD-BEARING CASE (T-d1 idiom): a record written by the CURRENT shipped
// binary must read back on the new one, and re-serialize byte-identically once
// the new fields are at their defaults. If this fails, every house record on
// every live datadir is corrupted by the upgrade.
BOOST_AUTO_TEST_CASE(chouse_v9_reads_v8_and_rewrites_byte_identical)
{
    CHouse h;
    h.nHouseID = 4;
    h.houseID = uint256S("f00d");
    h.nTier = HOUSE_TIER_MULTI_PARTNER;
    h.nThresholdM = 1;
    h.status = HOUSE_STATUS_OPEN;
    h.nRegisteredHeight = 1000;
    h.nLastAttestHeight = 2000;
    h.amountLastAttestReserves = 100 * COIN;
    h.nMintedUnits = 12345;
    h.nLoanBookFace = 6789;
    h.nLoanWtMatHi = 0;
    h.nLoanWtMatLo = 42;
    HousePartner p;
    p.vchPubKey = Bytes("02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    p.amountPledge = 50 * COIN;
    p.status = HOUSE_PARTNER_ACTIVE;
    h.vPartner.push_back(p);

    // Fresh v9 record with protest state at defaults.
    BOOST_CHECK_EQUAL(h.nProtestOpen, 0u);
    BOOST_CHECK_EQUAL(h.nProtestHeight, 0u);
    BOOST_CHECK_EQUAL(h.nProtestDemandHeight, 0u);
    BOOST_CHECK(!h.ProtestLive());

    const std::vector<unsigned char> v9 = Ser(h);
    CHouse back;
    BOOST_REQUIRE(Deser(v9, back));
    BOOST_CHECK_EQUAL(back.nProtestOpen, 0u);
    BOOST_CHECK(Ser(back) == v9);

    // Now the real test: hand-build a V8 record (version byte 8, and the three
    // protest fields simply ABSENT) and prove it reads with defaults.
    std::vector<unsigned char> v8 = v9;
    BOOST_REQUIRE(!v8.empty());
    BOOST_REQUIRE_EQUAL(v8[0], (unsigned char)HOUSE_SER_VERSION);   // version leads
    v8[0] = 8;
    BOOST_REQUIRE(v8.size() >= 12);
    v8.resize(v8.size() - 12);           // drop the three trailing uint32s
    CHouse fromV8;
    BOOST_REQUIRE(Deser(v8, fromV8));
    BOOST_CHECK_EQUAL(fromV8.nProtestOpen, 0u);
    BOOST_CHECK_EQUAL(fromV8.nProtestHeight, 0u);
    BOOST_CHECK_EQUAL(fromV8.nProtestDemandHeight, 0u);
    // everything the v8 record DID carry survives untouched
    BOOST_CHECK_EQUAL(fromV8.nHouseID, h.nHouseID);
    BOOST_CHECK_EQUAL(fromV8.nMintedUnits, h.nMintedUnits);
    BOOST_CHECK_EQUAL(fromV8.nLoanBookFace, h.nLoanBookFace);
    BOOST_CHECK_EQUAL(fromV8.nLoanWtMatLo, h.nLoanWtMatLo);
    BOOST_CHECK_EQUAL(fromV8.vPartner.size(), 1u);
    // and a v8 record re-serializes AS V9 with the defaults appended - the
    // upgrade is one-way and lossless, never a silent truncation.
    BOOST_CHECK(Ser(fromV8) == v9);
}

BOOST_AUTO_TEST_CASE(chouse_v9_protest_state_roundtrips)
{
    CHouse h;
    h.nHouseID = 9;
    h.houseID = uint256S("cafe");
    h.nProtestOpen = 3;
    h.nProtestHeight = 555000;
    h.nProtestDemandHeight = 554000;
    BOOST_CHECK(h.ProtestLive());

    CHouse back;
    BOOST_REQUIRE(Deser(Ser(h), back));
    BOOST_CHECK_EQUAL(back.nProtestOpen, 3u);
    BOOST_CHECK_EQUAL(back.nProtestHeight, 555000u);
    BOOST_CHECK_EQUAL(back.nProtestDemandHeight, 554000u);
    BOOST_CHECK(back.ProtestLive());
    BOOST_CHECK(Ser(back) == Ser(h));

    // counter semantics at the boundary: the LAST decrement is what clears the
    // origin, and nothing else may. (The transition itself is T-b4's; here we
    // only pin that the predicate is the counter and not the height.)
    back.nProtestOpen = 1;
    BOOST_CHECK(back.ProtestLive());
    back.nProtestOpen = 0;
    BOOST_CHECK(!back.ProtestLive());
    BOOST_CHECK(back.nProtestHeight != 0);   // height may linger; LIVENESS is the counter
}

// ------------------------------------------------------------- the window
BOOST_AUTO_TEST_CASE(demand_window_is_a_consensus_param_per_network)
{
    // D-ii (signed): 1008 main / 12 regtest, and it lives in Consensus::Params
    // because settle.h:54 warns the extern-plus-CLI pattern used by
    // HOUSE_ATTEST_CADENCE is a fork hazard. A test that reads it from the
    // params is also the cheapest guard against someone "helpfully" adding a
    // -demandwindow knob later.
    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(Params().GetConsensus().nDemandWindow, 1008u);
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().GetConsensus().nDemandWindow, 12u);
    BOOST_CHECK(Params().GetConsensus().nDemandWindow > 0);
}

// ============================ T-b2: SHAPE LAYER ============================
// CheckNoteTransactionShape is context-free (no house record, no coins), so
// these are the cheapest possible rejections and the ones an attacker hits
// first. Every vector below is a payload a peer could relay.

// (CheckNoteTransactionShape is declared in note.h)

namespace {

CMutableTransaction NoteTx(uint8_t op)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = op;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0001"), 0)));
    return mtx;
}

void SetNotePayload(CMutableTransaction& mtx, const NoteDemand& d)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << d;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
}
void SetNotePayload(CMutableTransaction& mtx, const NoteProtest& p)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << p;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
}

// A well-formed re-issue output set: dust P2PKH per unit entry.
void AddNoteOutputs(CMutableTransaction& mtx, size_t n)
{
    const std::vector<unsigned char> pk(33, 0x02);
    for (size_t i = 0; i < n; i++)
        mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(pk)));
}

// T-b3: a pre-auth re-issue (DEMAND with fPreAuth, PROTEST) moves the coins
// onto the consensus-custody script - shape requires custody-SHAPED there.
void AddNoteCustodyOutputs(CMutableTransaction& mtx, size_t n)
{
    const std::vector<unsigned char> pk(33, 0x02);
    for (size_t i = 0; i < n; i++)
        mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NotePreAuthScript(pk)));
}

NoteDemand BaseDemand(bool fPreAuth)
{
    NoteDemand d;
    d.nHouseID = 3;
    d.vUnits.push_back(1000);
    d.vchHolderPubKey = std::vector<unsigned char>(33, 0x02);
    d.vchHolderSig = std::vector<unsigned char>(70, 0x30);
    d.fPreAuth = fPreAuth ? 1 : 0;
    if (fPreAuth) {
        d.vchPayoutScript = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
        d.vchPreAuthSig = std::vector<unsigned char>(70, 0x30);
    }
    return d;
}

std::string ShapeReject(const CMutableTransaction& mtx)
{
    CValidationState state;
    if (CheckNoteTransactionShape(CTransaction(mtx), state))
        return "";               // accepted
    return state.GetRejectReason();
}

} // namespace

BOOST_AUTO_TEST_CASE(shape_protest_is_in_range_and_reserved_ops_are_not)
{
    // op 8 must now be reachable...
    CMutableTransaction ok = NoteTx(NOTE_OP_PROTEST);
    NoteProtest p;
    p.nHouseID = 3;
    p.vUnits.push_back(1000);
    p.vchHolderPubKey = std::vector<unsigned char>(33, 0x02);
    p.vchHolderSig = std::vector<unsigned char>(70, 0x30);
    SetNotePayload(ok, p);
    AddNoteCustodyOutputs(ok, 1);
    BOOST_CHECK_EQUAL(ShapeReject(ok), "");

    // ...without opening the reserved v1.5 bearer codes, which stay inert
    for (uint8_t op : {NOTE_OP_LOCK, NOTE_OP_UNLOCK}) {
        CMutableTransaction bad = NoteTx(op);
        SetNotePayload(bad, p);
        BOOST_CHECK_EQUAL(ShapeReject(bad), "bad-note-op-reserved");
    }
    // and 9 is still out of range - widening the ceiling must not widen it twice
    CMutableTransaction nine = NoteTx(9);
    SetNotePayload(nine, p);
    BOOST_CHECK_EQUAL(ShapeReject(nine), "bad-note-op");
}

BOOST_AUTO_TEST_CASE(shape_preauth_fields_are_all_or_nothing)
{
    // plain demand: accepted, and must NOT carry pre-auth baggage
    {
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, BaseDemand(false));
        AddNoteOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "");
    }
    // pre-auth demand: accepted with both fields (custody outputs - the
    // holder signed away unilateral control, the coins leave their P2PKH)
    {
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, BaseDemand(true));
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "");
    }
    // and P2PKH outputs on a PRE-AUTH demand are now themselves a shape
    // reject - a pre-auth coin left on the holder's P2PKH could never be
    // discharged (the house cannot produce the holder's scriptSig)
    {
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, BaseDemand(true));
        AddNoteOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-output-script");
    }
    // conversely a custody output on a PLAIN demand is a shape reject too
    {
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, BaseDemand(false));
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-output-script");
    }
    // A STANDING AUTHORISATION CONSENSUS NEVER CHECKS: script present, flag
    // clear. The holder would believe they had pre-authorised a payout; no
    // discharge would ever honour it.
    {
        NoteDemand d = BaseDemand(false);
        d.vchPayoutScript = ParseHex("76a90088ac");
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, d);
        AddNoteOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-demand-preauth-unexpected");
    }
    // A DISCHARGE TARGET THAT CANNOT EXIST: flag set, no script.
    {
        NoteDemand d = BaseDemand(true);
        d.vchPayoutScript.clear();
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, d);
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-demand-preauth-script");
    }
    // flag set, no signature
    {
        NoteDemand d = BaseDemand(true);
        d.vchPreAuthSig.clear();
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, d);
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-demand-preauth-sig");
    }
    // the flag is a BOOLEAN, not a byte: 2 is not "true"
    {
        NoteDemand d = BaseDemand(true);
        d.fPreAuth = 2;
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, d);
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-demand-flag");
    }
    // an unbounded payout script is a per-discharge comparison cost
    {
        NoteDemand d = BaseDemand(true);
        d.vchPayoutScript.assign(MAX_NOTE_PAYOUT_SCRIPT + 1, 0x51);
        CMutableTransaction mtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(mtx, d);
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-demand-preauth-script");
        // exactly at the cap is fine - the boundary is inclusive
        d.vchPayoutScript.assign(MAX_NOTE_PAYOUT_SCRIPT, 0x51);
        CMutableTransaction okmtx = NoteTx(NOTE_OP_DEMAND);
        SetNotePayload(okmtx, d);
        AddNoteCustodyOutputs(okmtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(okmtx), "");
    }
}

BOOST_AUTO_TEST_CASE(shape_protest_rejections)
{
    NoteProtest base;
    base.nHouseID = 3;
    base.vUnits.push_back(1000);
    base.vchHolderPubKey = std::vector<unsigned char>(33, 0x02);
    base.vchHolderSig = std::vector<unsigned char>(70, 0x30);

    {   // TOO FEW outputs for the unit vector is the real boundary: the notes
        // are re-issued, so every unit entry needs its output.
        NoteProtest p = base;
        p.vUnits.push_back(500);                 // 2 units...
        CMutableTransaction mtx = NoteTx(NOTE_OP_PROTEST);
        SetNotePayload(mtx, p);
        AddNoteCustodyOutputs(mtx, 1);           // ...1 output
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-vout-size");
    }
    {   // MORE outputs than units is ACCEPTED, and deliberately so: a note tx
        // funds its own fee, so base-coin change follows the note outputs.
        // AddCoins tags exactly the first vUnits.size() of them, so a trailing
        // dust output is an ordinary payment carrying no note claim - not a
        // smuggled note. (My first cut asserted a rejection here; the code was
        // right and the test was wrong.)
        CMutableTransaction mtx = NoteTx(NOTE_OP_PROTEST);
        SetNotePayload(mtx, base);
        AddNoteCustodyOutputs(mtx, 1);           // the re-issued unit...
        AddNoteOutputs(mtx, 1);                  // ...then ordinary change
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "");
    }
    {   // a bad holder key is not a protest
        NoteProtest p = base;
        p.vchHolderPubKey.assign(33, 0x07);      // invalid prefix
        CMutableTransaction mtx = NoteTx(NOTE_OP_PROTEST);
        SetNotePayload(mtx, p);
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-protest-auth");
    }
    {   // and neither is an unsigned one
        NoteProtest p = base;
        p.vchHolderSig.clear();
        CMutableTransaction mtx = NoteTx(NOTE_OP_PROTEST);
        SetNotePayload(mtx, p);
        AddNoteCustodyOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-protest-auth");
    }
    {   // garbage payload
        CMutableTransaction mtx = NoteTx(NOTE_OP_PROTEST);
        mtx.vchNotePayload = ParseHex("deadbeef");
        AddNoteOutputs(mtx, 1);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-note-protest-payload");
    }
}

BOOST_AUTO_TEST_CASE(upgrade_payload_carries_the_prior_height)
{
    // Δ1b's clock preservation is a PAYLOAD fact, because AddCoins is
    // self-contained (it never reads inputs - that is what makes connect and
    // rollforward tag identically). So the prior height must survive the codec
    // exactly, and a fresh demand must carry zero.
    NoteDemand up = BaseDemand(true);
    up.nPriorDemandHeight = 123456;
    NoteDemand back;
    BOOST_REQUIRE(Deser(Ser(up), back));
    BOOST_CHECK_EQUAL(back.nPriorDemandHeight, 123456u);
    BOOST_CHECK_EQUAL(BaseDemand(false).nPriorDemandHeight, 0u);

    // The tag AddCoins would stamp in each case (the arithmetic, in isolation):
    //   fresh pre-auth at height H -> H | BIT
    //   upgrade of a prior P       -> P | BIT   (H is NOT used)
    const uint32_t H = 900000, P = 123456;
    BOOST_CHECK_EQUAL(NoteDemandTag(H, true), H | NOTE_DEMAND_PREAUTH_BIT);
    BOOST_CHECK_EQUAL(NoteDemandHeightOf(NoteDemandTag(P, true)), P);
    BOOST_CHECK(NoteDemandTag(P, true) != NoteDemandTag(H, true));   // the clock did not move
}

BOOST_AUTO_TEST_CASE(protest_payload_carries_the_tag_unchanged)
{
    NoteProtest p;
    p.nHouseID = 3;
    p.vUnits.push_back(1000);
    p.vchHolderPubKey = std::vector<unsigned char>(33, 0x02);
    p.vchHolderSig = std::vector<unsigned char>(70, 0x30);
    p.nDemandTag = NoteDemandTag(777, true);
    NoteProtest back;
    BOOST_REQUIRE(Deser(Ser(p), back));
    BOOST_CHECK_EQUAL(back.nDemandTag, p.nDemandTag);
    BOOST_CHECK(NoteDemandIsPreAuth(back.nDemandTag));
    BOOST_CHECK_EQUAL(NoteDemandHeightOf(back.nDemandTag), 777u);
}

BOOST_AUTO_TEST_SUITE_END()
