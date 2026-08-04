// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// B3 T-b3 — THE CONTEXTUAL LAYER (sheet rev 4 §10 row 3).
// DEMAND's two status-keyed modes, the pre-auth digest at demand time, the
// unilateral DISCHARGE (signature swap, exact-script payout, the D-iii floor,
// brassage incidence), PROTEST (window edge, priors, counter), and the D-v
// decrement. Every reject is asserted at its exact boundary.
//
// T-b4 (landed): the protest origin is WIRED - a protested house is
// effectively STRESSED from nProtestHeight and INSOLVENT at the window, an
// attestation clears only its own family, and a deferral episode that
// overlapped the protest re-arms the fuse at the recovery stamp. The
// derivation table at the bottom is the sheet's T-b4 gate.

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
// public header) - the note_tests idiom.
bool CheckNoteOperation(const CTransaction& tx, CValidationState& state, int nHeight, uint64_t nNoteUnitsIn,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CHouse& houseOut, bool& fHouseChanged);
// The J2 displacement whitelist (validation.cpp) - pinned structurally below.
bool IsAttestDisplaceable(const CTransaction& mtx);

BOOST_FIXTURE_TEST_SUITE(b3_contextual_tests, BasicTestingSetup)

namespace {

const auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
const auto fnNoBlock = [](uint32_t, uint256&) { return false; };

// A healthy effectively-OPEN house: fresh cadence, fully-reserved (no spread).
CHouse MakeOpenHouse(uint32_t nHouseID, int nHeight, uint64_t nMinted)
{
    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = uint256S("b3c0");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "b3ctx";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nMintedUnits = nMinted;
    house.nLastAttestHeight = (uint32_t)nHeight - 1;
    house.amountLastAttestReserves = (CAmount)nMinted;   // ratio 10000 bps
    return house;
}

std::string CtxReject(const CMutableTransaction& mtx, int nHeight, uint64_t nUnitsIn,
                      const CHouse& house,
                      const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                      CHouse* pHouseOut = nullptr, bool* pfChanged = nullptr)
{
    auto fnGetHouse = [&](uint32_t id, CHouse& out) {
        if (id == house.nHouseID) { out = house; return true; }
        return false;
    };
    CValidationState state; CHouse houseOut; bool fChanged = false;
    const bool fOK = CheckNoteOperation(CTransaction(mtx), state, nHeight, nUnitsIn,
                                        fnGetHouse, fnGetCoin, fnGetCoin, fnNoBlock,
                                        houseOut, fChanged);
    if (pHouseOut) *pHouseOut = houseOut;
    if (pfChanged) *pfChanged = fChanged;
    return fOK ? "" : state.GetRejectReason();
}

// A fully-signed DEMAND. Outputs are built FIRST (custody or P2PKH by mode),
// then both signatures are made over the finished tx - exactly the wallet's
// build order, because both digests are checked at connect.
CMutableTransaction MakeDemandTx(uint32_t nHouseID, uint64_t nUnits, const CKey& keyHolder,
                                 bool fPreAuth, const std::vector<unsigned char>& vchPayoutScript,
                                 bool fCustodyOutputs = true, bool fValidPreAuthSig = true)
{
    const CPubKey pub = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());

    NoteDemand d;
    d.nHouseID = nHouseID;
    d.vUnits.push_back(nUnits);
    d.vchHolderPubKey = vchKey;
    d.fPreAuth = fPreAuth ? 1 : 0;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_DEMAND;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("de3a"), 0)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE,
        (fPreAuth && fCustodyOutputs) ? NotePreAuthScript(vchKey) : NoteScriptForPubKey(vchKey)));

    if (fPreAuth) {
        d.vchPayoutScript = vchPayoutScript;
        keyHolder.Sign(NotePreAuthSigHash(nHouseID, d.vUnits, d.vchPayoutScript), d.vchPreAuthSig);
        if (!fValidPreAuthSig)
            keyHolder.Sign(NotePreAuthSigHash(nHouseID + 1, d.vUnits, d.vchPayoutScript), d.vchPreAuthSig);
    }
    keyHolder.Sign(NoteDemandSigHash(nHouseID, d.vUnits, BillHashOutputs(mtx)), d.vchHolderSig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << d;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

// A DISCHARGE (REDEEM with fPreAuthDischarge): no fresh holder signature -
// the demand-time pre-auth is re-supplied and re-verified. vout[0] pays the
// payout script; vout[1] (optional) the brassage spread to escrow.
CMutableTransaction MakeDischargeTx(uint32_t nHouseID, uint64_t nUnits, const CKey& keyHolder,
                                    const std::vector<unsigned char>& vchPayoutScript,
                                    CAmount amountPayout, CAmount amountSpread,
                                    const uint256& houseID256)
{
    const CPubKey pub = keyHolder.GetPubKey();

    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = amountSpread > 0 ? 1 : 0;
    redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    redeem.fPreAuthDischarge = 1;
    redeem.vPreAuthUnits.push_back(nUnits);
    redeem.vchPayoutScript = vchPayoutScript;
    keyHolder.Sign(NotePreAuthSigHash(nHouseID, redeem.vPreAuthUnits, redeem.vchPayoutScript),
                   redeem.vchPreAuthSig);
    // vchHolderSig stays EMPTY - that is the entire point of the variant.

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("d15c"), 0)));
    mtx.vout.push_back(CTxOut(amountPayout, CScript(vchPayoutScript.begin(), vchPayoutScript.end())));
    if (amountSpread > 0)
        mtx.vout.push_back(CTxOut(amountSpread, HouseEscrowScript(houseID256)));

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

// A PLAIN redeem of nUnits paying amountPayout to the holder's own P2PKH -
// the voluntary path, which must keep working on pre-auth coins.
CMutableTransaction MakePlainRedeemTx(uint32_t nHouseID, uint64_t nUnits, const CKey& keyHolder,
                                      CAmount amountPayout)
{
    const CPubKey pub = keyHolder.GetPubKey();
    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = 0;
    redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("p1a1"), 0)));
    mtx.vout.push_back(CTxOut(amountPayout, NoteScriptForPubKey(redeem.vchHolderPubKey)));

    keyHolder.Sign(NoteRedeemSigHash(nHouseID, nUnits, BillHashOutputs(mtx)), redeem.vchHolderSig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

// A fully-signed PROTEST re-issuing one marked coin. nDemandTag is the OUTPUT
// tag (input | PROTESTED) exactly as tx_verify pins it.
CMutableTransaction MakeProtestTx(uint32_t nHouseID, uint64_t nUnits, const CKey& keyHolder,
                                  uint32_t nDemandTagOut, const CHouse& housePriors,
                                  bool fCustodyOutputs = true)
{
    const CPubKey pub = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());

    NoteProtest p;
    p.nHouseID = nHouseID;
    p.vUnits.push_back(nUnits);
    p.vchHolderPubKey = vchKey;
    p.nDemandTag = nDemandTagOut;
    p.nPrevProtestOpen = housePriors.nProtestOpen;
    p.nPrevProtestHeight = housePriors.nProtestHeight;
    p.nPrevProtestDemandHeight = housePriors.nProtestDemandHeight;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_PROTEST;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("9707"), 0)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE,
        fCustodyOutputs ? NotePreAuthScript(vchKey) : NoteScriptForPubKey(vchKey)));

    keyHolder.Sign(NoteProtestSigHash(nHouseID, p.vUnits, BillHashOutputs(mtx)), p.vchHolderSig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << p;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

// Serve one note coin with the given tag on the given script.
std::function<bool(const COutPoint&, Coin&)> ServeCoin(uint32_t nHouseID, uint64_t nUnits,
                                                       uint32_t nTag, const CScript& script)
{
    return [=](const COutPoint&, Coin& coin) {
        coin = Coin(CTxOut(NOTE_DUST_VALUE, script), 100, false, false, false, 0);
        coin.SetNote(nHouseID, nUnits, nTag);
        return true;
    };
}

} // namespace

// --------------------------------------------------------------- DEMAND
BOOST_AUTO_TEST_CASE(demand_status_matrix)
{
    const int H = 5000;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");

    // DEFERRED: plain accepted (today's semantics), pre-auth FORBIDDEN.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nDeferInvokedHeight = (uint32_t)H - 10;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, false, {}), H, U, house, fnNoCoin), "");
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout), H, U, house, fnNoCoin),
                          "bad-note-demand-preauth-forbidden");
    }
    // OPEN: pre-auth REQUIRED - a plain demand is the old "interest clock the
    // house never agreed to"; the pre-auth demand IS the B3 formal demand.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, false, {}), H, U, house, fnNoCoin),
                          "bad-note-demand-preauth-required");
        bool fChanged = true;
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout), H, U, house,
                                    fnNoCoin, nullptr, &fChanged), "");
        // a demand writes NOTHING onto the house - it takes no slot, so any
        // number of holders can queue in one block (both modes).
        BOOST_CHECK(!fChanged);
    }
    // STRESSED: same rule as Open (the demand is how a worried holder makes
    // the house's obligation formal while it still can pay).
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.status = HOUSE_STATUS_STRESSED;
        house.nStressSinceHeight = (uint32_t)H - 1;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout), H, U, house, fnNoCoin), "");
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, false, {}), H, U, house, fnNoCoin),
                          "bad-note-demand-preauth-required");
    }
    // INSOLVENT: nothing to demand - the waterfall has it.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.status = HOUSE_STATUS_INSOLVENT;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_INSOLVENT);
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout), H, U, house, fnNoCoin),
                          "bad-note-demand-house-closed");
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, false, {}), H, U, house, fnNoCoin),
                          "bad-note-demand-house-closed");
    }
}

BOOST_AUTO_TEST_CASE(demand_preauth_digest_and_custody_pins)
{
    const int H = 5000;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
    CHouse house = MakeOpenHouse(1, H, 2 * U);

    // A demand whose standing authorisation does not verify is a claim the
    // house could never discharge - the teeth would fire unjustly. Reject NOW.
    BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout, true, /*fValidPreAuthSig=*/false),
                                H, U, house, fnNoCoin), "bad-note-demand-preauth-sig-invalid");

    // A payout script equal to THIS house's escrow script makes the discharge
    // UNBUILDABLE (the stray-escrow rule would reject it) - poison at the door.
    {
        const CScript scriptEscrow = HouseEscrowScript(house.houseID);
        const std::vector<unsigned char> vchEscrow(scriptEscrow.begin(), scriptEscrow.end());
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, vchEscrow), H, U, house, fnNoCoin),
                          "bad-note-demand-preauth-script-escrow");
    }

    // The custody re-issue must embed the DEMANDING holder's keyid: shape only
    // proved custody-SHAPED, and a stranger's keyid would strand the coins
    // (protest pin and discharge digest both resolve through it).
    {
        CMutableTransaction mtx = MakeDemandTx(1, U, key, true, payout);
        CKey stranger; stranger.MakeNewKey(true);
        const CPubKey pubS = stranger.GetPubKey();
        mtx.vout[0].scriptPubKey = NotePreAuthScript(std::vector<unsigned char>(pubS.begin(), pubS.end()));
        // re-sign the demand digest over the altered outputs so ONLY the
        // custody pin can be the reject
        NoteDemand d;
        {
            CDataStream ss(mtx.vchNotePayload, SER_NETWORK, PROTOCOL_VERSION); ss >> d;
        }
        key.Sign(NoteDemandSigHash(1, d.vUnits, BillHashOutputs(mtx)), d.vchHolderSig);
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION); ss2 << d;
        mtx.vchNotePayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
        BOOST_CHECK_EQUAL(CtxReject(mtx, H, U, house, fnNoCoin), "bad-note-demand-custody-script");
    }
}

// ------------------------------------------------------------- DISCHARGE
BOOST_AUTO_TEST_CASE(discharge_floor_and_diii_boundary)
{
    // D-iii (signed): "pay in a week and it costs you par". Demand at D; the
    // 5%/yr clock starts at D + W, not D. Window-1 pays par EXACTLY; at
    // W + k the floor accrues over k blocks only.
    const uint32_t D = 10000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
    const auto fnCoin = ServeCoin(1, U, NoteDemandTag(D, true), NotePreAuthScript(vchKey));

    // Inside the window: par exactly. One sat under par is short.
    {
        const int H = (int)(D + W - 1);
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID),
                                    H, U, house, fnCoin), "");
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U - 1, 0, house.houseID),
                                    H, U, house, fnCoin), "bad-note-redeem-interest-short");
    }
    // Past lapse: interest over exactly (H - (D + W)) blocks. The pre-fix code
    // read the tag RAW here - bit 31 made the "height" ~2^31 and the floor
    // silently vanished on exactly these coins. The masked read is the fix.
    {
        const uint32_t k = 5256;   // 0.1yr at mainnet cadence
        const int H = (int)(D + W + k);
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        const CAmount amountInterest = NoteDeferralInterest(U, k);
        BOOST_REQUIRE(amountInterest > 0);
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U + amountInterest, 0, house.houseID),
                                    H, U, house, fnCoin), "");
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U + amountInterest - 1, 0, house.houseID),
                                    H, U, house, fnCoin), "bad-note-redeem-interest-short");
    }
    // The PLAIN (Deferred-era) clock is untouched: an unmarked plain-demanded
    // coin still accrues FROM D - that clock belongs to the option clause.
    {
        const uint32_t k = 5256;
        const int H = (int)(D + k);
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        const auto fnPlain = ServeCoin(1, U, D, NoteScriptForPubKey(vchKey));
        const CAmount amountInterest = NoteDeferralInterest(U, k);
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + amountInterest),
                                    H, U, house, fnPlain), "");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + amountInterest - 1),
                                    H, U, house, fnPlain), "bad-note-redeem-interest-short");
    }
}

BOOST_AUTO_TEST_CASE(discharge_signature_and_payout_rules)
{
    const uint32_t D = 10000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    const int H = (int)(D + W - 1);
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
    CHouse house = MakeOpenHouse(1, H, 2 * U);
    const auto fnCoin = ServeCoin(1, U, NoteDemandTag(D, true), NotePreAuthScript(vchKey));

    // A pre-auth signature by the WRONG key (or over the wrong material) is
    // not an authorisation.
    {
        CMutableTransaction mtx = MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID);
        NoteRedeem r;
        { CDataStream ss(mtx.vchNotePayload, SER_NETWORK, PROTOCOL_VERSION); ss >> r; }
        CKey wrong; wrong.MakeNewKey(true);
        wrong.Sign(NotePreAuthSigHash(1, r.vPreAuthUnits, r.vchPayoutScript), r.vchPreAuthSig);
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION); ss2 << r;
        mtx.vchNotePayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
        BOOST_CHECK_EQUAL(CtxReject(mtx, H, U, house, fnCoin), "bad-note-redeem-discharge-sig-invalid");
    }
    // The re-supplied vector must sum to the burn: a mismatch means the sig
    // authorises a DIFFERENT demand than the coins being burned.
    {
        CMutableTransaction mtx = MakeDischargeTx(1, U / 2, key, payout, (CAmount)U, 0, house.houseID);
        BOOST_CHECK_EQUAL(CtxReject(mtx, H, U, house, fnCoin), "bad-note-redeem-discharge-sum");
    }
    // vout[0] must BE the pre-authorised script.
    {
        CMutableTransaction mtx = MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID);
        mtx.vout[0].scriptPubKey = NoteScriptForPubKey(vchKey);   // holder's P2PKH is NOT the deal
        BOOST_CHECK_EQUAL(CtxReject(mtx, H, U, house, fnCoin), "bad-note-redeem-discharge-payout-script");
    }
    // The voluntary path survives: a plain redeem of the same custody coin,
    // holder present and signing, at the same D-iii floor.
    {
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U), H, U, house, fnCoin), "");
    }
}

BOOST_AUTO_TEST_CASE(discharge_brassage_incidence)
{
    // Below rho the RUNNER bears the spread (sheet delta-2): floor to the
    // pre-authorised script drops by the spread and the spread lands in the
    // pot at vout[1] - same total house outlay as a plain below-rho redeem,
    // so demand-then-discharge is NOT a brassage bypass.
    const uint32_t D = 10000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    const int H = (int)(D + W - 1);   // inside the window: interest 0, spread only
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");

    CHouse house = MakeOpenHouse(1, H, 2 * U);
    house.amountLastAttestReserves = (CAmount)(U / 20);   // 250 bps <= theta: full spread
    house.status = HOUSE_STATUS_STRESSED;                 // what a below-floor attest produces
    house.nStressSinceHeight = (uint32_t)H - 1;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
    const CAmount amountSpread = HouseBrassageAmount(U, HouseBrassageBps(house));
    BOOST_REQUIRE(amountSpread > 0);
    const auto fnCoin = ServeCoin(1, U, NoteDemandTag(D, true), NotePreAuthScript(vchKey));

    // floor = U - spread to the payout script, spread to escrow: accepted.
    BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U - amountSpread,
                                                amountSpread, house.houseID),
                                H, U, house, fnCoin), "");
    // one sat under the reduced floor is short
    BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U - amountSpread - 1,
                                                amountSpread, house.houseID),
                                H, U, house, fnCoin), "bad-note-redeem-interest-short");
    // and the spread itself is not optional
    BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID),
                                H, U, house, fnCoin), "bad-note-redeem-brassage-missing");
}

// --------------------------------------------------------------- PROTEST
BOOST_AUTO_TEST_CASE(protest_window_priors_and_effects)
{
    const uint32_t D = 10000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const uint32_t tagOut = NoteDemandTag(D, true) | NOTE_DEMAND_PROTESTED_BIT;

    // W-1: one block early is EARLY. W: the sheet's "sat undischarged for
    // HOUSE_DEMAND_WINDOW blocks" is first true - accepted, and the effects
    // land exactly.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W - 1), U,
                                    house, fnNoCoin), "bad-note-protest-early");
        CHouse houseOut; bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W), U,
                                    house, fnNoCoin, &houseOut, &fChanged), "");
        BOOST_CHECK(fChanged);
        BOOST_CHECK_EQUAL(houseOut.nProtestOpen, 1u);            // one marked coin re-issued
        BOOST_CHECK_EQUAL(houseOut.nProtestHeight, D + W);
        BOOST_CHECK_EQUAL(houseOut.nProtestDemandHeight, D);
        BOOST_CHECK(houseOut.ProtestLive());

        // T-b4 (flipped from the T-b3 boundary pin): the origin is wired -
        // the protest makes the house effectively STRESSED on the spot, and
        // the insolvency fuse burns from the protest height.
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(houseOut, (int)(D + W)), HOUSE_STATUS_STRESSED);
        BOOST_CHECK_EQUAL(HouseStressOrigin(houseOut, (int)(D + W)), D + W);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(houseOut, (int)(D + W + HOUSE_STRESSED_WINDOW - 1)),
                          HOUSE_STATUS_STRESSED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(houseOut, (int)(D + W + HOUSE_STRESSED_WINDOW)),
                          HOUSE_STATUS_INSOLVENT);

        // STICKY-EARLIEST: a second protest (later demand D2, later height)
        // raises the counter but moves NEITHER height forward.
        const uint32_t D2 = D + 500;
        const uint32_t tag2 = NoteDemandTag(D2, true) | NOTE_DEMAND_PROTESTED_BIT;
        CHouse houseOut2; bool fChanged2 = false;
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tag2, houseOut), (int)(D2 + W), U,
                                    houseOut, fnNoCoin, &houseOut2, &fChanged2), "");
        BOOST_CHECK_EQUAL(houseOut2.nProtestOpen, 2u);
        BOOST_CHECK_EQUAL(houseOut2.nProtestHeight, D + W);      // unchanged
        BOOST_CHECK_EQUAL(houseOut2.nProtestDemandHeight, D);    // unchanged
    }
    // FRESH EPISODE (T-b5): a fully-discharged queue leaves the heights
    // INERT; the next protest OVERWRITES them - a sticky-min against a dead
    // episode's clock would hand the new episode a pre-burnt fuse.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        house.nProtestOpen = 0;            // queue clear...
        house.nProtestHeight = 100;        // ...heights inert from a dead episode
        house.nProtestDemandHeight = 50;
        BOOST_REQUIRE(!house.ProtestLive());
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)(D + W)), HOUSE_STATUS_OPEN);
        CHouse houseOut; bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W), U,
                                    house, fnNoCoin, &houseOut, &fChanged), "");
        BOOST_CHECK_EQUAL(houseOut.nProtestOpen, 1u);
        BOOST_CHECK_EQUAL(houseOut.nProtestHeight, D + W);       // overwritten, not min'd
        BOOST_CHECK_EQUAL(houseOut.nProtestDemandHeight, D);     // overwritten, not min'd
    }
    // Priors are the undo contract: a stale prior is a protest that cannot be
    // disconnected exactly.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        CHouse wrongPriors = house;
        wrongPriors.nProtestOpen = 7;
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, wrongPriors), (int)(D + W), U,
                                    house, fnNoCoin), "bad-note-protest-prior");
    }
    // Status gates: at Deferred the clause governs; at Insolvent the waterfall.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        house.nDeferInvokedHeight = D + W - 10;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)(D + W)), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W), U,
                                    house, fnNoCoin), "bad-note-protest-status");
    }
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        house.status = HOUSE_STATUS_INSOLVENT;
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W), U,
                                    house, fnNoCoin), "bad-note-protest-status");
    }
    // Custody preserved to the SAME holder; a bad signature is not a protest.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house, /*fCustodyOutputs=*/false),
                                    (int)(D + W), U, house, fnNoCoin), "bad-note-protest-custody-script");
        CMutableTransaction mtx = MakeProtestTx(1, U, key, tagOut, house);
        NoteProtest p;
        { CDataStream ss(mtx.vchNotePayload, SER_NETWORK, PROTOCOL_VERSION); ss >> p; }
        p.vchHolderSig[10] ^= 0x01;
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION); ss2 << p;
        mtx.vchNotePayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
        BOOST_CHECK_EQUAL(CtxReject(mtx, (int)(D + W), U, house, fnNoCoin), "bad-note-protest-sig");
    }
}

// ---------------------------------------------------------- D-v DECREMENT
BOOST_AUTO_TEST_CASE(redeem_decrements_the_protest_counter)
{
    // Two marked coins live (two protests); burning one decrements to 1 with
    // the heights INTACT - one continuous clock - and burning the last clears
    // the origin fields at exactly zero. An UNMARKED pre-auth coin's discharge
    // must not decrement anything.
    const uint32_t D = 10000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    const int H = (int)(D + W - 1);   // inside the window: floors are par
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");

    CHouse house = MakeOpenHouse(1, H, 4 * U);
    house.nProtestOpen = 2;
    house.nProtestHeight = D + 100;
    house.nProtestDemandHeight = D;

    const uint32_t tagMarked = NoteDemandTag(D, true) | NOTE_DEMAND_PROTESTED_BIT;
    const auto fnMarked = ServeCoin(1, U, tagMarked, NotePreAuthScript(vchKey));
    const auto fnUnmarked = ServeCoin(1, U, NoteDemandTag(D, true), NotePreAuthScript(vchKey));

    // 2 -> 1: heights stay (the clock never resets without a real recovery).
    CHouse houseMid;
    {
        bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID),
                                    H, U, house, fnMarked, &houseMid, &fChanged), "");
        BOOST_CHECK(fChanged);
        BOOST_CHECK_EQUAL(houseMid.nProtestOpen, 1u);
        BOOST_CHECK_EQUAL(houseMid.nProtestHeight, D + 100);
        BOOST_CHECK_EQUAL(houseMid.nProtestDemandHeight, D);
        BOOST_CHECK(houseMid.ProtestLive());
    }
    // T-b4: while the queue is live the house is STRESSED through the actual
    // REDEEM effects path, not just on hand-built fixtures.
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(houseMid, H), HOUSE_STATUS_STRESSED);
    // 1 -> 0: the DERIVED origin vanishes at zero and the house is OPEN the
    // moment the last protested claim is paid - discharge, and nothing else,
    // ends a protest. The height fields go INERT rather than cleared (T-b5):
    // every consumer gates on the counter, and leaving them is what makes
    // the reorg path exact (no height restore exists in the clearing tx's
    // undo data).
    {
        CHouse houseOut; bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, houseMid.houseID),
                                    H, U, houseMid, fnMarked, &houseOut, &fChanged), "");
        BOOST_CHECK_EQUAL(houseOut.nProtestOpen, 0u);
        BOOST_CHECK_EQUAL(houseOut.nProtestHeight, D + 100);     // inert, not cleared
        BOOST_CHECK_EQUAL(houseOut.nProtestDemandHeight, D);     // inert, not cleared
        BOOST_CHECK(!houseOut.ProtestLive());
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(houseOut, H), HOUSE_STATUS_OPEN);
    }
    // Unmarked pre-auth coin: no decrement (a discharge of a never-protested
    // demand has nothing to retire).
    {
        CHouse houseOut; bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID),
                                    H, U, house, fnUnmarked, &houseOut, &fChanged), "");
        BOOST_CHECK_EQUAL(houseOut.nProtestOpen, 2u);
        BOOST_CHECK_EQUAL(houseOut.nProtestHeight, D + 100);
    }
    // And the VOLUNTARY path decrements identically: a holder-signed redeem of
    // a marked coin satisfies the demand just as fully as a discharge.
    {
        CHouse houseOut; bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U),
                                    H, U, house, fnMarked, &houseOut, &fChanged), "");
        BOOST_CHECK_EQUAL(houseOut.nProtestOpen, 1u);
    }
}

// ---------------------------------------------- T-b4 STRESS-ORIGIN TABLE
// The sheet's T-b4 gate: attest-family x protest across every clear
// combination, on the pure derivation functions. The cells a FLAG would
// fail are (d) - an attestation "recovers" but the protest holds the house
// stressed - and (f) - the house pays one holder per window and the clock
// does not move.
BOOST_AUTO_TEST_CASE(b4_stress_origin_derivation_table)
{
    const uint32_t W = HOUSE_STRESSED_WINDOW;
    const uint64_t U = 1000000;   // divisible by 100: pct fixtures are exact
    const int H = 20000;

    const CAmount amountFloor    = (CAmount)((uint64_t)HOUSE_RESERVE_FLOOR_PCT * 2 * U / 100);
    const CAmount amountRecovery = (CAmount)((uint64_t)(HOUSE_RESERVE_FLOOR_PCT + HOUSE_RESTORE_BUFFER_PCT) * 2 * U / 100);

    // (a) no origins -> OPEN. Protest fields are v9 zero-default, so every
    // pre-B3 history derives bit-identically to the two-origin machine.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), 0u);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
    }
    // (b) protest only: the origin IS the protest height; STRESSED for the
    // window, INSOLVENT at exactly P + W.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nProtestOpen = 1;
        house.nProtestHeight = (uint32_t)H;
        house.nProtestDemandHeight = (uint32_t)H - 200;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H + (int)W - 1), HOUSE_STATUS_STRESSED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H + (int)W), HOUSE_STATUS_INSOLVENT);
    }
    // (c) earliest-wins against a stored breach, both ways.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nStressSinceHeight = (uint32_t)H - 50;
        house.nProtestOpen = 1;
        house.nProtestHeight = (uint32_t)H - 10;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 50);   // breach earlier
        house.nStressSinceHeight = (uint32_t)H - 10;
        house.nProtestHeight = (uint32_t)H - 50;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 50);   // protest earlier
    }
    // (c') earliest-wins against the derived missed-cadence origin, both ways.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nLastAttestHeight = 1000;   // deadline+1 = 1001 + MISS_N*CADENCE
        const uint32_t nCadenceOrigin = 1000 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1;
        house.nProtestOpen = 1;
        house.nProtestHeight = nCadenceOrigin - 100;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), nCadenceOrigin - 100);
        house.nProtestHeight = nCadenceOrigin + 100;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), nCadenceOrigin);
    }
    // (d) THE ASYMMETRY CELL. Breach + live protest; a recovery attestation
    // computes a ZERO family origin (it may clear only its own family, and
    // must - the recovery test in the ATTEST arm lifts deferrals on it), yet
    // after the write the house is STILL stressed from the protest height.
    // Reserves are not redemption.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nStressSinceHeight = (uint32_t)H - 300;
        house.nProtestOpen = 2;
        house.nProtestHeight = (uint32_t)H - 100;
        house.nProtestDemandHeight = (uint32_t)H - 900;
        BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, amountRecovery, H), 0u);
        house.nStressSinceHeight = 0;                    // the ATTEST arm's write
        house.nLastAttestHeight = (uint32_t)H;
        house.amountLastAttestReserves = amountRecovery;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 100);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
        // The SAME write with the queue cleared is a full recovery.
        house.nProtestOpen = 0;
        house.nProtestHeight = 0;
        house.nProtestDemandHeight = 0;
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
    }
    // (e) cross-contamination guard: no attest branch ever returns the
    // protest height, so it can never be written into nStressSinceHeight.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nProtestOpen = 1;
        house.nProtestHeight = (uint32_t)H - 500;
        // T2 below floor with no stored breach: stamps its OWN height.
        BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, amountFloor - 1, H), (uint32_t)H);
        // In-band: preserves the (empty) family, NOT the protest.
        BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, amountFloor, H), 0u);
        // ... while the merged origin still carries the protest.
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 500);
    }
    // (f) THE COUNTER CELL a flag fails: three holders protested; paying one
    // at a time never moves the clock - the origin holds at the EARLIEST
    // until the queue is genuinely clear, then the DERIVED origin vanishes
    // at zero even though the height fields stay behind INERT (T-b5: the
    // REDEEM arm never clears them; ProtestLive() is the gate).
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nProtestOpen = 3;
        house.nProtestHeight = (uint32_t)H - 400;
        house.nProtestDemandHeight = (uint32_t)H - 1200;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 400);
        house.nProtestOpen = 2;   // paid one (the REDEEM arm's decrement)
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 400);
        house.nProtestOpen = 1;   // paid another
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 400);
        house.nProtestOpen = 0;   // the last - heights left INERT, not cleared
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), 0u);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
    }
    // (g) deferral overlap: discharge is impossible while DEFERRED, so a
    // protest that rode through a lawful episode re-arms at the recovery
    // stamp - the house gets a full window from nDeferEndedHeight, not a
    // pre-burnt fuse (the teeth are only just if the house can always
    // discharge). An episode that ended BEFORE the protest extends nothing.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nProtestOpen = 1;
        house.nProtestHeight = (uint32_t)H - 5000;       // fuse would be long burnt...
        house.nDeferEndedHeight = (uint32_t)H;           // ...but recovery just landed
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H + (int)W - 1), HOUSE_STATUS_STRESSED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H + (int)W), HOUSE_STATUS_INSOLVENT);
        // stale episode, protest younger: the protest height governs
        house.nProtestHeight = (uint32_t)H - 100;
        house.nDeferEndedHeight = (uint32_t)H - 3000;
        BOOST_CHECK_EQUAL(HouseStressOrigin(house, H), (uint32_t)H - 100);
    }
    // (h) a RUNNING episode masks the protest (the clause governs; PROTEST
    // itself is rejected at Deferred) and expiry-without-recovery is
    // INSOLVENT regardless of the queue.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nProtestOpen = 1;
        house.nProtestHeight = (uint32_t)H - 5000;
        house.nDeferInvokedHeight = (uint32_t)H - 10;
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)house.DeferEndHeight()),
                          HOUSE_STATUS_INSOLVENT);
    }
}

// -------------------------------------------- T-b6 DISPLACEMENT WHITELIST
// Sheet 4c: PROTEST is third-party and re-issuable - it MEETS the J2 party
// test for displaceability - and must be non-displaceable anyway, because
// there the eviction is the attack (attest every block = perpetual-eviction
// defence). The whitelist is by VERSION; this pin fails if v13 ever enters
// it, or if the two legitimate families ever silently leave it.
BOOST_AUTO_TEST_CASE(b6_attest_displacement_whitelist)
{
    CMutableTransaction mtx;

    mtx.nVersion = TRANSACTION_NOTE_VERSION;      // v13: PROTEST/REDEEM/MINT/CLAIM
    mtx.nNoteOp = NOTE_OP_PROTEST;
    BOOST_CHECK(!IsAttestDisplaceable(CTransaction(mtx)));
    mtx.nNoteOp = NOTE_OP_REDEEM;                 // a pooled discharge: house's own work
    BOOST_CHECK(!IsAttestDisplaceable(CTransaction(mtx)));

    CMutableTransaction mtxHouse;
    mtxHouse.nVersion = TRANSACTION_HOUSE_VERSION;    // WINDDOWN etc: house's own work
    BOOST_CHECK(!IsAttestDisplaceable(CTransaction(mtxHouse)));
    CMutableTransaction mtxDeposit;
    mtxDeposit.nVersion = TRANSACTION_DEPOSIT_VERSION;
    BOOST_CHECK(!IsAttestDisplaceable(CTransaction(mtxDeposit)));
    CMutableTransaction mtxPool;
    mtxPool.nVersion = TRANSACTION_POOL_VERSION;
    BOOST_CHECK(!IsAttestDisplaceable(CTransaction(mtxPool)));

    CMutableTransaction mtxSettle;
    mtxSettle.nVersion = TRANSACTION_SETTLE_VERSION;  // counterparty-signed: the J2 rule
    BOOST_CHECK(IsAttestDisplaceable(CTransaction(mtxSettle)));
    CMutableTransaction mtxBill;
    mtxBill.nVersion = TRANSACTION_BILL_VERSION;      // drawee-built HRETIRE: forced
    BOOST_CHECK(IsAttestDisplaceable(CTransaction(mtxBill)));
}

BOOST_AUTO_TEST_SUITE_END()
