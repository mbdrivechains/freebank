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
#include <issued.h>
#include <houserate.h>      // CCharterToken, CHouseCharter, ChainClockKey (S1X-15)
#include <policy/policy.h> // IsStandard (S1X-15)
#include <units.h>         // CUnitsView (S1X-15)

#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <tinyformat.h>
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
                        CHouse& houseOut, bool& fHouseChanged, bool fMempool = false);
// The J2 displacement whitelist (validation.cpp) - pinned structurally below.

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

// S1X-14: a pre-auth note demand's custody script and pre-auth digest carry its demand id (S1X-42: NoteDemandId of the
// DEMAND, its prevouts with its vector and payout). The discharge helpers default to DemandIdFor(), an opaque id
// standing for "this demand's coins"; MakeDemandTx computes its own.
uint256 DemandIdFor(const uint256& prevHash = uint256S("de3a"))
{
    CMutableTransaction m;
    m.vin.push_back(CTxIn(COutPoint(prevHash, 0)));
    return NoteHashPrevouts(CTransaction(m));
}
CScript TestCustody(const std::vector<unsigned char>& vchKey, const uint256& demandId = DemandIdFor())
{
    return NoteDemandCustodyScript(vchKey, demandId);
}

// A fully-signed DEMAND. Outputs are built FIRST (custody or P2PKH by mode),
// then both signatures are made over the finished tx - exactly the wallet's
// build order, because both digests are checked at connect.
CMutableTransaction MakeDemandTx(uint32_t nHouseID, uint64_t nUnits, const CKey& keyHolder,
                                 bool fPreAuth, const std::vector<unsigned char>& vchPayoutScript,
                                 bool fCustodyOutputs = true, bool fValidPreAuthSig = true,
                                 bool fQueue = false, const uint256& prevHash = uint256S("de3a"))
{
    const CPubKey pub = keyHolder.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());

    NoteDemand d;
    d.nHouseID = nHouseID;
    d.vUnits.push_back(nUnits);
    d.vchHolderPubKey = vchKey;
    d.fPreAuth = fPreAuth ? (fQueue ? NOTE_DEMAND_MODE_PREAUTH_QUEUE : NOTE_DEMAND_MODE_PREAUTH)
                          : NOTE_DEMAND_MODE_PLAIN;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_DEMAND;
    mtx.vin.push_back(CTxIn(COutPoint(prevHash, 0)));
    if (fPreAuth)
        d.vchPayoutScript = vchPayoutScript;
    const uint256 demandId = NoteDemandId(CTransaction(mtx), d.vUnits, d.vchPayoutScript);   // S1X-42
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE,
        (fPreAuth && fCustodyOutputs) ? TestCustody(vchKey, demandId) : NoteScriptForPubKey(vchKey)));

    if (fPreAuth) {
        keyHolder.Sign(NotePreAuthSigHash(nHouseID, d.vUnits, d.vchPayoutScript, demandId), d.vchPreAuthSig);
        if (!fValidPreAuthSig)
            keyHolder.Sign(NotePreAuthSigHash(nHouseID + 1, d.vUnits, d.vchPayoutScript, demandId), d.vchPreAuthSig);
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
                                    const uint256& houseID256, const uint256& demandId = DemandIdFor())
{
    const CPubKey pub = keyHolder.GetPubKey();

    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = amountSpread > 0 ? 1 : 0;
    redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    redeem.fPreAuthDischarge = 1;
    redeem.vPreAuthUnits.push_back(nUnits);
    redeem.vchPayoutScript = vchPayoutScript;
    keyHolder.Sign(NotePreAuthSigHash(nHouseID, redeem.vPreAuthUnits, redeem.vchPayoutScript, demandId),
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
                                  bool fCustodyOutputs = true, const uint256& demandId = DemandIdFor())
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
        fCustodyOutputs ? TestCustody(vchKey, demandId) : NoteScriptForPubKey(vchKey)));

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
        coin = Coin(CTxOut(NOTE_DUST_VALUE, script), 100, false, false, false, uint256());
        coin.SetNote(nHouseID, nUnits, nTag);
        return true;
    };
}

// Interest over k blocks at the network's schedule (one 10%/yr step from 0 on
// every network, so any k-block range gives the same amount).
CAmount Interest(uint64_t nUnits, uint32_t k)
{
    return NoteDeferralInterest(nUnits, 0, k, Params().GetConsensus().vDeferInterestSchedule);
}

// A PLAIN (holder-signed) redeem with an optional brassage output at vout[1].
CMutableTransaction MakePlainRedeemSpreadTx(uint32_t nHouseID, uint64_t nUnits, const CKey& keyHolder,
                                            CAmount amountPayout, CAmount amountSpread,
                                            const uint256& houseID256)
{
    const CPubKey pub = keyHolder.GetPubKey();
    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = amountSpread > 0 ? 1 : 0;
    redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("p1a2"), 0)));
    mtx.vout.push_back(CTxOut(amountPayout, NoteScriptForPubKey(redeem.vchHolderPubKey)));
    if (amountSpread > 0)
        mtx.vout.push_back(CTxOut(amountSpread, HouseEscrowScript(houseID256)));

    keyHolder.Sign(NoteRedeemSigHash(nHouseID, nUnits, BillHashOutputs(mtx)), redeem.vchHolderSig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

} // namespace

// --------------------------------------------------------------- DEMAND
BOOST_AUTO_TEST_CASE(demand_status_matrix)
{
    const int H = 5000;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");

    // DEFERRED (v0.2.18 "a"): plain accepted, PRE-AUTH QUEUE accepted (the
    // house can pay it alone), the B3 lapse-start mode 1 refused.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nDeferInvokedHeight = (uint32_t)H - 10;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, false, {}), H, U, house, fnNoCoin), "");
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout, true, true, true), H, U, house,
                                    fnNoCoin), "");
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout), H, U, house, fnNoCoin),
                          "bad-note-demand-preauth-queue-required");
    }
    // OPEN: pre-auth REQUIRED - a plain demand is the old "interest clock the
    // house never agreed to"; the pre-auth demand IS the B3 formal demand.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, false, {}), H, U, house, fnNoCoin),
                          "bad-note-demand-preauth-required");
        // a fresh queue-mode demand is only for a suspended house
        BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, payout, true, true, true), H, U, house,
                                    fnNoCoin), "bad-note-demand-queue-not-deferred");
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
        mtx.vout[0].scriptPubKey = TestCustody(std::vector<unsigned char>(pubS.begin(), pubS.end()));   // only the keyid differs
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
    const auto fnCoin = ServeCoin(1, U, NoteDemandTag(D, true), TestCustody(vchKey));

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
        const CAmount amountInterest = Interest(U, k);
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
        const CAmount amountInterest = Interest(U, k);
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
    const auto fnCoin = ServeCoin(1, U, NoteDemandTag(D, true), TestCustody(vchKey));

    // A pre-auth signature by the WRONG key (or over the wrong material) is
    // not an authorisation.
    {
        CMutableTransaction mtx = MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID);
        NoteRedeem r;
        { CDataStream ss(mtx.vchNotePayload, SER_NETWORK, PROTOCOL_VERSION); ss >> r; }
        CKey wrong; wrong.MakeNewKey(true);
        wrong.Sign(NotePreAuthSigHash(1, r.vPreAuthUnits, r.vchPayoutScript, DemandIdFor()), r.vchPreAuthSig);
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION); ss2 << r;
        mtx.vchNotePayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
        BOOST_CHECK_EQUAL(CtxReject(mtx, H, U, house, fnCoin), "bad-note-redeem-discharge-sig-invalid");
    }
    // The burn may not exceed the re-supplied vector's sum (S1X-32: it may fall short of it - the rest of a demand the
    // holder partly redeemed itself).
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
    const CAmount amountSpread = GoldBrassageAmount(house, H, U);   // S1X-8: the consensus amount (rounded up once)
    BOOST_REQUIRE(amountSpread > 0);
    const auto fnCoin = ServeCoin(1, U, NoteDemandTag(D, true), TestCustody(vchKey));

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
    // S1X-14: the protest reads the demand id from the custody coins it re-issues.
    const CPubKey pubKey = key.GetPubKey();
    const auto fnCustody = ServeCoin(1, U, NoteDemandTag(D, true), TestCustody(std::vector<unsigned char>(pubKey.begin(), pubKey.end())));

    // W-1: one block early is EARLY. W: the sheet's "sat undischarged for
    // HOUSE_DEMAND_WINDOW blocks" is first true - accepted, and the effects
    // land exactly.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W - 1), U,
                                    house, fnCustody), "bad-note-protest-early");
        CHouse houseOut; bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W), U,
                                    house, fnCustody, &houseOut, &fChanged), "");
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
                                    houseOut, fnCustody, &houseOut2, &fChanged2), "");
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
                                    house, fnCustody, &houseOut, &fChanged), "");
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
                                    house, fnCustody), "bad-note-protest-prior");
    }
    // Status gates: at Deferred the clause governs; at Insolvent the waterfall.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        house.nDeferInvokedHeight = D + W - 10;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)(D + W)), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W), U,
                                    house, fnCustody), "bad-note-protest-status");
    }
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        house.status = HOUSE_STATUS_INSOLVENT;
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house), (int)(D + W), U,
                                    house, fnCustody), "bad-note-protest-status");
    }
    // Custody preserved to the SAME holder; a bad signature is not a protest.
    {
        CHouse house = MakeOpenHouse(1, (int)(D + W), 2 * U);
        BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagOut, house, /*fCustodyOutputs=*/false),
                                    (int)(D + W), U, house, fnCustody), "bad-note-protest-custody-script");
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
    const auto fnMarked = ServeCoin(1, U, tagMarked, TestCustody(vchKey));
    const auto fnUnmarked = ServeCoin(1, U, NoteDemandTag(D, true), TestCustody(vchKey));

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
    // (c') earliest-wins against a stored origin, both ways (gram-notes release: the missed-cadence origin no longer
    // derives, so the same earliest-wins merge is shown against a stored one).
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        const uint32_t nCadenceOrigin = 1000 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1;
        house.nStressSinceHeight = nCadenceOrigin;
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
    // itself is rejected at Deferred). v0.2.18: there is no expiry - only
    // silence (missed cadences + nDeferSilenceWindow) turns it INSOLVENT,
    // regardless of the queue.
    {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nProtestOpen = 1;
        house.nProtestHeight = (uint32_t)H - 5000;
        house.nDeferInvokedHeight = (uint32_t)H - 10;
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)HouseDeferSilenceInsolventHeight(house) - 1),
                          HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)HouseDeferSilenceInsolventHeight(house)),
                          HOUSE_STATUS_INSOLVENT);
    }
}

// T-b6 DISPLACEMENT WHITELIST: retired in plain v1.2.2 with J2 itself (UR-ext-2). House-slot conflicts are settled by
// fee now; no op type is displaceable for free. The slot gates (slot_fee_priority, mempool_slot_matrix) pin the rule.

// ------------------------------------------- v0.2.18 SUSPENSION (Q6/Q7/Q8)
// A suspended house may pay DEMANDED notes (from new money; the till stays
// locked - a redeem cannot spend escrow, tx_verify), at least principal +
// interest at the scheduled 10%/yr less the brassage the RUNNER bears.
// Undemanded notes still cannot redeem while suspended.

// A house suspended at S, attesting on cadence (so not silent), ratio as given.
static CHouse MakeSuspendedHouse(uint32_t nHouseID, int nHeight, uint64_t nMinted, CAmount amountReserves, uint32_t S)
{
    CHouse house = MakeOpenHouse(nHouseID, nHeight, nMinted);
    house.amountLastAttestReserves = amountReserves;
    house.nStressSinceHeight = S - 1;
    house.nDeferInvokedHeight = S;
    house.nDeferActivations = 1;
    house.nDeferLastActivation = S;
    return house;
}

BOOST_AUTO_TEST_CASE(suspended_redeem_demanded_only_at_floor)
{
    const uint32_t S = 9000, D = 10000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    const int H = (int)(D + 26280);                 // half a year after the demand
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());

    // Fully reserved suspended house -> no spread; the floor is U + interest.
    CHouse house = MakeSuspendedHouse(1, H, 2 * U, (CAmount)(2 * U), S);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
    BOOST_REQUIRE_EQUAL(GoldBrassageBps(house, H), 0u);

    // Rate check: 10%/yr on 1e6 units for exactly half a year = 50,000 sats.
    const CAmount I = Interest(U, (uint32_t)H - D);
    BOOST_CHECK_EQUAL(I, 50000);

    // A plain (suspension-queue) demanded note: paid at the floor - accepted,
    // the units retire; one sat short - rejected.
    const auto fnDemanded = ServeCoin(1, U, D, NoteScriptForPubKey(vchKey));
    {
        CHouse houseOut; bool fChanged = false;
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + I), H, U, house, fnDemanded,
                                    &houseOut, &fChanged), "");
        BOOST_CHECK(fChanged);
        BOOST_CHECK_EQUAL(houseOut.nMintedUnits, U);
        BOOST_CHECK_EQUAL(houseOut.nDeferInvokedHeight, S);       // still suspended
        BOOST_CHECK(houseOut.vOutReserveLock == house.vOutReserveLock);   // the till is untouched
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + I - 1), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
        // Par (the pre-v0.2.18 Open-house habit) is far short.
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
    }
    // An UNDEMANDED note cannot redeem while suspended - at any payout.
    {
        const auto fnPlain = ServeCoin(1, U, 0, NoteScriptForPubKey(vchKey));
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + I), H, U, house, fnPlain),
                          "bad-note-redeem-deferred");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, 10 * (CAmount)U), H, U, house, fnPlain),
                          "bad-note-redeem-deferred");
    }
    // A B3 pre-auth demand lodged BEFORE the suspension (at Open) can be
    // DISCHARGED by the suspended house, its clock from window lapse (D-iii).
    {
        const uint32_t D0 = S - 500;
        const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
        const auto fnPreAuth = ServeCoin(1, U, NoteDemandTag(D0, true), TestCustody(vchKey));
        const CAmount I0 = Interest(U, (uint32_t)H - (D0 + W));
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U + I0, 0, house.houseID),
                                    H, U, house, fnPreAuth), "");
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeTx(1, U, key, payout, (CAmount)U + I0 - 1, 0, house.houseID),
                                    H, U, house, fnPreAuth), "bad-note-redeem-interest-short");
    }
    // Once SILENT past the clock the house is Insolvent: no redemption at all.
    {
        CHouse hSilent = house;
        hSilent.nLastAttestHeight = (uint32_t)H - HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE - 1
                                  - Params().GetConsensus().nDeferSilenceWindow;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(hSilent, H), HOUSE_STATUS_INSOLVENT);
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + I), H, U, hSilent, fnDemanded),
                          "bad-note-redeem-house-closed");
    }
}

BOOST_AUTO_TEST_CASE(suspended_redeem_runner_bears_brassage)
{
    // Q7: brassage unchanged, and BOTH redeem paths put it on the runner: the
    // holder-signed floor is U + interest - spread, exactly the discharge
    // floor (until v0.2.17 it was U + interest with the spread on top).
    const uint32_t S = 9000, D = 10000;
    const uint64_t U = 1000000;
    const int H = (int)(D + 5256);
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());

    CHouse house = MakeSuspendedHouse(1, H, 2 * U, (CAmount)(U / 10), S);   // 500 bps < rho
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
    const CAmount amountSpread = GoldBrassageAmount(house, H, U);   // S1X-8: the consensus amount (rounded up once)
    BOOST_REQUIRE(amountSpread > 0);
    const CAmount I = Interest(U, (uint32_t)H - D);
    BOOST_REQUIRE(I > 0);
    const auto fnDemanded = ServeCoin(1, U, D, NoteScriptForPubKey(vchKey));

    BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemSpreadTx(1, U, key, (CAmount)U + I - amountSpread, amountSpread, house.houseID),
                                H, U, house, fnDemanded), "");
    BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemSpreadTx(1, U, key, (CAmount)U + I - amountSpread - 1, amountSpread, house.houseID),
                                H, U, house, fnDemanded), "bad-note-redeem-interest-short");
    // The house may still pay the full U + interest with the spread on top
    // (what the v0.2.17 wallet builds) - the floor is a minimum.
    BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemSpreadTx(1, U, key, (CAmount)U + I, amountSpread, house.houseID),
                                H, U, house, fnDemanded), "");
    // The spread itself is not optional.
    BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemSpreadTx(1, U, key, (CAmount)U + I, 0, house.houseID),
                                H, U, house, fnDemanded), "bad-note-redeem-brassage-missing");
}

BOOST_AUTO_TEST_CASE(demand_accrual_reopen_rule)
{
    // Q8: a demanded note accrues until PAID; it stops at the reopen height E
    // only if paid while the house is open AND within W of E.
    const uint32_t D = 10000, E = 15256;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const auto fnDemanded = ServeCoin(1, U, D, NoteScriptForPubKey(vchKey));
    const CAmount ICapped = Interest(U, E - D);
    BOOST_REQUIRE_EQUAL(ICapped, 10000);    // 10%/yr x 0.1yr

    auto Reopened = [&](int H) {
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nDeferEndedHeight = E;
        house.nDeferActivations = 1;
        house.nDeferLastActivation = D - 100;
        return house;
    };
    // Paid AT the last in-window height E + W (inclusive): stops at E.
    {
        const int H = (int)(E + W);
        CHouse house = Reopened(H);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ICapped), H, U, house, fnDemanded), "");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ICapped - 1), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
        uint32_t a = 0, b = 0;
        NoteDemandAccrualWindow(house, D, (uint32_t)H, W, a, b);
        BOOST_CHECK_EQUAL(a, D);
        BOOST_CHECK_EQUAL(b, E);
    }
    // Paid later (this is a PLAIN demand): v0.2.18 "b" - the clock stopped at
    // E + W, the end of the holder's week to cash in. More than the in-time
    // amount, and nothing for the holder's own delay after E + W.
    {
        const int H = (int)(E + W + 50);
        CHouse house = Reopened(H);
        const CAmount ICap = Interest(U, E + W - D);
        BOOST_REQUIRE(ICap > ICapped);
        BOOST_REQUIRE(Interest(U, (uint32_t)H - D) > ICap);
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ICap), H, U, house, fnDemanded), "");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ICap - 1), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ICapped), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
    }
    // THE TRICK Q8 CLOSES: reopen at E, re-suspend at E + 5, pay while
    // suspended at E + 10 (well inside the window). Interest runs D -> payment.
    {
        const int H = (int)(E + 10);
        CHouse house = Reopened(H);
        house.nDeferInvokedHeight = E + 5;
        house.nDeferActivations = 2;
        house.nDeferLastActivation = E + 5;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
        const CAmount IFull = Interest(U, (uint32_t)H - D);
        BOOST_REQUIRE(IFull > ICapped);
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + IFull), H, U, house, fnDemanded), "");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ICapped), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
    }
    // ...and when that second episode reopens at E2 (overwriting E) and the
    // note is paid within W of E2, it has accrued continuously D -> E2 (both
    // episodes AND the gap between them), not just from the second episode.
    {
        const uint32_t E2 = E + 20000;
        const int H = (int)(E2 + 3);
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nDeferEndedHeight = E2;
        house.nDeferActivations = 2;
        house.nDeferLastActivation = E + 5;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
        const CAmount ITo2 = Interest(U, E2 - D);
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ITo2), H, U, house, fnDemanded), "");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + ITo2 - 1), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
    }
    // A demand in the SAME block as the reopen (D == E): zero window, par.
    {
        const int H = (int)(D + 5);
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nDeferEndedHeight = D;
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U), H, U, house, fnDemanded), "");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U - 1), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
    }
    // A reopen BEFORE the demand caps nothing: accrual from D to payment.
    {
        const int H = (int)(D + 500);
        CHouse house = MakeOpenHouse(1, H, 2 * U);
        house.nDeferEndedHeight = D - 1;
        const CAmount I = Interest(U, (uint32_t)H - D);
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + I - 1), H, U, house, fnDemanded),
                          "bad-note-redeem-interest-short");
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U, key, (CAmount)U + I), H, U, house, fnDemanded), "");
    }
}

BOOST_AUTO_TEST_CASE(protest_queue_demand_window_starts_at_reopen)
{
    // v0.2.18: a QUEUE demand (filed while suspended) gets its week to be paid
    // from the REOPEN, not from the demand - otherwise every queue holder could
    // protest the block the house recovers.
    const uint32_t D = 10000, E = 15000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const uint32_t tagQueueOut = NoteDemandTag(D, NOTE_DEMAND_MODE_PREAUTH_QUEUE) | NOTE_DEMAND_PROTESTED_BIT;
    const uint32_t tagB3Out = NoteDemandTag(D, NOTE_DEMAND_MODE_PREAUTH) | NOTE_DEMAND_PROTESTED_BIT;

    CHouse house = MakeOpenHouse(1, (int)(E + W), 2 * U);
    house.nDeferEndedHeight = E;                       // reopened at E
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)(E + W)), HOUSE_STATUS_OPEN);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    auto fnCoinAt = [&](uint32_t nCoinHeight) {
        return [=](const COutPoint&, Coin& coin) {
            coin = Coin(CTxOut(NOTE_DUST_VALUE, TestCustody(vchKey)), (int)nCoinHeight, false, false, false, uint256());
            coin.SetNote(1, U, NoteDemandTag(D, NOTE_DEMAND_MODE_PREAUTH_QUEUE));
            return true;
        };
    };
    // Long past D + W, but inside the week after the reopen: early.
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagQueueOut, house), (int)(E + W - 1), U,
                                house, fnCoinAt(D)), "bad-note-protest-early");
    // The week after the reopen has run: accepted.
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagQueueOut, house), (int)(E + W), U,
                                house, fnCoinAt(D)), "");
    // A Δ1b UPGRADE at U2 > E (the tag keeps D, the coin is created at U2): the
    // house could not pay alone before U2, so the week starts there.
    const uint32_t U2 = E + 3 * W;
    CHouse houseLate = house;
    houseLate.nLastAttestHeight = U2 + W - 2;          // still attesting: Open at these heights
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(houseLate, (int)(U2 + W)), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagQueueOut, houseLate), (int)(U2 + W - 1), U,
                                houseLate, fnCoinAt(U2)), "bad-note-protest-early");
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagQueueOut, houseLate), (int)(U2 + W), U,
                                houseLate, fnCoinAt(U2)), "");
    // Fail closed: an unresolvable input cannot shorten a queue window.
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagQueueOut, houseLate), (int)(U2 + W), U,
                                houseLate, fnNoCoin), "bad-note-protest-coin");
    // A B3 formal demand keeps its own window from the demand.
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagB3Out, house), (int)(E + W - 1), U,
                                house, ServeCoin(1, U, tagB3Out & ~NOTE_DEMAND_PROTESTED_BIT, TestCustody(vchKey))), "");
}

// v0.2.19 members-only houses: a PLAIN demand re-issues notes to a P2PKH the holder names (shape only), so it is held
// to the members-only rule (spec 4.1; the draft-1 review blocker). The wallet always re-issues to the holder's own key,
// so only a hand-built demand reaches the refusal. No member records exist here (no HouseDB in this suite): only the
// holder's own key and the house's redemption key are allowed.
static CMutableTransaction MakePlainDemandTo(uint32_t nHouseID, uint64_t nUnits, const CKey& keyHolder, const CScript& scriptTo)
{
    const CPubKey pub = keyHolder.GetPubKey();
    NoteDemand d;
    d.nHouseID = nHouseID;
    d.vUnits.push_back(nUnits);
    d.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    d.fPreAuth = NOTE_DEMAND_MODE_PLAIN;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_DEMAND;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("de3a"), 0)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, scriptTo));
    keyHolder.Sign(NoteDemandSigHash(nHouseID, d.vUnits, BillHashOutputs(mtx)), d.vchHolderSig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << d;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

BOOST_AUTO_TEST_CASE(demand_plain_members_only_rule)
{
    const int H = 5000;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    CKey other; other.MakeNewKey(true);
    const CScript scriptOwn = GetScriptForDestination(key.GetPubKey().GetID());
    const CScript scriptOther = GetScriptForDestination(other.GetPubKey().GetID());

    CHouse house = MakeOpenHouse(1, H, 2 * U);
    house.nDeferInvokedHeight = (uint32_t)H - 10;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);
    const CScript scriptHouse = GetScriptForDestination(CPubKey(house.vchRedemptionDestPK).GetID());

    // An open house: any P2PKH, as before
    BOOST_CHECK_EQUAL(CtxReject(MakePlainDemandTo(1, U, key, scriptOther), H, U, house, fnNoCoin), "");
    // Members-only: the holder's own key and the house's key, not another key
    house.nFlags = HOUSE_FLAG_MEMBERS_ONLY;
    BOOST_CHECK_EQUAL(CtxReject(MakePlainDemandTo(1, U, key, scriptOwn), H, U, house, fnNoCoin), "");
    BOOST_CHECK_EQUAL(CtxReject(MakePlainDemandTo(1, U, key, scriptHouse), H, U, house, fnNoCoin), "");
    BOOST_CHECK_EQUAL(CtxReject(MakePlainDemandTo(1, U, key, scriptOther), H, U, house, fnNoCoin), "bad-house-not-member");
    // Redeem-only: the same, refused as passing on between holders
    house.nFlags = HOUSE_FLAG_MEMBERS_ONLY | HOUSE_FLAG_REDEEM_ONLY;
    BOOST_CHECK_EQUAL(CtxReject(MakePlainDemandTo(1, U, key, scriptOwn), H, U, house, fnNoCoin), "");
    BOOST_CHECK_EQUAL(CtxReject(MakePlainDemandTo(1, U, key, scriptOther), H, U, house, fnNoCoin), "bad-house-redeem-only");
    // The pre-auth modes re-issue into custody pinned to the holder: not this rule's business
    BOOST_CHECK_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, std::vector<unsigned char>(scriptOther.begin(), scriptOther.end()),
                                             true, true, true), H, U, house, fnNoCoin), "");
}

// S1X-14 (security 2026-11-24: Medium). A pre-auth signature covers
// only (house, unit vector, payout script), so nothing ties it to ONE demand. A discharge needs no holder signature
// and the custody script is open, so anyone holding an OLD discharged demand's pre-auth (it is public once that
// discharge confirms) can discharge a LATER pre-auth demand by the same key, at the same house, for the same total -
// paying the OLD payee. The old payee (or a house that controls it) funds the floor to itself and the new demand's
// notes are burned without paying its own payee.
// The test takes the old signature out of the old DEMAND's payload, so it holds whatever the fix binds the digest to.
// Any refusal passes; the check is at CheckNoteOperation, which reads the custody coins' tags.
namespace {
// The pre-auth signature a DEMAND carries (what a third party reads from the chain).
std::vector<unsigned char> PreAuthSigOf(const CMutableTransaction& mtxDemand)
{
    NoteDemand d;
    CDataStream ss(mtxDemand.vchNotePayload, SER_NETWORK, PROTOCOL_VERSION);
    ss >> d;
    return d.vchPreAuthSig;
}
// A DISCHARGE built by someone WITHOUT the holder's key: it re-supplies a signature it found.
CMutableTransaction ReplayDischargeTx(uint32_t nHouseID, uint64_t nUnits, const CPubKey& pubHolder,
                                      const std::vector<unsigned char>& vchPayoutScript,
                                      const std::vector<unsigned char>& vchFoundSig, CAmount amountPayout)
{
    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = 0;
    redeem.vchHolderPubKey = std::vector<unsigned char>(pubHolder.begin(), pubHolder.end());
    redeem.fPreAuthDischarge = 1;
    redeem.vPreAuthUnits.push_back(nUnits);
    redeem.vchPayoutScript = vchPayoutScript;
    redeem.vchPreAuthSig = vchFoundSig;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("d15c"), 0)));
    mtx.vout.push_back(CTxOut(amountPayout, CScript(vchPayoutScript.begin(), vchPayoutScript.end())));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}
} // namespace

BOOST_AUTO_TEST_CASE(s1x_14a_an_old_preauth_cannot_discharge_a_later_demand)
{
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint32_t D1 = 10000, D2 = 20000;        // two demands by one key, same house, same total
    const uint64_t U = 1000000;
    const int H = (int)(D2 + W - 1);              // inside D2's window: par exactly
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> vchPayeeA = ParseHex("76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac");
    const std::vector<unsigned char> vchPayeeB = ParseHex("76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac");
    CHouse house = MakeOpenHouse(1, H, 4 * U);

    // D1 named payee A and was discharged long ago: its pre-auth is public.
    // (S1X-14 fix: D1 spent other coins than D2, so it has its own demand id.)
    const std::vector<unsigned char> vchSigA =
        PreAuthSigOf(MakeDemandTx(1, U, key, true, vchPayeeA, true, true, false, uint256S("d1d1")));
    BOOST_REQUIRE(!vchSigA.empty());
    // D2's custody coins: demanded at D2, pre-auth, the holder's custody script.
    const auto fnCoinD2 = ServeCoin(1, U, NoteDemandTag(D2, true), TestCustody(vchKey));

    // Control: D2's own pre-auth (payee B) discharges D2.
    BOOST_REQUIRE_EQUAL(CtxReject(MakeDischargeTx(1, U, key, vchPayeeB, (CAmount)U, 0, house.houseID),
                                  H, U, house, fnCoinD2), "");

    // The replay: payee A spends D2's coins with D1's signature and pays itself.
    const std::string strReplay = CtxReject(ReplayDischargeTx(1, U, pub, vchPayeeA, vchSigA, (CAmount)U),
                                            H, U, house, fnCoinD2);
    BOOST_CHECK_MESSAGE(!strReplay.empty(),
        "S1X-14 (a): a discharge of the demand made at height " << D2 << " (payee B) was accepted with the pre-auth "
        "of an earlier demand made at height " << D1 << " (payee A), paying A; nothing binds a pre-auth to its demand");
}

BOOST_AUTO_TEST_CASE(s1x_14b_two_demands_in_one_block_cannot_swap_preauths)
{
    // The residual a height-only binding would leave: two pre-auth demands by one key, at one house, for one total,
    // filed in the SAME block to different payees (two payments the same day). Their coins carry the same tag, so
    // binding the demand height alone does not tell them apart. security decides whether this case must hold or the
    // wallet guards it instead (one pre-auth demand per key, house and total per block); kept separate for that.
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint32_t D = 20000;
    const uint64_t U = 1000000;
    const int H = (int)(D + W - 1);
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> vchPayeeA = ParseHex("76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac");
    const std::vector<unsigned char> vchPayeeB = ParseHex("76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac");
    CHouse house = MakeOpenHouse(1, H, 4 * U);

    const std::vector<unsigned char> vchSigA =
        PreAuthSigOf(MakeDemandTx(1, U, key, true, vchPayeeA, true, true, false, uint256S("a1a1")));   // its own coins
    const auto fnCoinB = ServeCoin(1, U, NoteDemandTag(D, true), TestCustody(vchKey));   // demand B's coins

    BOOST_REQUIRE_EQUAL(CtxReject(MakeDischargeTx(1, U, key, vchPayeeB, (CAmount)U, 0, house.houseID),
                                  H, U, house, fnCoinB), "");
    const std::string strReplay = CtxReject(ReplayDischargeTx(1, U, pub, vchPayeeA, vchSigA, (CAmount)U),
                                            H, U, house, fnCoinB);
    BOOST_CHECK_MESSAGE(!strReplay.empty(),
        "S1X-14 (b): two pre-auth demands filed at height " << D << " by one key for one total: payee A discharged "
        "payee B's demand with A's pre-auth, paying A");
}

// S1X-15 (Claude max s1 run 1, #2/#3; testing reads High): a payout script the house must pay later is chosen by the
// holder alone, so the chain must refuse at the door any script the house cannot pay. Otherwise one holder with a few
// notes makes a demand or swap the house cannot discharge; the window lapses, a protest follows, and the house fails
// with no cure. Two ways a script is unpayable:
// - (b) non-standard: the discharge REDEEM / SWAP_PAY must pay it exactly at vout[0], policy refuses the output
//   (policy.cpp, "scriptpubkey") and main refuses -acceptnonstdtxn, so no stock node relays or mines the payment;
// - (a) the noteholders' fund script: tx_verify refuses every swap-op output to it (bad-note-swap-stray-escrow), but the
//   SWAP open check (IsGoldUnpayableScript) leaves it out.
// The test asserts only that each is refused at the door (any reason), with an accepted P2PKH control each time.
BOOST_AUTO_TEST_CASE(s1x_15_payouts_the_house_cannot_pay_are_refused_at_the_door)
{
    const int H = 5000;
    const uint64_t U = 1000000;
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const CHouse house = MakeOpenHouse(1, H, 2 * U);

    const std::vector<unsigned char> vchP2PKH = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
    const std::vector<unsigned char> vchWitV2 =
        ParseHex("5220" "1111111111111111111111111111111111111111111111111111111111111111");   // OP_2 <32 bytes>
    const std::vector<unsigned char> vchBareTrue = {0x51};                                     // OP_TRUE
    const CScript scriptFund = MutualFundScript();
    const std::vector<unsigned char> vchFund(scriptFund.begin(), scriptFund.end());

    // The premise, checked against the node's own policy: the P2PKH control is standard, the two bad scripts are not.
    {
        txnouttype t;
        BOOST_REQUIRE(::IsStandard(CScript(vchP2PKH.begin(), vchP2PKH.end()), t, true));
        BOOST_REQUIRE(!::IsStandard(CScript(vchWitV2.begin(), vchWitV2.end()), t, true));
        BOOST_REQUIRE(!::IsStandard(CScript(vchBareTrue.begin(), vchBareTrue.end()), t, true));
    }

    // (b) A pre-auth DEMAND at an Open house. The discharge must pay the payout script at vout[0] (validation.cpp,
    // bad-note-redeem-discharge-payout-script), so a non-standard one makes the house's only cure unminable.
    BOOST_REQUIRE_EQUAL(CtxReject(MakeDemandTx(1, U, key, true, vchP2PKH), H, U, house, fnNoCoin), "");
    for (const auto& bad : {vchWitV2, vchBareTrue}) {
        const std::string strReason = CtxReject(MakeDemandTx(1, U, key, true, bad), H, U, house, fnNoCoin);
        BOOST_CHECK_MESSAGE(!strReason.empty(),
                            "S1X-15 (b): a pre-auth DEMAND naming the non-standard payout " + HexStr(bad) +
                            " was accepted; its discharge could never be relayed or mined on main");
    }

    // (a)+(b) A SWAP (holder-unilateral). The holder never reveals the preimage, so SWAP_PAY to the payout script is the
    // house's only way to settle; to the fund it is refused by tx_verify, to a non-standard script by policy.
    {
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
        units.Put(HouseCharterKey(1), charter);
        CChainClock clock;
        clock.nHeight = (uint32_t)(H - 1);
        clock.nMonoTime = clock.nActiveTime = (int64_t)H * 600;
        units.Put(ChainClockKey(), clock);
        UnitsCheckScope scope(&units);

        auto swapReject = [&](const std::vector<unsigned char>& vchPayout) {
            NoteSwap sw;
            sw.nHouseID = 1;
            sw.nUnits = U;
            sw.vchHolderPubKey = vchKey;
            sw.nChainID = 1;
            sw.vchContract = tok.vchContract;
            sw.vchEthAddress = std::vector<unsigned char>(20, 0xe7);
            sw.hashLock = uint256S("51015");
            sw.nRateNamed = 0;   // the unit tests' rate override names the bid
            sw.vchPayoutScript = vchPayout;
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_NOTE_VERSION;
            mtx.nNoteOp = NOTE_OP_SWAP;
            mtx.vin.push_back(CTxIn(COutPoint(uint256S("5a0b"), 0)));
            mtx.vout.push_back(CTxOut(10000, CScript(vchP2PKH.begin(), vchP2PKH.end())));   // fee change
            BOOST_REQUIRE(key.Sign(NoteSwapSigHash(sw, CTransaction(mtx)), sw.vchHolderSig));
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << sw;
            mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
            return CtxReject(mtx, H, U, house, fnNoCoin);
        };
        BOOST_REQUIRE_EQUAL(swapReject(vchP2PKH), "");   // control: the open reaches the end of its checks
        for (const auto& bad : {vchFund, vchWitV2}) {
            const std::string strReason = swapReject(bad);
            BOOST_CHECK_MESSAGE(!strReason.empty(),
                                "S1X-15 (a/b): a SWAP naming the payout " + HexStr(bad) +
                                " was accepted; no SWAP_PAY to it can confirm, so the house can only be protested");
        }
    }
}

// S1X-15, security's extra case (2026-11-24): with a payable (whitelisted) payout the house's cure works. A swap to a
// P2PKH, unpaid a day past its deadline, can be protested (control: the protest path is live in this fixture); the house
// can pay it with a SWAP_PAY to that script; and once it is PAID, no protest can be built against it. Holds on master
// and after the fix (it pins that the whitelist keeps the cure, and that a paid swap closes the protest path).
BOOST_AUTO_TEST_CASE(s1x_15_a_paid_whitelisted_payout_cannot_be_protested)
{
    const uint64_t U = 1000000;
    const int64_t DEADLINE = 4000 * 600;
    const Consensus::GramParams& gpSwap = Params().GetConsensus().GramAt(4000);
    const int64_t nProtestAt = DEADLINE + (int64_t)gpSwap.nSwapPayWindowSecs;   // the first protestable active time
    const int H = (int)(nProtestAt / 600) + 1;
    const CHouse house = MakeOpenHouse(1, H, 2 * U);
    const std::vector<unsigned char> vchP2PKH = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
    const uint256 hashLock = uint256S("51015b");

    CSwapRecord rec;
    rec.nHouseID = 1;
    rec.nUnits = U;
    rec.nBid0 = 1000;
    rec.nDemandHeight = 3500;
    rec.nDeadlineActive = DEADLINE;
    rec.vchPayoutScript = vchP2PKH;

    auto run = [&](const CMutableTransaction& mtx, uint8_t nSettled) {
        CUnitsView units(nullptr);
        SwapOpen(units, hashLock, rec);
        if (nSettled != SWAP_PENDING)
            SwapSettle(units, hashLock, nSettled, 1000, nProtestAt, H - 1, 12960);
        CChainClock clock;
        clock.nHeight = (uint32_t)(H - 1);
        clock.nMonoTime = clock.nActiveTime = nProtestAt;
        units.Put(ChainClockKey(), clock);
        UnitsCheckScope scope(&units);
        return CtxReject(mtx, H, 0, house, fnNoCoin);
    };
    auto protestTx = [&]() {
        NoteSwapProtest pro;
        pro.nHouseID = 1;
        pro.hashLock = hashLock;
        pro.nPrevProtestOpen = house.nProtestOpen;
        pro.nPrevProtestHeight = house.nProtestHeight;
        pro.nPrevProtestDemandHeight = house.nProtestDemandHeight;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_SWAP_PROTEST;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("9a0b"), 0)));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << pro;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        return mtx;
    };
    auto payTx = [&]() {
        NoteSwapPay pay;
        pay.nHouseID = 1;
        pay.hashLock = hashLock;
        pay.nRateNamed = 0;   // the unit tests' rate override names the bid
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_SWAP_PAY;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("9a0c"), 0)));
        mtx.vout.push_back(CTxOut(100 * COIN, CScript(vchP2PKH.begin(), vchP2PKH.end())));   // well over what is owed
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << pay;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        return mtx;
    };

    BOOST_REQUIRE_EQUAL(run(protestTx(), SWAP_PENDING), "");   // control: unpaid past the pay window, protestable
    BOOST_CHECK_EQUAL(run(payTx(), SWAP_PENDING), "");          // the house can cure it: SWAP_PAY to the P2PKH
    const std::string strPaid = run(protestTx(), SWAP_PAID);
    BOOST_CHECK_MESSAGE(!strPaid.empty(), "S1X-15: a SWAP_PROTEST was accepted against a swap the house had already "
                        "PAID to its whitelisted payout");
}


// S1X-14 (security's checks): the demand id travels with the coins. A DEMAND puts its own id on its custody output; a
// discharge refuses burned coins of mixed demands; the 57-byte custody form stays standard to create and to spend. (A
// PROTEST copying the id is exercised by the protest cases above: their inputs and outputs carry one id, and the
// check refuses any other.)
// S1X-42 (testing: Low; Michael 2026-11-26 "Yes, build all 6"): a replaced DEMAND over the same inputs (another payout)
// has another id, so the replaced one's pre-auth signature can't discharge the confirmed demand's coins to its payout.
BOOST_AUTO_TEST_CASE(s1x_42_a_replaced_demands_signature_does_not_discharge_the_confirmed_one)
{
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint32_t D = 20000;
    const uint64_t U = 1000000;
    const int H = (int)(D + W - 1);
    CKey key; key.MakeNewKey(true);
    const std::vector<unsigned char> payout1 = ParseHex("76a914cccccccccccccccccccccccccccccccccccccccc88ac");
    const std::vector<unsigned char> payout2 = ParseHex("76a914dddddddddddddddddddddddddddddddddddddddd88ac");
    CHouse house = MakeOpenHouse(1, H, 4 * U);

    // Same inputs, different payouts (and vectors): different ids.
    CMutableTransaction dem1 = MakeDemandTx(1, U, key, true, payout1);
    CMutableTransaction dem2 = MakeDemandTx(1, U, key, true, payout2);
    BOOST_CHECK(NoteHashPrevouts(CTransaction(dem1)) == NoteHashPrevouts(CTransaction(dem2)));
    uint256 id1, id2;
    BOOST_REQUIRE(NoteCustodyDemandId(dem1.vout[0].scriptPubKey, id1));
    BOOST_REQUIRE(NoteCustodyDemandId(dem2.vout[0].scriptPubKey, id2));
    BOOST_CHECK(id1 != id2);
    BOOST_CHECK(NoteDemandId(CTransaction(dem1), std::vector<uint64_t>{U}, payout1) !=
                NoteDemandId(CTransaction(dem1), std::vector<uint64_t>{U + 1}, payout1));

    // DEMAND2 confirmed (its coins carry id2). A discharge carrying DEMAND1's signature (payout1, signed over id1) is
    // refused; DEMAND2's own (payout2, over id2) is accepted.
    auto fnCoins = [&](const COutPoint&, Coin& coin) {
        coin = Coin(CTxOut(NOTE_DUST_VALUE, TestCustody(std::vector<unsigned char>(key.GetPubKey().begin(),
                                                                                   key.GetPubKey().end()), id2)),
                    (int)D, false, false, false, uint256());
        coin.SetNote(1, U, NoteDemandTag(D, true));
        return true;
    };
    CMutableTransaction disOld = MakeDischargeTx(1, U, key, payout1, (CAmount)U, 0, house.houseID, id1);
    BOOST_CHECK_EQUAL(CtxReject(disOld, H, U, house, fnCoins), "bad-note-redeem-discharge-sig-invalid");
    CMutableTransaction disNew = MakeDischargeTx(1, U, key, payout2, (CAmount)U, 0, house.houseID, id2);
    BOOST_CHECK_EQUAL(CtxReject(disNew, H, U, house, fnCoins), "");
}

BOOST_AUTO_TEST_CASE(s1x_14_the_demand_id_travels_with_the_coins)
{
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint32_t D = 20000;
    const uint64_t U = 1000000;
    const int H = (int)(D + W - 1);
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> payout = ParseHex("76a914cccccccccccccccccccccccccccccccccccccccc88ac");
    CHouse house = MakeOpenHouse(1, H, 4 * U);

    // A DEMAND's custody output carries its own id (S1X-42: NoteDemandId) and pins the holder's key.
    CMutableTransaction dem = MakeDemandTx(1, U, key, true, payout);
    BOOST_CHECK(IsNoteDemandCustodyScript(dem.vout[0].scriptPubKey));
    uint256 id;
    BOOST_REQUIRE(NoteCustodyDemandId(dem.vout[0].scriptPubKey, id));
    BOOST_CHECK(id == NoteDemandId(CTransaction(dem), std::vector<uint64_t>{U}, payout));
    BOOST_CHECK(NoteCustodyKeyIs(dem.vout[0].scriptPubKey, vchKey));

    // A discharge whose burned coins belong to two demands is refused (one served per input: alternate ids).
    {
        const CScript scriptA = TestCustody(vchKey, DemandIdFor());
        const CScript scriptB = TestCustody(vchKey, DemandIdFor(uint256S("b2b2")));
        CMutableTransaction dis = MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID);
        dis.vin.push_back(CTxIn(COutPoint(uint256S("d15d"), 0)));
        auto fnMixed = [&](const COutPoint& op, Coin& coin) {
            coin = Coin(CTxOut(NOTE_DUST_VALUE, op.hash == uint256S("d15c") ? scriptA : scriptB), (int)D, false, false,
                        false, uint256());
            coin.SetNote(1, U / 2, NoteDemandTag(D, true));
            return true;
        };
        BOOST_CHECK_EQUAL(CtxReject(dis, H, U, house, fnMixed), "bad-note-redeem-discharge-mixed-demand");
    }

    // The custody form is standard to create (the DEMAND) and to spend (a discharge burning a tagged custody coin).
    std::string reason;
    BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(dem), reason, true), "DEMAND not standard: " << reason);
    {
        CCoinsView base;
        CCoinsViewCache view(&base);
        CMutableTransaction dis = MakeDischargeTx(1, U, key, payout, (CAmount)U, 0, house.houseID);
        Coin coin(CTxOut(NOTE_DUST_VALUE, TestCustody(vchKey)), (int)D, false, false, false, uint256());
        coin.SetNote(1, U, NoteDemandTag(D, true));
        view.AddCoin(dis.vin[0].prevout, std::move(coin), false);
        BOOST_CHECK(AreInputsStandard(CTransaction(dis), view));
    }
}

// S1X-14 (security's integration ask, as a unit case): a queue demand UPGRADED (Delta-1b, mode 2) gets a fresh id from
// the upgrade's own inputs; a PROTEST of the upgraded coins must carry that id onward, and the discharge then verifies
// the UPGRADE's pre-auth over it - not the original demand's id. The house here is synthetic (reopened with no earlier
// episode, which a real chain can't produce: DEFER needs a protest); the id checks don't read the episode. testing's
// gate runs the reachable path: the first protest still open at the recovery, the upgraded demand's protest joining it.
BOOST_AUTO_TEST_CASE(s1x_14_an_upgraded_demand_keeps_its_id_through_protest_and_discharge)
{
    const uint32_t D = 10000, E = 15000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U = 1000000;
    const uint32_t U2 = E + 3 * W;                         // the upgrade's block (the tag keeps D)
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> payout = ParseHex("76a914dddddddddddddddddddddddddddddddddddddddd88ac");
    const uint32_t tagQueue = NoteDemandTag(D, NOTE_DEMAND_MODE_PREAUTH_QUEUE);
    const uint32_t tagQueueOut = tagQueue | NOTE_DEMAND_PROTESTED_BIT;

    CHouse house = MakeOpenHouse(1, (int)(U2 + W), 2 * U);
    house.nDeferEndedHeight = E;
    house.nLastAttestHeight = U2 + W - 2;                  // still attesting: Open at these heights
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)(U2 + W)), HOUSE_STATUS_OPEN);

    // The upgrade spent its own coins: its id, and the pre-auth it signed over that id.
    const CMutableTransaction upgrade = MakeDemandTx(1, U, key, true, payout, true, true, true, uint256S("a9a9"));
    uint256 idUp;
    BOOST_REQUIRE(NoteCustodyDemandId(upgrade.vout[0].scriptPubKey, idUp));
    BOOST_REQUIRE(idUp != DemandIdFor());
    auto fnUpgraded = [&](uint32_t nTag) {
        return [=](const COutPoint&, Coin& coin) {
            coin = Coin(CTxOut(NOTE_DUST_VALUE, TestCustody(vchKey, idUp)), (int)U2, false, false, false, uint256());
            coin.SetNote(1, U, nTag);
            return true;
        };
    };

    // PROTEST: re-issued onto the upgrade's id - accepted; onto any other id - refused.
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagQueueOut, house, true, idUp), (int)(U2 + W), U, house,
                                fnUpgraded(tagQueue)), "");
    BOOST_CHECK_EQUAL(CtxReject(MakeProtestTx(1, U, key, tagQueueOut, house, true, DemandIdFor()), (int)(U2 + W), U,
                                house, fnUpgraded(tagQueue)), "bad-note-protest-custody-script");

    // Discharge of the protested coins (still on the upgrade's id): the upgrade's pre-auth verifies; a pre-auth over
    // another id (an earlier demand by the same key for the same units) does not.
    const std::vector<unsigned char> vchSigUp = PreAuthSigOf(upgrade);
    const std::vector<unsigned char> vchSigOld =
        PreAuthSigOf(MakeDemandTx(1, U, key, true, payout, true, true, true, uint256S("de3a")));
    const std::string strUp = CtxReject(ReplayDischargeTx(1, U, pub, payout, vchSigUp, (CAmount)U), (int)(U2 + W), U,
                                        house, fnUpgraded(tagQueueOut));
    BOOST_CHECK_MESSAGE(strUp != "bad-note-redeem-discharge-sig-invalid" && strUp != "bad-note-redeem-discharge-custody" &&
                        strUp != "bad-note-redeem-discharge-mixed-demand",
                        "S1X-14: the upgrade's own pre-auth was refused on its protested coins: " << strUp);
    BOOST_CHECK_EQUAL(CtxReject(ReplayDischargeTx(1, U, pub, payout, vchSigOld, (CAmount)U), (int)(U2 + W), U, house,
                                fnUpgraded(tagQueueOut)), "bad-note-redeem-discharge-sig-invalid");
}

namespace {
// Since S1X-14's fix (13503d2) each demand's coins sit on their own custody script (the demand id). Demand A is the
// helpers' default id (MakeProtestTx's); demand B spent other coins, so it has its own.
const uint256 S1X21_ID_B = DemandIdFor(uint256S("b0b0"));
CScript S1X21CustodyB(const std::vector<unsigned char>& vchKey) { return TestCustody(vchKey, S1X21_ID_B); }
CMutableTransaction S1X21HolderProtestB(const CKey& key, uint32_t nTagOut, const CHouse& house)
{
    return MakeProtestTx(1, 1000000, key, nTagOut, house, true, S1X21_ID_B);
}
} // namespace

// S1X-21 (Claude /code-review max run 2, candidate A2-4, 2026-11-24). NoteProtestSigHash covers
// (network, house, unit vector, outputs) only: not the demand tag and no prevout. A holder's protest of demand A is
// public once mined, so anyone can replay its signature against the same holder's OTHER lapsed pre-auth demand B of the
// same size at the same house: copy A's outputs byte for byte (the change goes back to the holder) and write B's tag.
// Within 180 days of the house's last episode the protest finds no cure, so the house is Insolvent at once
// (HouseProtestEpisodeStart). The test takes the protest A as built and signed by the holder, changes only the tag in
// its payload, and spends B's coins. Any refusal passes.
BOOST_AUTO_TEST_CASE(s1x_21_a_protest_signature_cannot_be_replayed_onto_another_demand)
{
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint32_t DA = 20000, DB = 20010;       // two lapsed pre-auth demands, one key, one house, one size
    const uint64_t U = 1000000;
    const int H = (int)(DB + W + 1);
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    CHouse house = MakeOpenHouse(1, H, 4 * U);
    house.nEpisodeEndHeight = (uint32_t)H - 100;   // an earlier episode ended 100 blocks ago: no cure inside 180 days
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
    const uint32_t tagA = NoteDemandTag(DA, true), tagB = NoteDemandTag(DB, true);

    const auto fnCoinB = ServeCoin(1, U, tagB, S1X21CustodyB(vchKey));
    // Control: the holder's own protest of B is accepted (the protest path is live in this fixture).
    BOOST_REQUIRE_EQUAL(CtxReject(S1X21HolderProtestB(key, tagB | NOTE_DEMAND_PROTESTED_BIT, house), H, U, house,
                                  fnCoinB), "");

    // The replay: the holder's protest of A, with only the payload's tag changed to B's.
    CMutableTransaction replay = MakeProtestTx(1, U, key, tagA | NOTE_DEMAND_PROTESTED_BIT, house);
    NoteProtest p;
    { CDataStream ss(replay.vchNotePayload, SER_NETWORK, PROTOCOL_VERSION); ss >> p; }
    p.nDemandTag = tagB | NOTE_DEMAND_PROTESTED_BIT;
    { CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << p; replay.vchNotePayload.assign(ss.begin(), ss.end()); }
    CHouse houseOut;
    const std::string strReplay = CtxReject(replay, H, U, house, fnCoinB, &houseOut);
    BOOST_CHECK_MESSAGE(!strReplay.empty(),
        "S1X-21: the holder's protest signature for demand A protested demand B without the holder; the house is now "
        << (HouseEffectiveStatus(houseOut, H) == HOUSE_STATUS_INSOLVENT ? "Insolvent at once (no cure: an episode ended "
            "100 blocks before)" : "protested"));
}

// S1X-32 (testing 2026-11-26; security 11-26: High). A holder must not be able to leave part of its own pre-auth
// demand undischargeable. A DEMAND re-issues custody coins under ONE pre-auth signature over its whole unit vector. The
// holder alone may plain-REDEEM some of those coins (legal: the voluntary path, tx_verify). The house holds only the
// demand's pre-auth, and the discharge must burn exactly the signed vector's sum, so the rest can never be discharged;
// the holder protests it after the window, only a REDEEM of marked coins lowers nProtestOpen, and the house runs out its
// cure (or is insolvent at once with no cure left). Cost: a few mg of notes, against any Open house.
// PASS (security's suggestion, not yet agreed: a discharge burns any coins carrying the demand id, at most the signed
// total, the floor priced on the units burned): the house discharges the protested remainder with the demand's own
// pre-auth and the protest clears; a 100-coin demand discharges in two txs. FAIL on master c53f2e6:
// bad-note-redeem-discharge-sum at each discharge.
namespace {
// A discharge burning vIn (each a custody coin of the demand) under the demand's pre-auth over vDemandUnits.
CMutableTransaction MakeDischargeOf(uint32_t nHouseID, const std::vector<uint64_t>& vDemandUnits,
                                    const std::vector<unsigned char>& vchPreAuthSig, const CKey& keyHolder,
                                    const std::vector<unsigned char>& vchPayoutScript, const std::vector<COutPoint>& vIn,
                                    CAmount amountPayout)
{
    const CPubKey pub = keyHolder.GetPubKey();
    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = 0;
    redeem.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    redeem.fPreAuthDischarge = 1;
    redeem.vPreAuthUnits = vDemandUnits;
    redeem.vchPayoutScript = vchPayoutScript;
    redeem.vchPreAuthSig = vchPreAuthSig;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    for (const COutPoint& o : vIn)
        mtx.vin.push_back(CTxIn(o));
    mtx.vout.push_back(CTxOut(amountPayout, CScript(vchPayoutScript.begin(), vchPayoutScript.end())));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}
COutPoint CustodyCoin(int i) { return COutPoint(uint256S(strprintf("%x", 0x5320 + i)), 0); }
}

BOOST_AUTO_TEST_CASE(s1x_32_a_holder_cannot_strand_part_of_its_own_preauth_demand)
{
    const uint32_t D = 10000;
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint64_t U1 = 400000, U2 = 600000;
    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const std::vector<unsigned char> vchKey(pub.begin(), pub.end());
    const std::vector<unsigned char> payout = ParseHex("76a914aabbccddeeff0011223344556677889900aabbcc88ac");
    const uint256 id = DemandIdFor();
    const CScript custody = TestCustody(vchKey, id);
    const std::vector<uint64_t> vDemand{U1, U2};
    std::vector<unsigned char> vchPreAuth;
    BOOST_REQUIRE(key.Sign(NotePreAuthSigHash(1, vDemand, payout, id), vchPreAuth));
    const uint32_t nTag = NoteDemandTag(D, NOTE_DEMAND_MODE_PREAUTH);
    const uint32_t nTagProtested = nTag | NOTE_DEMAND_PROTESTED_BIT;

    // Control: inside the window the house discharges both coins together with the demand's pre-auth (par).
    {
        const int H = (int)(D + W - 1);
        CHouse house = MakeOpenHouse(1, H, 2 * (U1 + U2));
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeOf(1, vDemand, vchPreAuth, key, payout, {CustodyCoin(1), CustodyCoin(2)},
                                                    (CAmount)(U1 + U2)),
                                    H, U1 + U2, house, ServeCoin(1, U1, nTag, custody)), "");
    }

    // The split: the holder alone plain-REDEEMs c1 (its own fresh signature over the burn and the outputs). It stays
    // legal (the voluntary path); the defect is what it leaves behind.
    {
        const int H = (int)(D + W - 1);
        CHouse house = MakeOpenHouse(1, H, 2 * (U1 + U2));
        BOOST_CHECK_EQUAL(CtxReject(MakePlainRedeemTx(1, U1, key, (CAmount)U1), H, U1, house,
                                    ServeCoin(1, U1, nTag, custody)), "");
    }

    // After the window the holder protests c2: the house is Stressed and its cure runs.
    const int P = (int)(D + W);
    CHouse houseProtested;
    {
        CHouse house = MakeOpenHouse(1, P, 2 * (U1 + U2) - U1);
        bool fChanged = false;
        BOOST_REQUIRE_EQUAL(CtxReject(MakeProtestTx(1, U2, key, nTagProtested, house, true, id), P, U2, house,
                                      ServeCoin(1, U2, nTag, custody), &houseProtested, &fChanged), "");
        BOOST_REQUIRE_EQUAL(houseProtested.nProtestOpen, 1u);
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(houseProtested, P + 1), HOUSE_STATUS_STRESSED);
    }

    // The house pays c2 with the only authorisation it holds, the demand's pre-auth, at the floor on c2's units. It must
    // be accepted and clear the protest; otherwise only the holder can ever lift it.
    {
        const int Hd = P + 1;
        const CAmount amountFloor = (CAmount)U2 + Interest(U2, (uint32_t)(Hd - (int)(D + W)));
        CHouse houseOut; bool fChanged = false;
        const std::string strReason = CtxReject(MakeDischargeOf(1, vDemand, vchPreAuth, key, payout, {CustodyCoin(2)},
                                                                amountFloor),
                                                Hd, U2, houseProtested, ServeCoin(1, U2, nTagProtested, custody),
                                                &houseOut, &fChanged);
        BOOST_CHECK_MESSAGE(strReason.empty(), "S1X-32: the house cannot discharge the protested remainder of a split "
                            "pre-auth demand: " << strReason << " (the protest can then only be lifted by the holder)");
        if (strReason.empty())
            BOOST_CHECK_EQUAL(houseOut.nProtestOpen, 0u);
        // The other encoding the house could try (the remainder's own vector) is not the holder's signature.
        BOOST_CHECK_EQUAL(CtxReject(MakeDischargeOf(1, {U2}, vchPreAuth, key, payout, {CustodyCoin(2)}, amountFloor),
                                    Hd, U2, houseProtested, ServeCoin(1, U2, nTagProtested, custody)),
                          "bad-note-redeem-discharge-sig-invalid");
        // A discharge still can't burn more than the holder authorised.
        BOOST_CHECK(!CtxReject(MakeDischargeOf(1, vDemand, vchPreAuth, key, payout, {CustodyCoin(2), CustodyCoin(3)},
                                               (CAmount)(U1 + U2 + U2) * 2),
                               Hd, U1 + U2 + U2, houseProtested, ServeCoin(1, U2, nTagProtested, custody)).empty());
    }

    // Fan-out: a 100-coin demand (MAX_NOTE_OUTPUTS) discharged in two txs of 50 coins, inside the window (par).
    {
        const int H = (int)(D + W - 1);
        CHouse house = MakeOpenHouse(1, H, 200000);
        const std::vector<uint64_t> vFan(MAX_NOTE_OUTPUTS, 1000);
        std::vector<unsigned char> vchFanSig;
        BOOST_REQUIRE(key.Sign(NotePreAuthSigHash(1, vFan, payout, id), vchFanSig));
        for (int half = 0; half < 2; half++) {
            std::vector<COutPoint> vIn;
            for (int i = 0; i < 50; i++)
                vIn.push_back(CustodyCoin(100 + 50 * half + i));
            const std::string strReason = CtxReject(MakeDischargeOf(1, vFan, vchFanSig, key, payout, vIn, 50000), H, 50000,
                                                    house, ServeCoin(1, 1000, nTag, custody));
            BOOST_CHECK_MESSAGE(strReason.empty(), "S1X-32 fan-out: half " << half << " of a 100-coin pre-auth demand "
                                "can't be discharged on its own: " << strReason);
        }
    }
}

// ===========================================================================
// testing (2026-11-26): S1X-42 (Claude max run 4 #10; testing Low; fixed in consensus batch 2 with S1X-32, Michael
// 2026-11-26 "Yes, build all 6"). The holder relays DEMAND1 (inputs X, payout P1, pre-auth signature S1); it stalls and
// they replace it with DEMAND2 (the same inputs X, payout P2), which confirms. With the demand id a hash of the inputs
// alone, both have the same id, so a discharge carrying DEMAND1's vector, payout P1 and S1 burns DEMAND2's coins and
// pays P1, the payout the holder replaced. Version-free: the DEMANDs come from MakeDemandTx, which computes the id the
// way its branch does, and the ids are read back from their custody scripts.
// FAILS on master 7f65d2e (the old signature discharges the confirmed demand to P1); passes on mb/consensus-batch-2.
// ===========================================================================
BOOST_AUTO_TEST_CASE(s1x_42_a_replaced_demand_does_not_pay_its_old_payout)
{
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    const uint32_t D = 20000;
    const uint64_t U = 1000000;
    const int H = (int)(D + W - 1);
    CKey key;
    key.MakeNewKey(true);
    const std::vector<unsigned char> vchKey = [&] { const CPubKey p = key.GetPubKey(); return std::vector<unsigned char>(p.begin(), p.end()); }();
    const std::vector<unsigned char> payout1 = ParseHex("76a914a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a188ac");
    const std::vector<unsigned char> payout2 = ParseHex("76a914b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b288ac");
    const CHouse house = MakeOpenHouse(1, H, 4 * U);

    const CMutableTransaction dem1 = MakeDemandTx(1, U, key, true, payout1);   // relayed, stalled, replaced
    const CMutableTransaction dem2 = MakeDemandTx(1, U, key, true, payout2);   // the same input; confirmed at D
    BOOST_REQUIRE(dem1.vin[0].prevout == dem2.vin[0].prevout);
    uint256 id1, id2;
    BOOST_REQUIRE(NoteCustodyDemandId(dem1.vout[0].scriptPubKey, id1));
    BOOST_REQUIRE(NoteCustodyDemandId(dem2.vout[0].scriptPubKey, id2));

    // DEMAND2's custody coin, as the chain holds it.
    const CScript scriptCoin2 = dem2.vout[0].scriptPubKey;
    auto fnCoin2 = [&](const COutPoint&, Coin& coin) {
        coin = Coin(CTxOut(NOTE_DUST_VALUE, scriptCoin2), (int)D, false, false, false, uint256());
        coin.SetNote(1, U, NoteDemandTag(D, true));
        return true;
    };

    // The discharge a stranger builds from DEMAND1's public payload: its vector, its payout P1 and its signature over id1.
    const std::string rOld = CtxReject(MakeDischargeTx(1, U, key, payout1, (CAmount)U, 0, house.houseID, id1), H, U, house, fnCoin2);
    BOOST_CHECK_MESSAGE(!rOld.empty(),
                        std::string("S1X-42: DEMAND1's pre-auth signature (payout P1) discharged the confirmed DEMAND2's coins ") +
                        "to P1, the payout the holder replaced (ids " + (id1 == id2 ? "equal" : "different") + ")");
    BOOST_CHECK_MESSAGE(rOld.empty() || rOld == "bad-note-redeem-discharge-sig-invalid",
                        "S1X-42: refused, but not for its signature: " + rOld);
    // Control: DEMAND2's own authorisation (payout P2, over id2) discharges it.
    const std::string rNew = CtxReject(MakeDischargeTx(1, U, key, payout2, (CAmount)U, 0, house.houseID, id2), H, U, house, fnCoin2);
    BOOST_CHECK_MESSAGE(rNew.empty(), "S1X-42 control: DEMAND2's own discharge was refused: " + rNew);
}

BOOST_AUTO_TEST_SUITE_END()
