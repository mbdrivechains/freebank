// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PROPERTY-BASED GENERATOR v1 (Phase-0 testing programme, 2026-08-04).
//
// Every family validator in this codebase is already a PURE step function:
// (tx, height, resolvers) -> (accept/reject, staged post-state). The unit
// suite drives them with hand-built scenes at hand-picked moments; this file
// drives RANDOM OP SEQUENCES over a multi-entity in-memory World and asserts
// the stated consensus invariants after EVERY accepted op. The difference in
// kind: a hand-written test can only cover compositions someone thought of,
// and the invariants this file guards are exactly the ones whose failure mode
// is "silent supply-shaped corruption" - wrong-but-alive, not a crash.
//
// v1 SCOPE - the bill family (CheckBillOperation) over N bills x M houses,
// ops ISSUE / ENDORSE / DISCOUNT / HRETIRE / HCLAIM / ADVANCE(height), with
// two invariants:
//
//   I1 (the loan-book state invariant, PHASE3_9 s3.1):  for every house H,
//        Sigma{ bill.amount   : owner == H }              == H.nLoanBookFace
//        Sigma{ bill.amount * bill.nMaturityHeight }      == H.LoanWtMaturity()
//      plus the ownership biconditional: owner != 0 => status 'a'.
//
//   I2 (the CM-2 capital cap, hand-copied at FIVE enforcement sites - the
//       drift-bug shape):  nMintedUnits + nDepositUnits <= CapitalCapUnits.
//
// The generator does not know which ops are valid when - it TRIES, applies on
// accept (the write-back ConnectBlock staging performs, which no unit test
// previously did), discards on reject, and the invariants must hold on every
// accepted prefix. Rejections are counted, not asserted: op mix statistics
// are printed so a generator drifting into all-reject territory is visible.
//
// DETERMINISM: SeedInsecureRand(SEED); the seed prints on entry so any
// failure replays exactly. Two worlds x fixed steps keeps `make check` cost
// at ~a second.
//
// MODELLING HONESTY (v1 limits, deliberate):
//  - attestation freshness is EXOGENOUS: DISCOUNT needs a recent attest +
//    live reserve proof; ATTEST is a different validator family, so the world
//    refreshes nLastAttestHeight directly as a modelled background event.
//    The invariant under test is the book Sigma, not attestation honesty.
//  - no Coin/UTXO model: proof coins resolve from the world map; input-layer
//    conservation (tx_verify.cpp) stays with the integration gates.
//  - RETIRE/CLAIM/RECOURSE (holder-held terminal ops) are v1.1: they never
//    touch a loan book, so I1 does not need them; adding them extends
//    coverage of I1's *absence* of change.

#include <bill.h>
#include <house.h>
#include <note.h>

#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <utilstrencodings.h>
#include <version.h>

#include <functional>
#include <map>
#include <vector>

#include <boost/test/unit_test.hpp>

bool CheckBillOperation(const CTransaction& tx, CValidationState& state, int nHeight, const CAmount& nTxFee,
                        const std::function<bool(uint32_t, CBill&)>& fnGetBill,
                        const std::function<bool(const uint256&)>& fnHaveBillHash,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CBill& billOut, CHouse& houseOut, bool& fHouseChanged);

BOOST_FIXTURE_TEST_SUITE(fb_property_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Pub(const CKey& k)
{
    const CPubKey p = k.GetPubKey();
    return std::vector<unsigned char>(p.begin(), p.end());
}

struct WBill {                 // a bill plus the keys the generator must sign with
    CBill bill;
    CKey drawer;
    CKey acceptor;
    CKey holder;               // key over bill.vchHolderPubKey RIGHT NOW
};

struct WHouse {
    CHouse house;
    CKey custody;
    CKey partner;
    CKey reserve;
    COutPoint outReserve;
    Coin coinReserve;
};

struct World {
    std::map<uint32_t, WBill> bills;
    std::map<uint32_t, WHouse> houses;
    int nHeight;
    uint32_t nNextBillID;
    // op-mix statistics, printed at the end
    int nTried[8];
    int nAccepted[8];

    World() : nHeight(10000), nNextBillID(1) {
        for (int i = 0; i < 8; i++) { nTried[i] = 0; nAccepted[i] = 0; }
    }
};

// Deterministic chain stand-in: every height strictly below the current tip
// resolves to a fixed hash (the discount reserve-proof challenge needs it).
bool WorldBlockHash(const World& w, uint32_t nH, uint256& hash)
{
    if ((int)nH >= w.nHeight) return false;
    hash = uint256S("dead");
    return true;
}

bool RunWorldOp(World& w, const CMutableTransaction& mtx,
                CBill& billOut, CHouse& houseOut, bool& fHouseChanged)
{
    const World* pw = &w;
    std::function<bool(uint32_t, CBill&)> getBill =
        [pw](uint32_t id, CBill& out) {
            std::map<uint32_t, WBill>::const_iterator it = pw->bills.find(id);
            if (it == pw->bills.end()) return false;
            out = it->second.bill; return true;
        };
    std::function<bool(const uint256&)> haveHash =
        [pw](const uint256& h) {
            for (std::map<uint32_t, WBill>::const_iterator it = pw->bills.begin(); it != pw->bills.end(); it++)
                if (it->second.bill.billID == h) return true;
            return false;
        };
    std::function<bool(uint32_t, CHouse&)> getHouse =
        [pw](uint32_t id, CHouse& out) {
            std::map<uint32_t, WHouse>::const_iterator it = pw->houses.find(id);
            if (it == pw->houses.end()) return false;
            out = it->second.house; return true;
        };
    std::function<bool(const COutPoint&, Coin&)> getProofCoin =
        [pw](const COutPoint& o, Coin& out) {
            for (std::map<uint32_t, WHouse>::const_iterator it = pw->houses.begin(); it != pw->houses.end(); it++)
                if (it->second.outReserve == o) { out = it->second.coinReserve; return true; }
            return false;
        };
    std::function<bool(uint32_t, uint256&)> getBlockHash =
        [pw](uint32_t nH, uint256& hash) { return WorldBlockHash(*pw, nH, hash); };

    CValidationState state;
    return CheckBillOperation(CTransaction(mtx), state, w.nHeight, 100000,
                              getBill, haveHash, getHouse, getProofCoin, getBlockHash,
                              billOut, houseOut, fHouseChanged);
}

// Apply = the ConnectBlock staging step no unit test previously performed.
void Apply(World& w, const CMutableTransaction& mtx, const CBill& billOut,
           const CHouse& houseOut, bool fHouseChanged, const CKey* pNewHolderKey)
{
    if (mtx.nBillOp == BILL_OP_ISSUE) {
        WBill nb;
        nb.bill = billOut;
        nb.bill.nBillID = w.nNextBillID++;      // the DB's dense-id assignment, modelled
        // keys are threaded by the caller through the fresh-issue path below
        w.bills[nb.bill.nBillID] = nb;
    } else {
        std::map<uint32_t, WBill>::iterator it = w.bills.find(billOut.nBillID);
        BOOST_REQUIRE(it != w.bills.end());
        it->second.bill = billOut;
        if (pNewHolderKey) it->second.holder = *pNewHolderKey;
    }
    if (fHouseChanged) {
        std::map<uint32_t, WHouse>::iterator ih = w.houses.find(houseOut.nHouseID);
        BOOST_REQUIRE(ih != w.houses.end());
        ih->second.house = houseOut;
    }
}

// ------------------------------------------------------------ the invariants
void AssertInvariants(const World& w, const char* whereabouts)
{
    // I1: per-house loan-book Sigma + the u128 weight accumulator
    for (std::map<uint32_t, WHouse>::const_iterator ih = w.houses.begin(); ih != w.houses.end(); ih++) {
        uint64_t nFace = 0;
        unsigned __int128 nWt = 0;
        for (std::map<uint32_t, WBill>::const_iterator ib = w.bills.begin(); ib != w.bills.end(); ib++) {
            const CBill& b = ib->second.bill;
            if (b.nOwnerHouseID != ih->first) continue;
            BOOST_REQUIRE_MESSAGE(b.status == BILL_STATUS_ACTIVE,
                std::string("house-held bill not ACTIVE at ") + whereabouts);
            nFace += (uint64_t)b.amount;
            nWt += (unsigned __int128)(uint64_t)b.amount * (unsigned __int128)b.nMaturityHeight;
        }
        const CHouse& h = ih->second.house;
        BOOST_REQUIRE_MESSAGE(nFace == h.nLoanBookFace,
            std::string("I1 FACE broken at ") + whereabouts);
        BOOST_REQUIRE_MESSAGE(nWt == h.LoanWtMaturity(),
            std::string("I1 WEIGHT broken at ") + whereabouts);
        // I2: the five-site capital cap
        BOOST_REQUIRE_MESSAGE(h.nMintedUnits + h.nDepositUnits <= HouseCapitalCapUnits(h),
            std::string("I2 CAP broken at ") + whereabouts);
    }
}

// -------------------------------------------------------------- op builders
void SetBillPayload(CMutableTransaction& mtx, CDataStream& ss)
{
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
}

CMutableTransaction BuildIssue(World& w, WBill& keysOut)
{
    keysOut.drawer.MakeNewKey(true);
    keysOut.acceptor.MakeNewKey(true);
    keysOut.holder.MakeNewKey(true);

    BillIssue is;
    // random body => unique billID; sizes small and varied
    is.vchEncryptedBody.resize(32 + (InsecureRandBits(5)));
    for (size_t i = 0; i < is.vchEncryptedBody.size(); i++)
        is.vchEncryptedBody[i] = (unsigned char)InsecureRandBits(8);
    is.amount = 1000000 + (CAmount)InsecureRandRange(50000000);
    is.nMaturityHeight = (uint32_t)w.nHeight + 100 + InsecureRandRange(8000);
    is.nGraceBlocks = 5 + InsecureRandRange(1000);
    is.vchDrawerPubKey = Pub(keysOut.drawer);
    is.vchAcceptorPubKey = Pub(keysOut.acceptor);
    is.vchHolderPubKey = Pub(keysOut.holder);

    const CAmount amountEscrow = 1 + (CAmount)InsecureRandRange((uint64_t)is.amount + (uint64_t)is.amount / 2);
    const uint256 billID = BillIDFromBody(is.vchEncryptedBody);
    const uint256 sighash = BillIssueSigHash(billID, is.amount, amountEscrow,
            is.nMaturityHeight, is.nGraceBlocks,
            is.vchDrawerPubKey, is.vchAcceptorPubKey, is.vchHolderPubKey);
    BOOST_REQUIRE(keysOut.drawer.Sign(sighash, is.vchDrawerSig));
    BOOST_REQUIRE(keysOut.acceptor.Sign(sighash, is.vchAcceptorSig));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_ISSUE;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0001"), 0)));
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, BillScriptForPubKey(is.vchHolderPubKey)));
    mtx.vout.push_back(CTxOut(amountEscrow, BillEscrowScript(billID)));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << is;
    SetBillPayload(mtx, ss);
    return mtx;
}

CMutableTransaction BuildEndorse(World& w, const WBill& wb, const CKey& to)
{
    BillEndorse e;
    e.nBillID = wb.bill.nBillID;
    e.endorsement.vchFrom = wb.bill.vchHolderPubKey;
    e.endorsement.vchTo = Pub(to);
    e.endorsement.nAtHeight = (uint32_t)w.nHeight;
    BOOST_REQUIRE(wb.holder.Sign(
            BillEndorseSigHash(wb.bill.billID, e.endorsement.vchTo, e.endorsement.nAtHeight),
            e.endorsement.vchSig));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_ENDORSE;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0002"), 0)));   // title coin
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, BillScriptForPubKey(e.endorsement.vchTo)));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << e;
    SetBillPayload(mtx, ss);
    return mtx;
}

CMutableTransaction BuildDiscount(World& w, const WBill& wb, const WHouse& wh)
{
    BillDiscount d;
    d.nBillID = wb.bill.nBillID;
    d.nHouseID = wh.house.nHouseID;
    d.amountFace = wb.bill.amount;
    // price in (0, face]; mostly sane, occasionally boundary
    d.amountPrice = 1 + (CAmount)InsecureRandRange((uint64_t)wb.bill.amount);
    d.nBillMaturityHeight = wb.bill.nMaturityHeight;
    d.nNoteOutputs = 1;
    d.vUnits.push_back((uint64_t)d.amountPrice);
    d.vchCustodyPubKey = wh.house.vchRedemptionDestPK;
    d.nExpiryHeight = (uint32_t)w.nHeight + 50 + InsecureRandRange(200);
    d.nAsOfHeight = (uint32_t)w.nHeight - 10;
    AttestProof p;
    p.outpoint = wh.outReserve;
    p.vchPubKey = Pub(wh.reserve);
    uint256 hashAsOf;
    BOOST_REQUIRE(WorldBlockHash(w, d.nAsOfHeight, hashAsOf));
    const uint256 challenge = HouseAttestChallenge(wh.house.houseID, d.nAsOfHeight, hashAsOf, p.outpoint);
    BOOST_REQUIRE(wh.reserve.Sign(challenge, p.vchSig));
    d.vReserveProofs.push_back(p);
    d.nPrevMintedUnits = wh.house.nMintedUnits;
    d.nPrevLoanBookFace = wh.house.nLoanBookFace;
    d.nPrevLoanWtMatHi = wh.house.nLoanWtMatHi;
    d.nPrevLoanWtMatLo = wh.house.nLoanWtMatLo;
    d.endorsement.vchFrom = wb.bill.vchHolderPubKey;
    d.endorsement.vchTo = wh.house.vchRedemptionDestPK;
    d.endorsement.nAtHeight = (uint32_t)w.nHeight;
    BOOST_REQUIRE(wb.holder.Sign(
            BillEndorseSigHash(wb.bill.billID, d.endorsement.vchTo, d.endorsement.nAtHeight),
            d.endorsement.vchSig));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_DISCOUNT;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0003"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0004"), 0)));
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, BillScriptForPubKey(d.vchCustodyPubKey)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, BillScriptForPubKey(wb.bill.vchHolderPubKey)));

    CDataStream ss0(SER_NETWORK, PROTOCOL_VERSION); ss0 << d;
    SetBillPayload(mtx, ss0);
    const uint256 sighash = BillDiscountSigHash(d, wb.bill.billID,
            BillHashPrevouts(CTransaction(mtx)), BillHashOutputs(CTransaction(mtx)));
    BOOST_REQUIRE(wb.holder.Sign(sighash, d.vchSellerSig));
    d.vApproverIndex.push_back(0);
    std::vector<unsigned char> vchApprover;
    BOOST_REQUIRE(wh.partner.Sign(sighash, vchApprover));
    d.vApproverSig.push_back(vchApprover);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << d;
    SetBillPayload(mtx, ss);
    return mtx;
}

CMutableTransaction BuildHRetire(const World& w, const WBill& wb, const WHouse& wh)
{
    (void)w;
    BillHRetire h;
    h.nBillID = wb.bill.nBillID;
    h.nOwnerHouseID = wb.bill.nOwnerHouseID;
    h.amountFace = wb.bill.amount;
    h.nBillMaturityHeight = wb.bill.nMaturityHeight;
    h.nPrevLoanBookFace = wh.house.nLoanBookFace;
    h.nPrevLoanWtMatHi = wh.house.nLoanWtMatHi;
    h.nPrevLoanWtMatLo = wh.house.nLoanWtMatLo;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_HRETIRE;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0005"), 1)));   // escrow coin
    mtx.vout.push_back(CTxOut(wb.bill.amount, BillScriptForPubKey(wb.bill.vchHolderPubKey)));
    CDataStream ss0(SER_NETWORK, PROTOCOL_VERSION); ss0 << h;
    SetBillPayload(mtx, ss0);
    BOOST_REQUIRE(wb.acceptor.Sign(BillRetireSigHash(wb.bill.billID,
            BillHashOutputs(CTransaction(mtx))), h.vchAcceptorSig));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << h;
    SetBillPayload(mtx, ss);
    return mtx;
}

CMutableTransaction BuildHClaim(const World& w, const WBill& wb, const WHouse& wh)
{
    (void)w;
    BillHClaim c;
    c.nBillID = wb.bill.nBillID;
    c.nOwnerHouseID = wb.bill.nOwnerHouseID;
    c.amountFace = wb.bill.amount;
    c.nBillMaturityHeight = wb.bill.nMaturityHeight;
    c.nPrevLoanBookFace = wh.house.nLoanBookFace;
    c.nPrevLoanWtMatHi = wh.house.nLoanWtMatHi;
    c.nPrevLoanWtMatLo = wh.house.nLoanWtMatLo;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_HCLAIM;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0006"), 1)));   // escrow coin
    mtx.vout.push_back(CTxOut(wb.bill.amountEscrow, BillScriptForPubKey(wh.house.vchRedemptionDestPK)));
    CDataStream ss0(SER_NETWORK, PROTOCOL_VERSION); ss0 << c;
    SetBillPayload(mtx, ss0);
    const uint256 sighash = BillClaimSigHash(wb.bill.billID, BillHashOutputs(CTransaction(mtx)));
    c.vApproverIndex.push_back(0);
    std::vector<unsigned char> vchApprover;
    BOOST_REQUIRE(wh.partner.Sign(sighash, vchApprover));
    c.vApproverSig.push_back(vchApprover);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << c;
    SetBillPayload(mtx, ss);
    return mtx;
}

WHouse MakeWorldHouse(uint32_t id, int nHeight)
{
    WHouse wh;
    wh.custody.MakeNewKey(true);
    wh.partner.MakeNewKey(true);
    wh.reserve.MakeNewKey(true);
    wh.house = CHouse();
    wh.house.nHouseID = id;
    wh.house.houseID = uint256S(strprintf("%08x", 0xf00d0000 + id));
    wh.house.nTier = HOUSE_TIER_MULTI_PARTNER;
    wh.house.nThresholdM = 1;
    wh.house.status = HOUSE_STATUS_OPEN;
    wh.house.nRegisteredHeight = (uint32_t)nHeight - 5000;
    wh.house.nLastAttestHeight = (uint32_t)nHeight - 10;
    wh.house.amountLastAttestReserves = 100 * COIN;
    wh.house.vchRedemptionDestPK = Pub(wh.custody);
    HousePartner p;
    p.vchPubKey = Pub(wh.partner);
    p.amountPledge = 100 * COIN;
    p.status = HOUSE_PARTNER_ACTIVE;
    wh.house.vPartner.push_back(p);
    wh.outReserve = COutPoint(uint256S(strprintf("%08x", 0xcafe0000 + id)), 0);
    wh.coinReserve = Coin(CTxOut(100 * COIN,
            GetScriptForDestination(wh.reserve.GetPubKey().GetID())), nHeight - 500, false, false, false, 0);
    return wh;
}

enum GenOp { OP_ISSUE = 0, OP_ENDORSE, OP_DISCOUNT, OP_HRETIRE, OP_HCLAIM, OP_ADVANCE, GEN_OPS };

uint32_t PickBill(const World& w)
{
    if (w.bills.empty()) return 0;
    uint64_t k = InsecureRandRange(w.bills.size());
    std::map<uint32_t, WBill>::const_iterator it = w.bills.begin();
    std::advance(it, k);
    return it->first;
}

void RunGenerator(uint32_t nSeed, int nSteps, int nHouses)
{
    SeedInsecureRand(true);
    // fold the per-world seed in deterministically
    for (uint32_t i = 0; i < nSeed % 97; i++) (void)InsecureRand32();
    BOOST_TEST_MESSAGE(strprintf("fb_property generator: seed-fold %u, %d steps, %d houses",
                                 nSeed, nSteps, nHouses));
    World w;
    for (int i = 1; i <= nHouses; i++)
        w.houses[(uint32_t)i] = MakeWorldHouse((uint32_t)i, w.nHeight);

    for (int step = 0; step < nSteps; step++) {
        const int op = (int)InsecureRandRange(GEN_OPS);
        w.nTried[op]++;
        CBill billOut; CHouse houseOut; bool fChanged = false;
        const std::string at = strprintf("step %d op %d height %d", step, op, w.nHeight);

        if (op == OP_ADVANCE) {
            w.nHeight += 1 + (int)InsecureRandRange(2000);
            // modelled background attestation keeps DISCOUNT constructible as
            // time passes (exogenous to the bill family; see header)
            for (std::map<uint32_t, WHouse>::iterator ih = w.houses.begin(); ih != w.houses.end(); ih++) {
                ih->second.house.nLastAttestHeight = (uint32_t)w.nHeight - 10;
                ih->second.coinReserve = Coin(ih->second.coinReserve.out, w.nHeight - 500, false, false, false, 0);
            }
            w.nAccepted[op]++;
            AssertInvariants(w, at.c_str());
            continue;
        }
        if (op == OP_ISSUE) {
            WBill keys;
            const CMutableTransaction mtx = BuildIssue(w, keys);
            if (RunWorldOp(w, mtx, billOut, houseOut, fChanged)) {
                w.nAccepted[op]++;
                WBill nb = keys;
                nb.bill = billOut;
                nb.bill.nBillID = w.nNextBillID++;
                w.bills[nb.bill.nBillID] = nb;
                BOOST_REQUIRE_MESSAGE(!fChanged, "ISSUE claimed a house change");
            }
            AssertInvariants(w, at.c_str());
            continue;
        }

        const uint32_t nBillPick = PickBill(w);
        if (nBillPick == 0) continue;
        WBill& wb = w.bills[nBillPick];

        if (op == OP_ENDORSE) {
            CKey to; to.MakeNewKey(true);
            const CMutableTransaction mtx = BuildEndorse(w, wb, to);
            if (RunWorldOp(w, mtx, billOut, houseOut, fChanged)) {
                w.nAccepted[op]++;
                Apply(w, mtx, billOut, houseOut, fChanged, &to);
            }
        } else if (op == OP_DISCOUNT) {
            const uint32_t nH = 1 + (uint32_t)InsecureRandRange(w.houses.size());
            const CMutableTransaction mtx = BuildDiscount(w, wb, w.houses[nH]);
            if (RunWorldOp(w, mtx, billOut, houseOut, fChanged)) {
                w.nAccepted[op]++;
                Apply(w, mtx, billOut, houseOut, fChanged, NULL);
            }
        } else if (op == OP_HRETIRE) {
            if (wb.bill.nOwnerHouseID == 0) continue;
            const CMutableTransaction mtx = BuildHRetire(w, wb, w.houses[wb.bill.nOwnerHouseID]);
            if (RunWorldOp(w, mtx, billOut, houseOut, fChanged)) {
                w.nAccepted[op]++;
                Apply(w, mtx, billOut, houseOut, fChanged, NULL);
            }
        } else if (op == OP_HCLAIM) {
            if (wb.bill.nOwnerHouseID == 0) continue;
            const CMutableTransaction mtx = BuildHClaim(w, wb, w.houses[wb.bill.nOwnerHouseID]);
            if (RunWorldOp(w, mtx, billOut, houseOut, fChanged)) {
                w.nAccepted[op]++;
                Apply(w, mtx, billOut, houseOut, fChanged, NULL);
            }
        }
        AssertInvariants(w, at.c_str());
    }

    BOOST_TEST_MESSAGE(strprintf(
        "  op mix (accepted/tried): issue %d/%d endorse %d/%d discount %d/%d hretire %d/%d hclaim %d/%d advance %d/%d",
        w.nAccepted[0], w.nTried[0], w.nAccepted[1], w.nTried[1], w.nAccepted[2], w.nTried[2],
        w.nAccepted[3], w.nTried[3], w.nAccepted[4], w.nTried[4], w.nAccepted[5], w.nTried[5]));
    // A generator that stopped accepting the book-touching ops is not testing
    // I1 any more - fail LOUDLY rather than pass vacuously (the Gate 2y lesson).
    BOOST_REQUIRE_MESSAGE(w.nAccepted[OP_DISCOUNT] > 0, "generator vacuous: no DISCOUNT ever accepted");
    BOOST_REQUIRE_MESSAGE(w.nAccepted[OP_HRETIRE] + w.nAccepted[OP_HCLAIM] > 0,
                          "generator vacuous: the book never exited");
}

} // anonymous namespace

BOOST_AUTO_TEST_CASE(loanbook_invariant_under_random_histories)
{
    RunGenerator(1, 400, 3);
    RunGenerator(2, 400, 3);
}

BOOST_AUTO_TEST_SUITE_END()
