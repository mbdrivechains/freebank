// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>
#include <house.h>
#include <note.h>

#include <coins.h>
#include <txdb.h>
#include <consensus/validation.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <utilstrencodings.h>
#include <version.h>

#include <functional>

#include <boost/test/unit_test.hpp>

// Contextual bill-op validator (validation.cpp, external linkage; not in a
// public header) - the note_tests.cpp precedent. B1 (Phase 3.9) extends it with
// the house resolvers: ops 5/7/8 mutate a CHouse, op 6 deliberately does not.
bool CheckBillOperation(const CTransaction& tx, CValidationState& state, int nHeight, const CAmount& nTxFee,
                        const std::function<bool(uint32_t, CBill&)>& fnGetBill,
                        const std::function<bool(const uint256&)>& fnHaveBillHash,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CBill& billOut, CHouse& houseOut, bool& fHouseChanged);

BOOST_FIXTURE_TEST_SUITE(discount_tests, BasicTestingSetup)

//
// The scene, throughout: the spec's worked example (PHASE3_9_DISCOUNT.md 2.6).
// Bill 7, face 40,000,000 sats, escrow bond 8,000,000, maturity H+8640. House 3
// "Ayr", one partner, ample pledge and reserves. Ayr discounts at 39,500,000.
//
static const int      H              = 10000;      // the connect height
static const uint32_t BILL_ID        = 7;
static const uint32_t HOUSE_ID       = 3;
static const CAmount  FACE           = 40000000;
static const CAmount  PRICE          = 39500000;
static const CAmount  ESCROW_BOND    = 8000000;
static const uint32_t MATURITY       = (uint32_t)H + 8640;
static const uint32_t GRACE          = 1008;
static const uint32_t ASOF           = (uint32_t)H - 10;

struct Scene {
    CKey seller;        // the bill's current holder
    CKey custody;       // house 3's redemption/custody key
    CKey partner;       // house 3's single approver
    CKey reserve;       // the key over the reserve coin
    CKey drawer;
    CKey acceptor;
    CKey stranger;

    CBill bill;
    CHouse house;
    COutPoint outReserve;
    Coin coinReserve;
};

static std::vector<unsigned char> Pub(const CKey& k)
{
    const CPubKey p = k.GetPubKey();
    return std::vector<unsigned char>(p.begin(), p.end());
}

static Scene MakeScene()
{
    Scene s;
    s.seller.MakeNewKey(true);
    s.custody.MakeNewKey(true);
    s.partner.MakeNewKey(true);
    s.reserve.MakeNewKey(true);
    s.drawer.MakeNewKey(true);
    s.acceptor.MakeNewKey(true);
    s.stranger.MakeNewKey(true);

    s.bill = CBill();
    s.bill.nBillID = BILL_ID;
    s.bill.billID = uint256S("b111");
    s.bill.amount = FACE;
    s.bill.amountEscrow = ESCROW_BOND;
    s.bill.nIssuedHeight = H - 100;
    s.bill.nMaturityHeight = MATURITY;
    s.bill.nGraceBlocks = GRACE;
    s.bill.vchDrawerPubKey = Pub(s.drawer);
    s.bill.vchAcceptorPubKey = Pub(s.acceptor);
    s.bill.vchHolderPubKey = Pub(s.seller);
    s.bill.status = BILL_STATUS_ACTIVE;
    s.bill.nOwnerHouseID = 0;

    s.house = CHouse();
    s.house.nHouseID = HOUSE_ID;
    s.house.houseID = uint256S("f00d");
    s.house.nTier = HOUSE_TIER_MULTI_PARTNER;
    s.house.nThresholdM = 1;
    s.house.status = HOUSE_STATUS_OPEN;
    s.house.nRegisteredHeight = H - 5000;
    s.house.nLastAttestHeight = (uint32_t)H - 10;
    s.house.amountLastAttestReserves = 100 * COIN;
    s.house.vchRedemptionDestPK = Pub(s.custody);
    HousePartner p;
    p.vchPubKey = Pub(s.partner);
    p.amountPledge = 100 * COIN;
    p.status = HOUSE_PARTNER_ACTIVE;
    s.house.vPartner.push_back(p);

    // One plain P2PKH reserve coin, old enough to have existed at ASOF.
    s.outReserve = COutPoint(uint256S("cafe"), 0);
    s.coinReserve = Coin(CTxOut(100 * COIN,
            GetScriptForDestination(s.reserve.GetPubKey().GetID())), H - 500, false, false, false, 0);
    return s;
}

// Deterministic stand-in for the chain: any height below H resolves.
static bool SceneBlockHash(uint32_t nH, uint256& hash)
{
    if ((int)nH >= H)
        return false;
    hash = uint256S("dead");
    return true;
}

static AttestProof MakeReserveProof(const Scene& s)
{
    AttestProof p;
    p.outpoint = s.outReserve;
    p.vchPubKey = Pub(s.reserve);
    uint256 hashAsOf;
    BOOST_REQUIRE(SceneBlockHash(ASOF, hashAsOf));
    const uint256 challenge = HouseAttestChallenge(s.house.houseID, ASOF, hashAsOf, p.outpoint);
    BOOST_REQUIRE(s.reserve.Sign(challenge, p.vchSig));
    return p;
}

static void SetPayload(CMutableTransaction& mtx, const BillDiscount& d)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << d;
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
}

/** Build a fully valid DISCOUNT and sign it. Both signatures bind the finished
 * transaction, so the outputs must be in place before signing - the caller
 * mutates through the `pre` hook, which runs BEFORE signing (so a mutation
 * still produces correctly signed bytes and isolates the check under test). */
static CMutableTransaction MakeDiscount(const Scene& s, BillDiscount& dOut,
        const std::function<void(BillDiscount&, CMutableTransaction&)>& pre =
            std::function<void(BillDiscount&, CMutableTransaction&)>())
{
    BillDiscount d;
    d.nBillID = BILL_ID;
    d.nHouseID = HOUSE_ID;
    d.amountPrice = PRICE;
    d.amountFace = FACE;
    d.nBillMaturityHeight = MATURITY;
    d.nNoteOutputs = 1;
    d.vUnits.push_back((uint64_t)PRICE);
    d.vchCustodyPubKey = Pub(s.custody);
    d.nExpiryHeight = (uint32_t)H + 100;
    d.nAsOfHeight = ASOF;
    d.vReserveProofs.push_back(MakeReserveProof(s));
    d.nPrevMintedUnits = s.house.nMintedUnits;
    d.nPrevLoanBookFace = s.house.nLoanBookFace;
    d.nPrevLoanWtMatHi = s.house.nLoanWtMatHi;
    d.nPrevLoanWtMatLo = s.house.nLoanWtMatLo;
    d.endorsement.vchFrom = Pub(s.seller);
    d.endorsement.vchTo = Pub(s.custody);
    d.endorsement.nAtHeight = (uint32_t)H;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_DISCOUNT;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0001"), 0)));   // the title coin
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0002"), 0)));   // plain funding
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, BillScriptForPubKey(Pub(s.custody))));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, BillScriptForPubKey(Pub(s.seller))));

    if (pre)
        pre(d, mtx);

    // The stored link carries the CLASSIC endorse digest, so the chain stays
    // verifiable from CBill alone.
    BOOST_REQUIRE(s.seller.Sign(
            BillEndorseSigHash(s.bill.billID, d.endorsement.vchTo, d.endorsement.nAtHeight),
            d.endorsement.vchSig));

    // One shared digest carries both authorities.
    SetPayload(mtx, d);
    const uint256 sighash = BillDiscountSigHash(d, s.bill.billID,
            BillHashPrevouts(CTransaction(mtx)), BillHashOutputs(CTransaction(mtx)));
    BOOST_REQUIRE(s.seller.Sign(sighash, d.vchSellerSig));
    d.vApproverIndex.push_back(0);
    std::vector<unsigned char> vchApprover;
    BOOST_REQUIRE(s.partner.Sign(sighash, vchApprover));
    d.vApproverSig.push_back(vchApprover);
    SetPayload(mtx, d);

    dOut = d;
    return mtx;
}

struct Resolvers {
    std::function<bool(uint32_t, CBill&)> getBill;
    std::function<bool(const uint256&)> haveHash;
    std::function<bool(uint32_t, CHouse&)> getHouse;
    std::function<bool(const COutPoint&, Coin&)> getProofCoin;
    std::function<bool(uint32_t, uint256&)> getBlockHash;
};

static Resolvers MakeResolvers(const Scene& s)
{
    Resolvers r;
    r.getBill = [&s](uint32_t id, CBill& out) {
        if (id == s.bill.nBillID) { out = s.bill; return true; }
        return false;
    };
    r.haveHash = [](const uint256&) { return false; };
    r.getHouse = [&s](uint32_t id, CHouse& out) {
        if (id == s.house.nHouseID) { out = s.house; return true; }
        return false;
    };
    r.getProofCoin = [&s](const COutPoint& o, Coin& out) {
        if (o == s.outReserve) { out = s.coinReserve; return true; }
        return false;
    };
    r.getBlockHash = [](uint32_t nH, uint256& hash) { return SceneBlockHash(nH, hash); };
    return r;
}

static bool RunOp(const Scene& s, const CMutableTransaction& mtx, CValidationState& state,
                  CBill& billOut, CHouse& houseOut, bool& fChanged, CAmount nFee = 100000, int nHeight = H)
{
    const Resolvers r = MakeResolvers(s);
    return CheckBillOperation(CTransaction(mtx), state, nHeight, nFee, r.getBill, r.haveHash,
                              r.getHouse, r.getProofCoin, r.getBlockHash, billOut, houseOut, fChanged);
}

// ===========================================================================
// DISCOUNT (op 5)
// ===========================================================================

BOOST_AUTO_TEST_CASE(discount_happy_path)
{
    const Scene s = MakeScene();
    BillDiscount d;
    const CMutableTransaction mtx = MakeDiscount(s, d);

    CValidationState state;
    CBill billOut; CHouse houseOut; bool fChanged = false;
    BOOST_CHECK(RunOp(s, mtx, state, billOut, houseOut, fChanged));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "");

    // Bill effects: the link is appended, the title moves to custody, and the
    // bill is now HOUSE-HELD - which is what shuts ops 2/3/4 out of it.
    BOOST_CHECK_EQUAL(billOut.vEndorsement.size(), 1);
    BOOST_CHECK(billOut.vEndorsement[0].vchFrom == Pub(s.seller));
    BOOST_CHECK(billOut.vchHolderPubKey == Pub(s.custody));
    BOOST_CHECK_EQUAL(billOut.nOwnerHouseID, HOUSE_ID);
    BOOST_CHECK(billOut.outTitle == COutPoint(CTransaction(mtx).GetHash(), 0));
    BOOST_CHECK_EQUAL(billOut.status, BILL_STATUS_ACTIVE);

    // House effects: notes minted at the PRICE, book carried at FACE.
    BOOST_CHECK(fChanged);
    BOOST_CHECK_EQUAL(houseOut.nMintedUnits, (uint64_t)PRICE);
    BOOST_CHECK_EQUAL(houseOut.nLoanBookFace, (uint64_t)FACE);
    BOOST_CHECK(houseOut.LoanWtMaturity() ==
                (unsigned __int128)(uint64_t)FACE * (unsigned __int128)MATURITY);

    // The flagship flow is mint-funded, so the match-funding slice is 0 and the
    // rule is vacuously satisfied - a house never punishes itself for it.
    BOOST_CHECK(HouseMatchFundingOK(houseOut, H));
}

BOOST_AUTO_TEST_CASE(discount_bill_and_house_rejections)
{
    // Each vector perturbs exactly one thing and must reject with exactly its
    // code. The scene is rebuilt per vector because several mutate house or
    // bill STATE rather than the transaction.
    auto check = [](const std::function<void(Scene&)>& mutateScene,
                    const std::function<void(BillDiscount&, CMutableTransaction&)>& pre,
                    const std::string& reason, int nHeight = H, CAmount nFee = 100000) {
        Scene s = MakeScene();
        if (mutateScene)
            mutateScene(s);
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d, pre);
        CValidationState state;
        CBill billOut; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!RunOp(s, mtx, state, billOut, houseOut, fChanged, nFee, nHeight));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
        BOOST_CHECK(!fChanged);
    };
    const std::function<void(Scene&)> noScene;
    const std::function<void(BillDiscount&, CMutableTransaction&)> noPre;

    // -- 12: the bill ----------------------------------------------------
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nBillID = 99; },
          "bad-bill-unknown");
    check([](Scene& s) { s.bill.status = BILL_STATUS_RETIRED; }, noPre,
          "bad-bill-discount-inactive");
    // Already in someone's book: a second house cannot buy it out from under
    // the first, and the SAME house cannot double-book it.
    check([](Scene& s) { s.bill.nOwnerHouseID = 9; }, noPre,
          "bad-bill-discount-already-held");
    // At maturity exactly - a discount is credit against FUTURE payment.
    check(noScene, noPre, "bad-bill-discount-matured", (int)MATURITY);
    // The two facts every house delta is computed from, byte-exact.
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.amountFace = FACE - 1; },
          "bad-bill-discount-bill-mismatch");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nBillMaturityHeight = MATURITY + 1; },
          "bad-bill-discount-bill-mismatch");

    // -- 13/14: the house ------------------------------------------------
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nHouseID = 99; },
          "bad-bill-discount-no-house");
    // A house under the option clause, or one that has missed its cadence, is
    // not effectively Open, and may not expand its book while holders queue.
    // (Status is DERIVED - setting the stored char would prove nothing.)
    check([](Scene& s) { s.house.nDeferInvokedHeight = (uint32_t)H - 10; }, noPre,
          "bad-bill-discount-house-status");
    check([](Scene& s) { s.house.nLastAttestHeight = 1; }, noPre,
          "bad-bill-discount-house-status");
    // The title must land on the house's CONSENSUS-known custody key.
    check([](Scene& s) { s.house.vchRedemptionDestPK = Pub(s.stranger); }, noPre,
          "bad-bill-discount-custody-key");

    // -- 17: capital cap --------------------------------------------------
    check([](Scene& s) { s.house.vPartner[0].amountPledge = 1000; }, noPre,
          "bad-bill-discount-capital-cap");
    // Deposits share the one lambda ceiling, so live D shrinks discount room.
    check([](Scene& s) {
              s.house.nDepositUnits = (uint64_t)HouseCapitalCapUnits(s.house) - (uint64_t)PRICE + 1;
          }, noPre, "bad-bill-discount-capital-cap");

    // -- 18/19: rho-at-mint ------------------------------------------------
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nAsOfHeight = (uint32_t)H; },
          "bad-bill-discount-reserve-future");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nAsOfHeight = 1; },
          "bad-bill-discount-reserve-stale");
    // The published figure binds only jointly with what is proven live: a house
    // that attested reserves it has since spent cannot discount against them.
    check([](Scene& s) { s.coinReserve.out.nValue = 1000; }, noPre,
          "bad-bill-discount-reserve-cap");
    check([](Scene& s) { s.house.amountLastAttestReserves = 1000; }, noPre,
          "bad-bill-discount-reserve-cap");

    // -- 21: priors --------------------------------------------------------
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nPrevMintedUnits = 1; },
          "bad-bill-discount-priors");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nPrevLoanBookFace = 1; },
          "bad-bill-discount-priors");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nPrevLoanWtMatHi = 1; },
          "bad-bill-discount-priors");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nPrevLoanWtMatLo = 1; },
          "bad-bill-discount-priors");

    // -- 23: expiry --------------------------------------------------------
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.nExpiryHeight = (uint32_t)H - 1; },
          "bad-bill-discount-expired");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) {
              d.nExpiryHeight = (uint32_t)H + BILL_DISCOUNT_MAX_EXPIRY_AHEAD + 1;
          }, "bad-bill-discount-expiry-far");

    // -- 24: the endorsement fee floor (a discount IS an endorsement) -------
    check([](Scene& s) {
              // Push the chain past the soft cap so a floor actually exists.
              BillEndorsement e;
              e.vchFrom = Pub(s.drawer);
              e.vchTo = Pub(s.seller);
              for (size_t j = 0; j < BILL_ENDORSE_SOFT_CAP + 1; j++)
                  s.bill.vEndorsement.push_back(e);
          }, noPre, "bad-bill-discount-fee", H, /*nFee=*/1);

    // -- 25: the link ------------------------------------------------------
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.endorsement.vchFrom[1] ^= 0xff; },
          "bad-bill-discount-not-holder");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) { d.endorsement.nAtHeight = (uint32_t)H + 1; },
          "bad-bill-discount-height");
    check(noScene, [](BillDiscount& d, CMutableTransaction&) {
              d.endorsement.nAtHeight = (uint32_t)H - BILL_ENDORSE_HEIGHT_SLACK - 1;
          }, "bad-bill-discount-height");
}

BOOST_AUTO_TEST_CASE(discount_signature_binding)
{
    // Both authorities sign ONE digest over every value field plus the
    // transaction's prevouts and outputs, so neither side can move a term after
    // the other has signed.
    const Scene s = MakeScene();

    // Seller signature over a different price.
    {
        BillDiscount d;
        CMutableTransaction mtx = MakeDiscount(s, d);
        d.amountPrice = PRICE - 1;
        d.vUnits[0] = (uint64_t)d.amountPrice;
        SetPayload(mtx, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-seller-sig");
    }
    // Moving an OUTPUT after signing breaks the same digest (hashOutputs).
    {
        BillDiscount d;
        CMutableTransaction mtx = MakeDiscount(s, d);
        mtx.vout.push_back(CTxOut(1234, CScript() << OP_TRUE));
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-seller-sig");
    }
    // Moving an INPUT breaks it too (hashPrevouts) - a confirmed discount
    // cannot be replayed with fresh funding.
    {
        BillDiscount d;
        CMutableTransaction mtx = MakeDiscount(s, d);
        mtx.vin[1] = CTxIn(COutPoint(uint256S("beef"), 3));
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-seller-sig");
    }
    // A stranger's approver signature is not the house's consent.
    {
        BillDiscount d;
        CMutableTransaction mtx = MakeDiscount(s, d);
        std::vector<unsigned char> sig;
        const uint256 sighash = BillDiscountSigHash(d, s.bill.billID,
                BillHashPrevouts(CTransaction(mtx)), BillHashOutputs(CTransaction(mtx)));
        BOOST_REQUIRE(s.stranger.Sign(sighash, sig));
        d.vApproverSig[0] = sig;
        SetPayload(mtx, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-approvers");
    }
    // The stored LINK signature is checked independently of the shared digest.
    {
        BillDiscount d;
        CMutableTransaction mtx = MakeDiscount(s, d);
        d.endorsement.vchSig[10] ^= 0xff;
        SetPayload(mtx, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-link-sig");
    }
    // Born strict: a high-S seller signature verifies under plain ECDSA and is
    // refused anyway - there must be no second valid encoding of a confirmed op.
    {
        BillDiscount d;
        CMutableTransaction mtx = MakeDiscount(s, d);
        std::vector<unsigned char> sig = {0x30, 0x25, 0x02, 0x01, 0x01, 0x02, 0x20, 0x7f};
        sig.insert(sig.end(), 31, 0xff);
        d.vchSellerSig = sig;
        SetPayload(mtx, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-seller-sig");
    }
}

BOOST_AUTO_TEST_CASE(discount_payment_equality_and_side_payments)
{
    const Scene s = MakeScene();

    // A note output that pays someone OTHER than the seller leaves the seller
    // short of the price he signed for.
    {
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d,
            [&s](BillDiscount&, CMutableTransaction& m) {
                m.vout[1].scriptPubKey = BillScriptForPubKey(Pub(s.stranger));
            });
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-payment");
    }
    // Splitting the price across two note outputs, both to the seller, is fine.
    {
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d,
            [&s](BillDiscount& x, CMutableTransaction& m) {
                x.nNoteOutputs = 2;
                x.vUnits.clear();
                x.vUnits.push_back((uint64_t)PRICE - 1000);
                x.vUnits.push_back(1000);
                m.vout.push_back(CTxOut(NOTE_DUST_VALUE, BillScriptForPubKey(Pub(s.seller))));
            });
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f));
    }
    // But splitting so that one leg goes elsewhere is not.
    {
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d,
            [&s](BillDiscount& x, CMutableTransaction& m) {
                x.nNoteOutputs = 2;
                x.vUnits.clear();
                x.vUnits.push_back((uint64_t)PRICE - 1000);
                x.vUnits.push_back(1000);
                m.vout.push_back(CTxOut(NOTE_DUST_VALUE, BillScriptForPubKey(Pub(s.stranger))));
            });
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-payment");
    }
    // No side payment: a kickback to the seller past the priced note leg is a
    // way to pay above the signed price without either party admitting it.
    {
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d,
            [&s](BillDiscount&, CMutableTransaction& m) {
                m.vout.push_back(CTxOut(500000, BillScriptForPubKey(Pub(s.seller))));
            });
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-seller-side-payment");
    }
    // Change to anyone else is free.
    {
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d,
            [&s](BillDiscount&, CMutableTransaction& m) {
                m.vout.push_back(CTxOut(500000, BillScriptForPubKey(Pub(s.stranger))));
            });
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f));
    }
    // The vout[0] EXEMPTION: the mandatory title output pays the custody key,
    // and if the seller ever WERE the custody key the op is a self-purchase the
    // shape gate already refuses - so the exemption cannot launder a payment.
    {
        Scene sc = MakeScene();
        sc.bill.vchHolderPubKey = Pub(sc.custody);
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(sc, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(sc, mtx, state, b, h, f));
        // Rejected at the link, before the exemption could ever matter.
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-payment");
    }
}

BOOST_AUTO_TEST_CASE(discount_match_funding_post_state)
{
    // The rule bites only when the book outgrows the escrow: excess =
    // max(0, L - E), slice = min(excess, D). The flagship mint-funded flow has
    // L <= E, hence slice 0, hence vacuous - which is the whole point.
    {
        const Scene s = MakeScene();
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(HouseLoanBookSlice(h), 0);
    }
    // Now give the house a book already well past its escrow, funded by SHORT
    // deposits: the post-state must fail the dollar-duration comparison. The
    // escrow has to be SMALL for the rule to be reachable at all - excess is
    // max(0, L - E), so a heavily over-escrowed house is vacuously fine.
    {
        Scene s = MakeScene();
        s.house.vPartner[0].amountPledge = 40000000;
        s.house.nLoanBookFace = 200000000;
        s.house.SetLoanWtMaturity((unsigned __int128)200000000 * (unsigned __int128)((uint32_t)H + 8640));
        s.house.nDepositUnits = 50000000;
        s.house.SetDepositWtMaturity((unsigned __int128)50000000 * (unsigned __int128)((uint32_t)H + 100));
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-match-funding");
    }
    // The same house with LONG deposits passes: the cure is real and is inside
    // the house's own control.
    {
        Scene s = MakeScene();
        s.house.vPartner[0].amountPledge = 40000000;
        s.house.nLoanBookFace = 200000000;
        s.house.SetLoanWtMaturity((unsigned __int128)200000000 * (unsigned __int128)((uint32_t)H + 8640));
        s.house.nDepositUnits = 50000000;
        s.house.SetDepositWtMaturity((unsigned __int128)50000000 * (unsigned __int128)((uint32_t)H + 20000));
        BillDiscount d;
        const CMutableTransaction mtx = MakeDiscount(s, d);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f));
    }
}

// ===========================================================================
// HRETIRE (7) / HCLAIM (8) - the house-held terminal events
// ===========================================================================

static Scene MakeHeldScene()
{
    Scene s = MakeScene();
    // The post-discount state: the house holds the title, the book carries it.
    s.bill.vchHolderPubKey = Pub(s.custody);
    s.bill.nOwnerHouseID = HOUSE_ID;
    BillEndorsement e;
    e.vchFrom = Pub(s.seller);
    e.vchTo = Pub(s.custody);
    e.nAtHeight = (uint32_t)H - 50;
    s.bill.vEndorsement.push_back(e);
    s.house.nMintedUnits = (uint64_t)PRICE;
    s.house.nLoanBookFace = (uint64_t)FACE;
    s.house.SetLoanWtMaturity((unsigned __int128)(uint64_t)FACE * (unsigned __int128)MATURITY);
    return s;
}

static CMutableTransaction MakeHRetire(const Scene& s,
        const std::function<void(BillHRetire&, CMutableTransaction&)>& pre =
            std::function<void(BillHRetire&, CMutableTransaction&)>())
{
    BillHRetire h;
    h.nBillID = BILL_ID;
    h.nOwnerHouseID = HOUSE_ID;
    h.amountFace = FACE;
    h.nBillMaturityHeight = MATURITY;
    h.nPrevLoanBookFace = s.house.nLoanBookFace;
    h.nPrevLoanWtMatHi = s.house.nLoanWtMatHi;
    h.nPrevLoanWtMatLo = s.house.nLoanWtMatLo;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_HRETIRE;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0003"), 1)));   // the escrow coin
    mtx.vout.push_back(CTxOut(FACE, BillScriptForPubKey(s.bill.vchHolderPubKey)));

    if (pre)
        pre(h, mtx);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << h;
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    BOOST_REQUIRE(s.acceptor.Sign(BillRetireSigHash(s.bill.billID,
            BillHashOutputs(CTransaction(mtx))), h.vchAcceptorSig));
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << h;
    mtx.vchBillPayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
    return mtx;
}

BOOST_AUTO_TEST_CASE(hretire_happy_path_and_rejections)
{
    const Scene s = MakeHeldScene();
    {
        const CMutableTransaction mtx = MakeHRetire(s);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(b.status, BILL_STATUS_RETIRED);
        // The bill LEAVES the book, in both the face and the weight accumulator.
        BOOST_CHECK_EQUAL(b.nOwnerHouseID, 0);
        BOOST_CHECK(f);
        BOOST_CHECK_EQUAL(h.nLoanBookFace, 0);
        BOOST_CHECK(h.LoanWtMaturity() == 0);
        // The minted notes are NOT retired by this: the house's liability to
        // its noteholders is unaffected by the drawee paying.
        BOOST_CHECK_EQUAL(h.nMintedUnits, (uint64_t)PRICE);
    }
    auto reject = [](const std::function<void(Scene&)>& mutateScene,
                     const std::function<void(BillHRetire&, CMutableTransaction&)>& pre,
                     const std::string& reason) {
        Scene s = MakeHeldScene();
        if (mutateScene)
            mutateScene(s);
        const CMutableTransaction mtx = MakeHRetire(s, pre);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    };
    const std::function<void(Scene&)> noScene;
    const std::function<void(BillHRetire&, CMutableTransaction&)> noPre;

    // The ownership pin. A bill no house holds cannot be h-retired, and the
    // pinned face/maturity are what make the house delta payload-derivable.
    reject([](Scene& s) { s.bill.nOwnerHouseID = 0; }, noPre, "bad-bill-hretire-bill-mismatch");
    reject([](Scene& s) { s.bill.nOwnerHouseID = 9; }, noPre, "bad-bill-hretire-bill-mismatch");
    reject(noScene, [](BillHRetire& h, CMutableTransaction&) { h.amountFace = FACE - 1; },
           "bad-bill-hretire-bill-mismatch");
    reject(noScene, [](BillHRetire& h, CMutableTransaction&) { h.nBillMaturityHeight = MATURITY + 1; },
           "bad-bill-hretire-bill-mismatch");
    // Face must reach the holder - which the discount pinned to the custody key.
    reject(noScene, [](BillHRetire&, CMutableTransaction& m) { m.vout[0].nValue = FACE - 1; },
           "bad-bill-hretire-payment");
    // Paying SOMEONE ELSE the face is not discharging the bill: the destination
    // is the record's holder, which the discount pinned to the custody key.
    {
        Scene sc = MakeHeldScene();
        const CMutableTransaction mtx = MakeHRetire(sc,
            [&sc](BillHRetire&, CMutableTransaction& m) {
                m.vout[0].scriptPubKey = BillScriptForPubKey(Pub(sc.stranger));
            });
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(sc, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-hretire-payment");
    }
    reject(noScene, [](BillHRetire& h, CMutableTransaction&) { h.nPrevLoanBookFace = 1; },
           "bad-bill-hretire-priors");
    // The state invariant is ENFORCED, not assumed: a book that does not
    // contain this bill's face cannot have it removed.
    reject([](Scene& s) {
               s.house.nLoanBookFace = 1000;
               s.house.SetLoanWtMaturity(1000);
           }, [](BillHRetire& h, CMutableTransaction&) {
               h.nPrevLoanBookFace = 1000;
               h.nPrevLoanWtMatHi = 0;
               h.nPrevLoanWtMatLo = 1000;
           }, "bad-bill-hretire-book-underflow");
}

BOOST_AUTO_TEST_CASE(hretire_valid_at_every_house_status)
{
    // The drawee must ALWAYS be able to discharge its debt - including into a
    // house that is stressed, deferred or effectively insolvent. The
    // destination is consensus-pinned, so there is nothing to steal.
    for (int i = 0; i < 3; i++) {
        Scene s = MakeHeldScene();
        if (i == 0) s.house.status = HOUSE_STATUS_DEFERRED;
        if (i == 1) s.house.nLastAttestHeight = 1;          // derived-Stressed
        if (i == 2) s.house.status = HOUSE_STATUS_INSOLVENT;
        const CMutableTransaction mtx = MakeHRetire(s);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(b.status, BILL_STATUS_RETIRED);
    }
}

BOOST_AUTO_TEST_CASE(hclaim_quorum_replaces_the_holder_signature)
{
    Scene s = MakeHeldScene();
    const int nLate = (int)MATURITY + (int)GRACE + 1;

    auto build = [&s](const std::function<void(BillHClaim&, CMutableTransaction&)>& pre) {
        BillHClaim h;
        h.nBillID = BILL_ID;
        h.nOwnerHouseID = HOUSE_ID;
        h.amountFace = FACE;
        h.nBillMaturityHeight = MATURITY;
        h.nPrevLoanBookFace = s.house.nLoanBookFace;
        h.nPrevLoanWtMatHi = s.house.nLoanWtMatHi;
        h.nPrevLoanWtMatLo = s.house.nLoanWtMatLo;

        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_HCLAIM;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0003"), 1)));
        mtx.vout.push_back(CTxOut(ESCROW_BOND, BillScriptForPubKey(Pub(s.custody))));
        if (pre)
            pre(h, mtx);
        h.vApproverIndex.push_back(0);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(s.partner.Sign(BillClaimSigHash(s.bill.billID,
                BillHashOutputs(CTransaction(mtx))), sig));
        h.vApproverSig.push_back(sig);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << h;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        return mtx;
    };
    const std::function<void(BillHClaim&, CMutableTransaction&)> noPre;

    {
        const CMutableTransaction mtx = build(noPre);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(b.status, BILL_STATUS_DEFAULTED);
        BOOST_CHECK_EQUAL(b.nOwnerHouseID, 0);
        BOOST_CHECK_EQUAL(h.nLoanBookFace, 0);
    }
    // Not before maturity + grace.
    {
        const CMutableTransaction mtx = build(noPre);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, (int)MATURITY + (int)GRACE));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-hclaim-early");
    }
    // The custody key ALONE is not authority - that is the whole reason op 8
    // exists rather than reusing op 4 on house-held paper.
    {
        CMutableTransaction mtx = build(noPre);
        BillHClaim h;
        BOOST_REQUIRE(DecodeBillPayload(mtx.vchBillPayload, h));
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(s.custody.Sign(BillClaimSigHash(s.bill.billID,
                BillHashOutputs(CTransaction(mtx))), sig));
        h.vApproverSig[0] = sig;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << h;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        CValidationState state; CBill b; CHouse hh; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, hh, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-hclaim-approvers");
    }
    // The quorum signs the exact output set, so a miner cannot redirect it.
    {
        CMutableTransaction mtx = build(noPre);
        mtx.vout[0].scriptPubKey = BillScriptForPubKey(Pub(s.stranger));
        CValidationState state; CBill b; CHouse hh; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, hh, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-hclaim-approvers");
    }
}

BOOST_AUTO_TEST_CASE(hretire_of_the_shortest_bill_cannot_freeze_the_house)
{
    // The rev-1 book-WAM formulation RATCHETED: retiring below-average paper
    // RAISED the book's average maturity and could flip a compliant house into
    // violation - punishing the drawee for paying early. Dollar-duration does
    // not, and the invariant is asserted directly.
    Scene s = MakeScene();
    // Two bills in the book: a short one (this one) and a long one.
    const uint64_t nLongFace = 100000000;
    const uint32_t nLongMat = (uint32_t)H + 20000;
    s.bill.vchHolderPubKey = Pub(s.custody);
    s.bill.nOwnerHouseID = HOUSE_ID;
    s.bill.nMaturityHeight = (uint32_t)H + 500;      // the SHORTEST paper
    s.house.nLoanBookFace = (uint64_t)FACE + nLongFace;
    s.house.SetLoanWtMaturity(
            (unsigned __int128)(uint64_t)FACE * (unsigned __int128)s.bill.nMaturityHeight +
            (unsigned __int128)nLongFace * (unsigned __int128)nLongMat);
    s.house.nDepositUnits = 20000000;
    s.house.SetDepositWtMaturity((unsigned __int128)20000000 * (unsigned __int128)((uint32_t)H + 30000));

    BOOST_REQUIRE(HouseMatchFundingOK(s.house, H));

    const CMutableTransaction mtx = MakeHRetire(s,
        [&s](BillHRetire& h, CMutableTransaction& m) {
            h.nBillMaturityHeight = s.bill.nMaturityHeight;
            m.vout[0].scriptPubKey = BillScriptForPubKey(Pub(s.custody));
        });
    CValidationState state; CBill b; CHouse h; bool f = false;
    BOOST_CHECK(RunOp(s, mtx, state, b, h, f));
    // Still compliant AFTER the shortest bill leaves - no ratchet.
    BOOST_CHECK(HouseMatchFundingOK(h, H));
}

// ===========================================================================
// RECOURSE (6)
// ===========================================================================

static CMutableTransaction MakeRecourse(const Scene& s, const CKey& payer, CAmount nPay,
                                        const std::vector<unsigned char>* pPrevHolder = nullptr)
{
    BillRecourse r;
    r.nBillID = BILL_ID;
    r.vchPayerPubKey = Pub(payer);
    r.vchPrevHolderPubKey = pPrevHolder ? *pPrevHolder : s.bill.vchHolderPubKey;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_RECOURSE;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0004"), 0)));
    mtx.vout.push_back(CTxOut(nPay, BillScriptForPubKey(s.bill.vchHolderPubKey)));

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << r;
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    const uint256 sighash = BillRecourseSigHash(r, s.bill.billID,
            BillHashPrevouts(CTransaction(mtx)), BillHashOutputs(CTransaction(mtx)));
    BOOST_REQUIRE(const_cast<CKey&>(payer).Sign(sighash, r.vchPayerSig));
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << r;
    mtx.vchBillPayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
    return mtx;
}

/** A bill past grace, held by `holder`, with an endorsement chain
 * drawer -> A -> holder. */
static Scene MakeRecourseScene(CKey& keyA)
{
    Scene s = MakeScene();
    keyA.MakeNewKey(true);
    BillEndorsement e1;
    e1.vchFrom = Pub(s.drawer);
    e1.vchTo = Pub(keyA);
    e1.nAtHeight = (uint32_t)H - 200;
    BillEndorsement e2;
    e2.vchFrom = Pub(keyA);
    e2.vchTo = Pub(s.seller);
    e2.nAtHeight = (uint32_t)H - 100;
    s.bill.vEndorsement.push_back(e1);
    s.bill.vEndorsement.push_back(e2);
    return s;
}

BOOST_AUTO_TEST_CASE(recourse_liable_set_and_floor)
{
    CKey keyA;
    Scene s = MakeRecourseScene(keyA);
    const int nLate = (int)MATURITY + (int)GRACE + 1;

    // The IMMEDIATE endorser - the one who delivered the bill - is liable. The
    // off-by-one that excluded them would have let a discount seller walk away
    // the moment the house took their paper.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK(b.vchHolderPubKey == Pub(keyA));
        // Subrogation and NOTHING else: no status change, no owner change, and
        // no house record touched - which is why no house slot is taken.
        BOOST_CHECK_EQUAL(b.status, BILL_STATUS_ACTIVE);
        BOOST_CHECK_EQUAL(b.nOwnerHouseID, 0);
        BOOST_CHECK(!f);
        BOOST_CHECK_EQUAL(b.vEndorsement.size(), 2);   // recourse appends no link
    }
    // The drawer is always liable.
    {
        const CMutableTransaction mtx = MakeRecourse(s, s.drawer, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
    }
    // The ACCEPTOR is not: its escrow bond already answers, and including it
    // enabled a default-then-self-recourse expropriation.
    {
        const CMutableTransaction mtx = MakeRecourse(s, s.acceptor, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-not-liable");
    }
    // Nor is a stranger.
    {
        const CMutableTransaction mtx = MakeRecourse(s, s.stranger, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-not-liable");
    }
    // The floor on an ACTIVE bill is max(face, escrow) - recourse must beat the
    // holder's alternative of simply claiming the bond.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, FACE - 1);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-payment");
    }
    // An over-bonded bill: the escrow, not the face, is the alternative.
    {
        Scene sc = MakeRecourseScene(keyA);
        sc.bill.amountEscrow = FACE * 2;
        {
            const CMutableTransaction mtx = MakeRecourse(sc, keyA, FACE);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(!RunOp(sc, mtx, state, b, h, f, 100000, nLate));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-payment");
        }
        {
            const CMutableTransaction mtx = MakeRecourse(sc, keyA, FACE * 2);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(RunOp(sc, mtx, state, b, h, f, 100000, nLate));
        }
    }
    // Not before maturity + grace: recourse is a cure for non-payment.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, (int)MATURITY + (int)GRACE));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-early");
    }
}

BOOST_AUTO_TEST_CASE(recourse_defaulted_path_and_deficiency)
{
    CKey keyA;
    Scene s = MakeRecourseScene(keyA);
    s.bill.status = BILL_STATUS_DEFAULTED;      // escrow already taken

    // On the 'd' path the floor is the DEFICIENCY, not the face: the holder has
    // already had the bond.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, FACE - ESCROW_BOND);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, H));
        BOOST_CHECK(b.vchHolderPubKey == Pub(keyA));
        BOOST_CHECK_EQUAL(b.status, BILL_STATUS_DEFAULTED);   // status unchanged
    }
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, FACE - ESCROW_BOND - 1);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, H));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-payment");
    }
    // A fully-bonded default leaves no deficiency, so there is nothing to cure
    // and the position is not for sale at zero.
    {
        Scene sc = MakeRecourseScene(keyA);
        sc.bill.status = BILL_STATUS_DEFAULTED;
        sc.bill.amountEscrow = FACE;
        const CMutableTransaction mtx = MakeRecourse(sc, keyA, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(sc, mtx, state, b, h, f, 100000, H));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-no-deficiency");
    }
    // A retired bill is nobody's problem.
    {
        Scene sc = MakeRecourseScene(keyA);
        sc.bill.status = BILL_STATUS_RETIRED;
        const CMutableTransaction mtx = MakeRecourse(sc, keyA, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(sc, mtx, state, b, h, f, 100000, H));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-status");
    }
}

BOOST_AUTO_TEST_CASE(recourse_never_on_house_held_paper)
{
    // THE rev-1 CRITICAL. RECOURSE requires only the payer's signature, so if it
    // were legal on house-held paper one custody key could pay itself, take the
    // position, and strip the bill out of the loan book - bypassing HCLAIM's
    // quorum entirely, and leaving nLoanBookFace asserting an asset the house no
    // longer holds.
    CKey keyA;
    Scene s = MakeRecourseScene(keyA);
    s.bill.nOwnerHouseID = HOUSE_ID;
    s.bill.vchHolderPubKey = Pub(s.custody);
    const int nLate = (int)MATURITY + (int)GRACE + 1;

    for (int i = 0; i < 2; i++) {
        // Both the third-party payer and the custody key itself are refused,
        // and refused BEFORE any liable-set or floor reasoning happens.
        const CKey& payer = (i == 0) ? keyA : s.drawer;
        const CMutableTransaction mtx = MakeRecourse(s, payer, FACE * 3);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-house-held");
    }
}

BOOST_AUTO_TEST_CASE(recourse_holder_who_arrived_by_recourse)
{
    // A holder who took the position by an earlier RECOURSE has no delivering
    // link (recourse appends none), so the WHOLE chain answers - the no-match
    // rule. Here the chain is drawer -> A -> B, but the holder is A again,
    // having recoursed. The last link TO A is index 0, so k = 0 and only the
    // drawer is liable... unless the no-match rule is misapplied.
    CKey keyA, keyB;
    Scene s = MakeScene();
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    BillEndorsement e1; e1.vchFrom = Pub(s.drawer); e1.vchTo = Pub(keyA); e1.nAtHeight = (uint32_t)H - 300;
    BillEndorsement e2; e2.vchFrom = Pub(keyA);     e2.vchTo = Pub(keyB); e2.nAtHeight = (uint32_t)H - 200;
    s.bill.vEndorsement.push_back(e1);
    s.bill.vEndorsement.push_back(e2);
    s.bill.vchHolderPubKey = Pub(keyA);             // A recoursed against B's seller
    const int nLate = (int)MATURITY + (int)GRACE + 1;

    // Last link TO A is index 0, so the liable set is {drawer} u {vFrom[0]} =
    // {drawer} minus the holder. The drawer pays.
    {
        const CMutableTransaction mtx = MakeRecourse(s, s.drawer, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
    }
    // B is NOT liable to A: B came after A in the chain, so A cannot walk the
    // loss forward onto someone who took it from him.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyB, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-not-liable");
    }
    // And the holder can never pay himself.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-self");
    }
}

BOOST_AUTO_TEST_CASE(recourse_prior_pin_and_signature)
{
    CKey keyA;
    Scene s = MakeRecourseScene(keyA);
    const int nLate = (int)MATURITY + (int)GRACE + 1;

    // The declared prior holder must BE the record's holder: otherwise a stale
    // recourse, signed against an earlier holder, could still land.
    {
        const std::vector<unsigned char> wrong = Pub(s.stranger);
        const CMutableTransaction mtx = MakeRecourse(s, keyA, FACE, &wrong);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-priors");
    }
    // The payer signature binds the outputs, so a miner cannot redirect the
    // payment away from the holder and keep the subrogation.
    {
        CMutableTransaction mtx = MakeRecourse(s, keyA, FACE);
        mtx.vout[0].scriptPubKey = BillScriptForPubKey(Pub(s.stranger));
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        // Fails the floor first: the holder is no longer being paid at all.
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-payment");
    }
    {
        CMutableTransaction mtx = MakeRecourse(s, keyA, FACE);
        mtx.vout.push_back(CTxOut(1, CScript() << OP_TRUE));   // outputs moved after signing
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-payer-sig");
    }
}

// ===========================================================================
// T-d6 GAP VECTORS. The five cases above already cover most of the T-d6 row -
// the acceptor, the stranger, both floors, the over-bonded 'a' case,
// deficiency = 0, early, retired, house-held, payer == holder, the prior pin,
// the signature, and the last-match rule - because T-d7b built them while
// shipping recourse. What follows is the remainder.
// ===========================================================================

//
// THE DISCOUNT SELLER: in the liable set by construction, and reachable
// through exactly ONE door.
//
// Spec §7(2) claimed the seller "is in the set the moment Dunlop's bank takes
// his paper". That names the one moment they are LEAST reachable, and it
// contradicts §7's own 'Ordering with the house book' paragraph. Set
// membership is check 32; check 30 refuses the whole operation two checks
// earlier. Traced:
//
//   house-held (post-DISCOUNT)  -> bad-bill-recourse-house-held
//   after HRETIRE  (status 'r') -> bad-bill-recourse-status, NEVER recoursable
//   after HCLAIM   (status 'd') -> available, DEFICIENCY arm only
//
// So the seller's covenant is only ever worth the deficiency - and on
// fully-bonded paper it is worth NOTHING, because the deficiency is zero and
// check 33 refuses. A house that discounts well-bonded paper has no recourse
// against its seller at all. That is the cascade working as designed (the
// house already took a full bond), but it is an economic property of the
// discount product, so it is pinned here rather than left to be rediscovered.
//
BOOST_AUTO_TEST_CASE(recourse_the_discount_seller_is_reachable_only_after_hclaim)
{
    // The chain as a discount leaves it: drawer -> seller, then the DISCOUNT's
    // own link seller -> custody. The seller is the delivering endorser, so the
    // last-match scan puts them squarely in the set.
    //
    // PREMISE, AND WHERE IT IS PINNED. This scene is hand-built rather than
    // produced by running a DISCOUNT, so on its own it proves nothing about
    // what a DISCOUNT actually appends - if op 5 stopped appending the link, or
    // appended it with a different vchFrom, everything below would still pass.
    // The premise is pinned by discount_happy_path, which asserts exactly
    // vEndorsement.size() == 1, vEndorsement[0].vchFrom == Pub(seller),
    // vchHolderPubKey == Pub(custody) and nOwnerHouseID == HOUSE_ID on a real
    // op-5 run. That is a CROSS-TEST COUPLING: weaken those four assertions and
    // this case silently starts testing a chain shape the chain no longer
    // produces. Named here so it is visible rather than discovered.
    auto sceneAfterDiscount = [](CBill& bill, const Scene& s) {
        BillEndorsement e1;
        e1.vchFrom = Pub(s.drawer);
        e1.vchTo = Pub(s.seller);
        e1.nAtHeight = (uint32_t)H - 200;
        BillEndorsement eDisc;                       // the DISCOUNT's real link
        eDisc.vchFrom = Pub(s.seller);
        eDisc.vchTo = Pub(s.custody);
        eDisc.nAtHeight = (uint32_t)H - 100;
        bill.vEndorsement.push_back(e1);
        bill.vEndorsement.push_back(eDisc);
        bill.vchHolderPubKey = Pub(s.custody);
    };

    // (1) While the house holds it, check 30 refuses before any liable-set
    // reasoning happens at all. This is the door §7(2) pointed at.
    {
        Scene s = MakeScene();
        sceneAfterDiscount(s.bill, s);
        s.bill.nOwnerHouseID = HOUSE_ID;
        const CMutableTransaction mtx = MakeRecourse(s, s.seller, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, (int)MATURITY + (int)GRACE + 1));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-house-held");
    }
    // (2) HRETIRE clears the owner but writes status 'r' - the drawee paid, so
    // there is nothing to cure, forever.
    {
        Scene s = MakeScene();
        sceneAfterDiscount(s.bill, s);
        s.bill.nOwnerHouseID = 0;
        s.bill.status = BILL_STATUS_RETIRED;
        const CMutableTransaction mtx = MakeRecourse(s, s.seller, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, (int)MATURITY + (int)GRACE + 1));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-status");
    }
    // (3) HCLAIM clears the owner and writes 'd'. NOW the seller is reachable -
    // and the floor is the deficiency, never the face.
    {
        Scene s = MakeScene();
        sceneAfterDiscount(s.bill, s);
        s.bill.nOwnerHouseID = 0;
        s.bill.status = BILL_STATUS_DEFAULTED;
        const CAmount nDeficiency = FACE - ESCROW_BOND;
        {   // one satoshi short of the deficiency is not a cure
            const CMutableTransaction mtx = MakeRecourse(s, s.seller, nDeficiency - 1);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, H));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-payment");
        }
        {   // exactly the deficiency is
            const CMutableTransaction mtx = MakeRecourse(s, s.seller, nDeficiency);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, H));
            BOOST_CHECK(b.vchHolderPubKey == Pub(s.seller));   // subrogation
            BOOST_CHECK_EQUAL(b.status, BILL_STATUS_DEFAULTED);
            BOOST_CHECK(!f);
        }
    }
    // (4) THE ONE THAT MATTERS COMMERCIALLY: fully-bonded paper. Same door,
    // same seller, and the covenant is worth nothing - there is no deficiency
    // to buy, so the house eats the whole credit loss it thought it had laid
    // off onto its seller.
    {
        Scene s = MakeScene();
        sceneAfterDiscount(s.bill, s);
        s.bill.nOwnerHouseID = 0;
        s.bill.status = BILL_STATUS_DEFAULTED;
        s.bill.amountEscrow = FACE;                  // bond == face
        const CMutableTransaction mtx = MakeRecourse(s, s.seller, FACE);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, H));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-no-deficiency");
    }
}

//
// THE TWO DEGENERATE ENDS OF THE LIABLE-SET SCAN.
//
// Rev 2's §4 check 32 expressed the no-match rule as "k = vEndorsement.size()
// - 1". On a never-endorsed bill that is -1 on the unsigned quantity the code
// actually uses - SIZE_MAX, an unbounded range. The implementation is a
// half-open end (nLiableEnd = vEndorsement.size()) and degrades correctly, but
// nothing pinned it, and a reimplementation from the spec sentence would have
// been wrong exactly here. The spec is corrected; this is the pin.
//
BOOST_AUTO_TEST_CASE(recourse_liable_set_degenerate_and_no_match_edges)
{
    const int nLate = (int)MATURITY + (int)GRACE + 1;

    // (a) A never-endorsed bill: the drawer is the whole liable set, and the
    // scan must not run off the end of an empty vector.
    {
        Scene s = MakeScene();                       // no endorsements at all
        BOOST_REQUIRE(s.bill.vEndorsement.empty());
        {
            const CMutableTransaction mtx = MakeRecourse(s, s.drawer, FACE);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
            BOOST_CHECK(b.vchHolderPubKey == Pub(s.drawer));
        }
        {
            const CMutableTransaction mtx = MakeRecourse(s, s.stranger, FACE);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-not-liable");
        }
    }

    // (b) A TRUE no-match: endorsements exist but NONE of them delivered to the
    // current holder, so the whole chain answers. Distinct from the existing
    // holder-arrived-by-recourse case, where the last link TO the holder is at
    // index 0 and the set therefore SHRINKS to the drawer alone. Here the
    // holder is a key that appears nowhere in the chain, which is what a
    // holder who arrived by recourse against the FIRST endorsee looks like.
    {
        Scene s = MakeScene();
        CKey keyA, keyB, keyC;
        keyA.MakeNewKey(true); keyB.MakeNewKey(true); keyC.MakeNewKey(true);
        BillEndorsement e1; e1.vchFrom = Pub(s.drawer); e1.vchTo = Pub(keyA); e1.nAtHeight = (uint32_t)H - 300;
        BillEndorsement e2; e2.vchFrom = Pub(keyA);     e2.vchTo = Pub(keyB); e2.nAtHeight = (uint32_t)H - 200;
        BillEndorsement e3; e3.vchFrom = Pub(keyB);     e3.vchTo = Pub(keyC); e3.nAtHeight = (uint32_t)H - 100;
        s.bill.vEndorsement.push_back(e1);
        s.bill.vEndorsement.push_back(e2);
        s.bill.vEndorsement.push_back(e3);
        s.bill.vchHolderPubKey = Pub(s.stranger);    // delivered to by NO link

        // Every vchFrom in the chain is liable, including the last one - if the
        // no-match rule were misread as "nobody", keyC's endorser keyB would
        // walk, and if it were misread as SIZE_MAX the scan would read past the
        // vector.
        for (const CKey* k : { &s.drawer, &keyA, &keyB }) {
            const CMutableTransaction mtx = MakeRecourse(s, *k, FACE);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
            BOOST_CHECK(b.vchHolderPubKey == Pub(*k));
        }
        // keyC only ever RECEIVED; it is nobody's endorser and is not liable.
        {
            const CMutableTransaction mtx = MakeRecourse(s, keyC, FACE);
            CValidationState state; CBill b; CHouse h; bool f = false;
            BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-not-liable");
        }
    }
}

//
// THE FLOOR IS A MINIMUM, NOT AN EQUALITY - and BillValuePaidTo SUMS.
//
// Check 33 is `BillValuePaidTo(tx, holder) >= floor`, over EVERY output on the
// holder's script. The wallet can never produce either shape: RecourseBill
// hard-codes one output at exactly the floor and re-keys its change off the
// holder's script, so no RPC or integration path can reach these. Spec §3
// asserts both ("outputs must pay >= the floor"); nothing tested them.
//
BOOST_AUTO_TEST_CASE(recourse_floor_is_a_minimum_not_an_equality)
{
    CKey keyA;
    Scene s = MakeRecourseScene(keyA);
    const int nLate = (int)MATURITY + (int)GRACE + 1;
    const CAmount nFloor = std::max(FACE, ESCROW_BOND);

    // Overpaying is legal. A payer may want the position badly enough.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, nFloor + 1234567);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK(b.vchHolderPubKey == Pub(keyA));
    }
    // And the floor is met by the SUM across outputs, not by any single one.
    // Built here rather than through MakeRecourse because the digest binds
    // hashOutputs - the outputs must be final before the payer signs, so a
    // post-signing edit would fail as a signature error and look like the
    // wrong thing entirely.
    {
        BillRecourse r;
        r.nBillID = BILL_ID;
        r.vchPayerPubKey = Pub(keyA);
        r.vchPrevHolderPubKey = s.bill.vchHolderPubKey;

        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_RECOURSE;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0004"), 0)));
        const CScript scriptHolder = BillScriptForPubKey(s.bill.vchHolderPubKey);
        const CAmount nLeg = nFloor / 3;
        mtx.vout.push_back(CTxOut(nLeg, scriptHolder));
        mtx.vout.push_back(CTxOut(nLeg, scriptHolder));
        mtx.vout.push_back(CTxOut(nFloor - 2 * nLeg, scriptHolder));   // sums to exactly the floor
        // A leg to someone else must NOT count toward the holder's floor.
        mtx.vout.push_back(CTxOut(9 * COIN, BillScriptForPubKey(Pub(s.stranger))));

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << r;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        const uint256 sighash = BillRecourseSigHash(r, s.bill.billID,
                BillHashPrevouts(CTransaction(mtx)), BillHashOutputs(CTransaction(mtx)));
        BOOST_REQUIRE(keyA.Sign(sighash, r.vchPayerSig));
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << r;
        mtx.vchBillPayload = std::vector<unsigned char>(ss2.begin(), ss2.end());

        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK(b.vchHolderPubKey == Pub(keyA));
    }
}

//
// REPEATED RECOURSE UP THE CHAIN (the last T-d6 row item).
//
// After a cure the payer IS the holder, and the set minus them is still
// liable, so the next endorser up may cure in turn. Two things must hold and
// neither is obvious: the set must not have shrunk to nothing, and the party
// who just paid must not be able to pay again - they are now the holder, so
// check 31 catches them BEFORE check 32 and the reject is
// bad-bill-recourse-self, not -not-liable. Getting that string wrong is the
// easiest way to write this vector so it passes for the wrong reason.
//
// NOTE for whoever writes the integration half: the per-bill mempool guard
// (T-d5) means two RECOURSE ops on one bill can no longer co-pool, so the gate
// must mine between hops or the second is silently refused.
//
BOOST_AUTO_TEST_CASE(recourse_repeated_up_the_chain)
{
    Scene s = MakeScene();
    CKey keyA, keyB;
    keyA.MakeNewKey(true); keyB.MakeNewKey(true);
    BillEndorsement e1; e1.vchFrom = Pub(s.drawer); e1.vchTo = Pub(keyA);     e1.nAtHeight = (uint32_t)H - 300;
    BillEndorsement e2; e2.vchFrom = Pub(keyA);     e2.vchTo = Pub(keyB);     e2.nAtHeight = (uint32_t)H - 200;
    BillEndorsement e3; e3.vchFrom = Pub(keyB);     e3.vchTo = Pub(s.seller); e3.nAtHeight = (uint32_t)H - 100;
    s.bill.vEndorsement.push_back(e1);
    s.bill.vEndorsement.push_back(e2);
    s.bill.vEndorsement.push_back(e3);
    const int nLate = (int)MATURITY + (int)GRACE + 1;
    const CAmount nFloor = std::max(FACE, ESCROW_BOND);

    // Hop 1: B, the endorser who delivered to the holder, cures.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyB, nFloor);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK(b.vchHolderPubKey == Pub(keyB));
        s.bill = b;                                  // the chain moves on
    }
    // B is now the holder and cannot cure again. Check 31 fires first, so the
    // string is -self even though B is also still in the liable set.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyB, nFloor);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-self");
    }
    // Hop 2: the set is recomputed against the NEW holder. The last link to B
    // is index 1, so liable = {drawer, A} - and A, who endorsed to B, may cure.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyA, nFloor);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK(b.vchHolderPubKey == Pub(keyA));
        s.bill = b;
    }
    // Hop 3: the drawer, the end of the line. The last link to A is index 0,
    // so liable = {drawer} alone - the set really does shrink as it walks up.
    {
        const CMutableTransaction mtx = MakeRecourse(s, keyB, nFloor);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-not-liable");
    }
    {
        const CMutableTransaction mtx = MakeRecourse(s, s.drawer, nFloor);
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(RunOp(s, mtx, state, b, h, f, 100000, nLate));
        BOOST_CHECK(b.vchHolderPubKey == Pub(s.drawer));
        BOOST_CHECK_EQUAL(b.vEndorsement.size(), 3);   // no link ever appended
    }
}

// ===========================================================================
// Check 27: the shipped ops are shut out of house-held paper, unconditionally
// ===========================================================================

BOOST_AUTO_TEST_CASE(shipped_ops_refuse_house_held_bills)
{
    const Scene s = MakeHeldScene();

    // ENDORSE. Without this conjunct, one custody key could endorse an entire
    // loan book to itself.
    {
        BillEndorse e;
        e.nBillID = BILL_ID;
        e.endorsement.vchFrom = Pub(s.custody);
        e.endorsement.vchTo = Pub(s.stranger);
        e.endorsement.nAtHeight = (uint32_t)H;
        BOOST_REQUIRE(const_cast<CKey&>(s.custody).Sign(
                BillEndorseSigHash(s.bill.billID, e.endorsement.vchTo, e.endorsement.nAtHeight),
                e.endorsement.vchSig));
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_ENDORSE;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0005"), 0)));
        mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, BillScriptForPubKey(e.endorsement.vchTo)));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << e;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-endorse-house-held");
    }
    // RETIRE: house-held paper discharges through op 7, which takes it out of
    // the book. Op 3 would pay the holder and leave nLoanBookFace overstated.
    {
        BillRetire r;
        r.nBillID = BILL_ID;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_RETIRE;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0006"), 1)));
        mtx.vout.push_back(CTxOut(FACE, BillScriptForPubKey(s.bill.vchHolderPubKey)));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << r;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        BOOST_REQUIRE(const_cast<CKey&>(s.acceptor).Sign(
                BillRetireSigHash(s.bill.billID, BillHashOutputs(CTransaction(mtx))), r.vchAcceptorSig));
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << r;
        mtx.vchBillPayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-retire-house-held");
    }
    // CLAIM: the escrow on house-held paper needs the quorum (op 8), never the
    // custody key's lone signature.
    {
        BillClaim c;
        c.nBillID = BILL_ID;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_CLAIM;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0007"), 1)));
        mtx.vout.push_back(CTxOut(ESCROW_BOND, BillScriptForPubKey(Pub(s.custody))));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << c;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        BOOST_REQUIRE(const_cast<CKey&>(s.custody).Sign(
                BillClaimSigHash(s.bill.billID, BillHashOutputs(CTransaction(mtx))), c.vchHolderSig));
        CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
        ss2 << c;
        mtx.vchBillPayload = std::vector<unsigned char>(ss2.begin(), ss2.end());
        CValidationState state; CBill b; CHouse h; bool f = false;
        BOOST_CHECK(!RunOp(s, mtx, state, b, h, f, 100000, (int)MATURITY + (int)GRACE + 1));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-claim-house-held");
    }
}

// ===========================================================================
// T-d7: the shared payload-pure output tagger
// ===========================================================================

BOOST_AUTO_TEST_CASE(bill_coin_tagger_is_the_one_decision_point)
{
    // Four places have to agree on WHICH v11 outputs are consensus-tagged:
    // AddCoins, the mempool view, the wallet's funding skip and the wallet's
    // note collector. Enumerating that four times is how a discount's minted
    // notes end up offered as fee coins - the fifth recurrence of a class this
    // codebase has been bitten by four times already. One tagger, pinned here.
    const Scene s = MakeScene();
    BillDiscount d;
    const CMutableTransaction mtx = MakeDiscount(s, d);
    const CTransaction tx(mtx);

    // vout[0]: the title, tagged fBill, id deliberately 0 (it does not exist
    // until the issuing tx connects - callers that have it stamp it on).
    Coin c0;
    ApplyBillCoinTags(tx, 0, c0);
    BOOST_CHECK(c0.fBill);
    BOOST_CHECK(!c0.fBillEscrow);
    BOOST_CHECK(!c0.fNote);
    BOOST_CHECK_EQUAL(c0.nBillID, 0u);

    // vout[1]: the minted note leg - the seller's actual payment. It must carry
    // the REAL house id and unit face, or the wallet's note machinery cannot
    // see it and the units are unspendable.
    Coin c1;
    ApplyBillCoinTags(tx, 1, c1);
    BOOST_CHECK(c1.fNote);
    BOOST_CHECK(!c1.fBill);
    BOOST_CHECK_EQUAL(c1.nHouseID, HOUSE_ID);
    BOOST_CHECK_EQUAL(c1.nNoteUnits, (uint64_t)PRICE);
    BOOST_CHECK_EQUAL(c1.nDemandHeight, 0u);

    // Anything past the note leg is free change and must stay spendable, or the
    // house cannot pay its own fees.
    Coin c2;
    ApplyBillCoinTags(tx, 2, c2);
    BOOST_CHECK(!c2.fBill && !c2.fBillEscrow && !c2.fNote);

    // The tagger must agree with AddCoins for EVERY index - that agreement is
    // the property that stops the four call sites drifting apart.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        AddCoins(cache, tx, 100, 0, 0, -1, 0, /*nBillID=*/BILL_ID, 0);
        for (unsigned int i = 0; i < tx.vout.size(); i++) {
            Coin probe;
            ApplyBillCoinTags(tx, i, probe);
            const Coin& real = cache.AccessCoin(COutPoint(tx.GetHash(), i));
            BOOST_CHECK_EQUAL(real.fBill, probe.fBill);
            BOOST_CHECK_EQUAL(real.fBillEscrow, probe.fBillEscrow);
            BOOST_CHECK_EQUAL(real.fNote, probe.fNote);
            if (probe.fNote) {
                BOOST_CHECK_EQUAL(real.nHouseID, probe.nHouseID);
                BOOST_CHECK_EQUAL(real.nNoteUnits, probe.nNoteUnits);
            }
            // AddCoins stamps the threaded dense id onto the title; the
            // payload-pure tagger cannot know it and leaves 0.
            if (probe.fBill)
                BOOST_CHECK_EQUAL(real.nBillID, BILL_ID);
        }
    }

    // Ops 6/7/8 create no tagged output at all: recourse pays in plain value,
    // and the two terminal events pay out of the escrow.
    CKeyID dummy;
    for (uint8_t op : {BILL_OP_RECOURSE, BILL_OP_HRETIRE, BILL_OP_HCLAIM}) {
        CMutableTransaction m2 = mtx;
        m2.nBillOp = op;
        const CTransaction tx2(m2);
        for (unsigned int i = 0; i < tx2.vout.size(); i++) {
            Coin probe;
            ApplyBillCoinTags(tx2, i, probe);
            BOOST_CHECK(!probe.fBill && !probe.fBillEscrow && !probe.fNote);
        }
    }

    // A truncated / undecodable payload must tag NOTHING rather than guess.
    {
        CMutableTransaction m3 = mtx;
        m3.vchBillPayload.resize(4, 0x00);
        const CTransaction tx3(m3);
        Coin probe;
        ApplyBillCoinTags(tx3, 1, probe);
        BOOST_CHECK(!probe.fNote);
    }
}

// ===========================================================================
// T-d4: BillDB's undo-side primitive
// ===========================================================================

BOOST_AUTO_TEST_CASE(billdb_block_effects_atomic_undo)
{
    // The undo side needs what the connect side had plus removals, so that the
    // reverted records, the dense-id rollback and the marker step-back all land
    // in ONE batch. Before this the records were written individually and the
    // marker moved afterwards: a crash in between restarted with the marker
    // still on the disconnected block, the undo re-ran, and every
    // non-idempotent inverse applied twice (R-3 / F-B1b).
    BillDB db(1 << 20, true, true);   // in-memory

    CBill bill;
    bill.nBillID = 1;
    bill.billID = uint256S("aaaa");
    bill.amount = FACE;
    bill.status = BILL_STATUS_ACTIVE;
    CBill bill2;
    bill2.nBillID = 2;
    bill2.billID = uint256S("bbbb");
    bill2.amount = FACE;
    bill2.status = BILL_STATUS_ACTIVE;

    const uint256 hashBlock = uint256S("1111");
    const uint32_t nLast = 2;
    BOOST_CHECK(db.WriteBlockEffects({bill, bill2}, {}, &nLast, hashBlock));

    uint256 hashBest;
    BOOST_CHECK(db.GetBestBlock(hashBest));
    BOOST_CHECK(hashBest == hashBlock);
    uint32_t nGot = 0;
    BOOST_CHECK(db.GetLastBillID(nGot));
    BOOST_CHECK_EQUAL(nGot, 2u);
    BOOST_CHECK(db.HaveBillHash(uint256S("bbbb")));

    // Disconnecting a block that ISSUEd bill 2 and mutated bill 1: one batch
    // carries the reverted record, the removal, the id rollback and the marker.
    CBill reverted = bill;
    reverted.status = BILL_STATUS_RETIRED;
    const uint256 hashPrev = uint256S("2222");
    const uint32_t nLastPrev = 1;
    BOOST_CHECK(db.WriteBlockEffects({reverted}, {2}, &nLastPrev, hashPrev));

    CBill got;
    BOOST_CHECK(db.GetBill(1, got));
    BOOST_CHECK_EQUAL(got.status, BILL_STATUS_RETIRED);
    BOOST_CHECK(!db.GetBill(2, got));
    // The hash-index row must go with the record, or a re-ISSUE of the same
    // body would collide with a bill that no longer exists.
    BOOST_CHECK(!db.HaveBillHash(uint256S("bbbb")));
    BOOST_CHECK(db.HaveBillHash(uint256S("aaaa")));
    BOOST_CHECK(db.GetLastBillID(nGot));
    BOOST_CHECK_EQUAL(nGot, 1u);
    BOOST_CHECK(db.GetBestBlock(hashBest));
    BOOST_CHECK(hashBest == hashPrev);
    BOOST_CHECK_EQUAL(db.GetBills().size(), 1u);

    // Replaying the same undo batch is a no-op, not an error: removing an
    // already-removed bill must not abort a restart.
    BOOST_CHECK(db.WriteBlockEffects({reverted}, {2}, &nLastPrev, hashPrev));
    BOOST_CHECK(!db.GetBill(2, got));
    BOOST_CHECK_EQUAL(db.GetBills().size(), 1u);
}

// ===========================================================================
// The property the three-message ceremony rests on (T-d7)
// ===========================================================================

/** The discount digest must be INVARIANT to exactly the fields the ceremony
 * fills in after it is computed, and SENSITIVE to every term either party
 * relies on.
 *
 * This is not a restatement of BillDiscountSigHash - it is the constraint that
 * makes signdiscount/completediscount possible at all. The house signs the
 * digest in round 2 with the seller's slots empty; the seller then writes its
 * endorsement (height AND signature) and its own signature into the payload in
 * round 3. If any of those ever entered the digest, every discount would fail
 * bad-bill-discount-approvers with no diagnostic, and the failure would look
 * like a wallet bug rather than a digest-definition change. The inclusion half
 * is the other edge: a term that fell OUT of the digest could be altered by the
 * other side after signing, which is the whole attack the shared digest exists
 * to prevent. */
BOOST_AUTO_TEST_CASE(discount_digest_is_the_ceremony_contract)
{
    const Scene s = MakeScene();
    BillDiscount d;
    const CMutableTransaction mtx = MakeDiscount(s, d);
    const uint256 hashPrev = BillHashPrevouts(CTransaction(mtx));
    const uint256 hashOut = BillHashOutputs(CTransaction(mtx));
    const uint256 base = BillDiscountSigHash(d, s.bill.billID, hashPrev, hashOut);

    // --- EXCLUDED: everything a later round writes ------------------------
    {   // the seller's own signature (written in round 3, after the house signed)
        BillDiscount x = d;
        x.vchSellerSig.assign(70, 0x11);
        BOOST_CHECK(BillDiscountSigHash(x, s.bill.billID, hashPrev, hashOut) == base);
    }
    {   // the house quorum's slots (written in round 2, before the seller signs)
        BillDiscount x = d;
        x.vApproverIndex.clear();
        x.vApproverSig.clear();
        BOOST_CHECK(BillDiscountSigHash(x, s.bill.billID, hashPrev, hashOut) == base);
    }
    {   // the WHOLE endorsement link - height and signature both, since round 3
        // sets nAtHeight as late as it can to keep the slack window fresh
        BillDiscount x = d;
        x.endorsement.nAtHeight = d.endorsement.nAtHeight + 33;
        x.endorsement.vchSig.assign(71, 0x22);
        BOOST_CHECK(BillDiscountSigHash(x, s.bill.billID, hashPrev, hashOut) == base);
    }
    {   // the reserve proofs, which carry their own per-coin challenge signatures
        BillDiscount x = d;
        x.vReserveProofs.clear();
        BOOST_CHECK(BillDiscountSigHash(x, s.bill.billID, hashPrev, hashOut) == base);
    }

    // --- INCLUDED: every term either side relies on -----------------------
    const std::vector<std::function<void(BillDiscount&)>> vMutate = {
        [](BillDiscount& x) { x.nBillID += 1; },
        [](BillDiscount& x) { x.nHouseID += 1; },
        [](BillDiscount& x) { x.amountPrice -= 1; },
        [](BillDiscount& x) { x.amountFace -= 1; },
        [](BillDiscount& x) { x.nBillMaturityHeight += 1; },
        [](BillDiscount& x) { x.nNoteOutputs += 1; },
        [](BillDiscount& x) { x.vUnits[0] -= 1; },
        [](BillDiscount& x) { x.vchCustodyPubKey[1] ^= 0x01; },
        [](BillDiscount& x) { x.nExpiryHeight += 1; },
        [](BillDiscount& x) { x.nAsOfHeight -= 1; },
        [](BillDiscount& x) { x.nPrevMintedUnits += 1; },
        [](BillDiscount& x) { x.nPrevLoanBookFace += 1; },
        [](BillDiscount& x) { x.nPrevLoanWtMatHi += 1; },
        [](BillDiscount& x) { x.nPrevLoanWtMatLo += 1; },
    };
    for (size_t i = 0; i < vMutate.size(); i++) {
        BillDiscount x = d;
        vMutate[i](x);
        BOOST_CHECK_MESSAGE(BillDiscountSigHash(x, s.bill.billID, hashPrev, hashOut) != base,
                            "digest ignored value field #" << i << " - it could be altered after signing");
    }
    // ...and the canonical bill identity, the input set and the output set.
    BOOST_CHECK(BillDiscountSigHash(d, uint256S("b112"), hashPrev, hashOut) != base);
    BOOST_CHECK(BillDiscountSigHash(d, s.bill.billID, uint256S("aaaa"), hashOut) != base);
    BOOST_CHECK(BillDiscountSigHash(d, s.bill.billID, hashPrev, uint256S("bbbb")) != base);
}

/** The same contract for RECOURSE. One party, but still assemble-then-sign:
 * the payer's signature is written into the payload the digest is taken over. */
BOOST_AUTO_TEST_CASE(recourse_digest_excludes_the_payer_signature)
{
    const Scene s = MakeScene();
    BillRecourse r;
    r.nBillID = BILL_ID;
    r.vchPayerPubKey = Pub(s.drawer);
    r.vchPrevHolderPubKey = Pub(s.seller);

    const uint256 hashPrev = uint256S("1111");
    const uint256 hashOut = uint256S("2222");
    const uint256 base = BillRecourseSigHash(r, s.bill.billID, hashPrev, hashOut);

    BillRecourse x = r;
    x.vchPayerSig.assign(70, 0x33);
    BOOST_CHECK(BillRecourseSigHash(x, s.bill.billID, hashPrev, hashOut) == base);

    x = r; x.nBillID += 1;
    BOOST_CHECK(BillRecourseSigHash(x, s.bill.billID, hashPrev, hashOut) != base);
    x = r; x.vchPayerPubKey[1] ^= 0x01;
    BOOST_CHECK(BillRecourseSigHash(x, s.bill.billID, hashPrev, hashOut) != base);
    x = r; x.vchPrevHolderPubKey[1] ^= 0x01;
    BOOST_CHECK(BillRecourseSigHash(x, s.bill.billID, hashPrev, hashOut) != base);
    BOOST_CHECK(BillRecourseSigHash(r, s.bill.billID, uint256S("3333"), hashOut) != base);
    BOOST_CHECK(BillRecourseSigHash(r, s.bill.billID, hashPrev, uint256S("4444")) != base);
}

/** The round-1 blob is a wallet message, never a consensus object - but it is
 * parsed from hex handed over out-of-band, so it must reject anything it does
 * not fully understand rather than silently ignore a tail. */
BOOST_AUTO_TEST_CASE(discount_proposal_blob_roundtrip)
{
    DiscountProposalV1 p;
    p.nBillID = BILL_ID;
    p.nHouseID = HOUSE_ID;
    p.amountPrice = PRICE;
    p.vchSellerPubKey = std::vector<unsigned char>(33, 0x02);
    p.outTitle = COutPoint(uint256S("0001"), 3);
    p.nExpiryHeight = (uint32_t)H + 100;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    const std::string strHex = HexStr(ss.begin(), ss.end());

    DiscountProposalV1 got;
    {
        std::vector<unsigned char> vch = ParseHex(strHex);
        CDataStream in(vch, SER_NETWORK, PROTOCOL_VERSION);
        in >> got;
        BOOST_CHECK(in.empty());
    }
    BOOST_CHECK_EQUAL(got.nVersion, 1);
    BOOST_CHECK_EQUAL(got.nBillID, p.nBillID);
    BOOST_CHECK_EQUAL(got.nHouseID, p.nHouseID);
    BOOST_CHECK_EQUAL(got.amountPrice, p.amountPrice);
    BOOST_CHECK(got.vchSellerPubKey == p.vchSellerPubKey);
    BOOST_CHECK(got.outTitle == p.outTitle);
    BOOST_CHECK_EQUAL(got.nExpiryHeight, p.nExpiryHeight);

    // A trailing byte must be visible to the caller (SignDiscount rejects on
    // !ss.empty(), the SettleProposalV1 precedent).
    {
        std::vector<unsigned char> vch = ParseHex(strHex);
        vch.push_back(0x00);
        CDataStream in(vch, SER_NETWORK, PROTOCOL_VERSION);
        DiscountProposalV1 tail;
        in >> tail;
        BOOST_CHECK(!in.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
