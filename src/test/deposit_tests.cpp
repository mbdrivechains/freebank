// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deposit.h>

#include <bill.h>           // BillHashOutputs
#include <coins.h>
#include <house.h>          // BLOCKS_PER_YEAR
#include <note.h>           // v0.2.29: the B3 custody script and demand tag bits
#include <chainparams.h>
#include <consensus/validation.h>
#include <consensus/tx_verify.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <undo.h>
#include <utilstrencodings.h>
#include <version.h>

#include <functional>

#include <boost/test/unit_test.hpp>

// Contextual deposit-op validator (validation.cpp, external linkage; not in a
// public header). Forward-declared so the ORIGINATE gate can be exercised
// directly, asserting exact reject reasons.
bool CheckDepositOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                           const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                           const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                           CHouse& houseOut, bool& fHouseChanged);

BOOST_FIXTURE_TEST_SUITE(deposit_tests, BasicTestingSetup)

static std::vector<unsigned char> FreshPubKey()
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pub = key.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

// A shape-valid ORIGINATE tx: `n` receipts of the given principals.
static CMutableTransaction MakeOriginateTx(uint32_t nHouseID, const std::vector<uint64_t>& vP)
{
    DepositOriginate org;
    org.nHouseID = nHouseID;
    org.vPrincipal = vP;
    for (size_t i = 0; i < vP.size(); i++) {
        org.vRateBps.push_back(500);
        org.vMaturityHeight.push_back(100000 + i);
    }
    org.vApproverIndex.push_back(0);
    org.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_DEPOSIT_VERSION;
    mtx.nDepositOp = DEPOSIT_OP_ORIGINATE;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << org;
    mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    for (size_t i = 0; i < vP.size(); i++)
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())));
    return mtx;
}

BOOST_AUTO_TEST_CASE(deposit_payload_roundtrip)
{
    DepositOriginate org;
    org.nHouseID = 7;
    org.vPrincipal = {100000, 250000};
    org.vRateBps = {450, 600};
    org.vMaturityHeight = {120000, 130000};
    org.vApproverIndex = {0, 2};
    org.vApproverSig = {std::vector<unsigned char>(70, 0x30), std::vector<unsigned char>(71, 0x31)};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << org;
    DepositOriginate o2;
    BOOST_CHECK(DecodeDepositPayload(std::vector<unsigned char>(ss.begin(), ss.end()), o2));
    BOOST_CHECK_EQUAL(o2.nHouseID, 7);
    BOOST_CHECK_EQUAL(o2.vPrincipal.size(), 2);
    BOOST_CHECK_EQUAL(o2.vPrincipal[1], 250000);
    BOOST_CHECK_EQUAL(o2.vMaturityHeight[0], 120000);

    DepositTransfer xf;
    xf.nHouseID = 7; xf.nPrincipal = 100000; xf.nRateBps = 450;
    xf.nMaturityHeight = 120000; xf.nOriginationHeight = 5000;
    xf.vchSenderPubKey = FreshPubKey(); xf.vchSenderSig = std::vector<unsigned char>(70, 0x30);
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION); ss2 << xf;
    DepositTransfer x2;
    BOOST_CHECK(DecodeDepositPayload(std::vector<unsigned char>(ss2.begin(), ss2.end()), x2));
    BOOST_CHECK_EQUAL(x2.nOriginationHeight, 5000);
    BOOST_CHECK_EQUAL(x2.nMaturityHeight, 120000);

    // Trailing bytes are rejected (canonical encoding).
    std::vector<unsigned char> vbad(ss2.begin(), ss2.end());
    vbad.push_back(0xff);
    DepositTransfer x3;
    BOOST_CHECK(!DecodeDepositPayload(vbad, x3));
}

BOOST_AUTO_TEST_CASE(deposit_sighash_domain_separation)
{
    const uint256 pv = uint256S("11"), out = uint256S("22");
    std::vector<uint64_t> vp{100000};
    std::vector<uint32_t> vr{500}, vm{120000};
    std::vector<uint256> v;
    v.push_back(DepositOriginateSigHash(1, vp, vr, vm, pv, out));
    v.push_back(DepositTransferSigHash(1, 100000, 500, 120000, 5000, out));
    v.push_back(DepositWithdrawSigHash(1, 100000, 120000, 5000, out));
    v.push_back(DepositClaimSigHash(1, 100000, out));
    for (size_t i = 0; i < v.size(); i++)
        for (size_t j = i + 1; j < v.size(); j++)
            BOOST_CHECK(v[i] != v[j]);
    // Sensitive to bound fields
    BOOST_CHECK(DepositOriginateSigHash(1, vp, vr, vm, pv, out) != DepositOriginateSigHash(2, vp, vr, vm, pv, out));
    BOOST_CHECK(DepositOriginateSigHash(1, vp, vr, vm, pv, out) != DepositOriginateSigHash(1, vp, vr, vm, uint256S("33"), out));
    BOOST_CHECK(DepositTransferSigHash(1, 100000, 500, 120000, 5000, out) != DepositTransferSigHash(1, 100000, 500, 120001, 5000, out));
    BOOST_CHECK(DepositWithdrawSigHash(1, 100000, 120000, 5000, out) != DepositWithdrawSigHash(1, 100000, 120000, 5001, out));
}

BOOST_AUTO_TEST_CASE(deposit_maturity_interest_math)
{
    // 5% of 1e8 held exactly one year = 5,000,000 (rate = the receipt's own bps).
    BOOST_CHECK_EQUAL(DepositMaturityInterest(100000000ULL, BLOCKS_PER_YEAR, 500), 5000000);
    // Zero principal/blocks/rate -> 0.
    BOOST_CHECK_EQUAL(DepositMaturityInterest(0, BLOCKS_PER_YEAR, 500), 0);
    BOOST_CHECK_EQUAL(DepositMaturityInterest(100000000ULL, 0, 500), 0);
    BOOST_CHECK_EQUAL(DepositMaturityInterest(100000000ULL, BLOCKS_PER_YEAR, 0), 0);
    // Half a year at 5% = 2.5%.
    BOOST_CHECK_EQUAL(DepositMaturityInterest(100000000ULL, BLOCKS_PER_YEAR / 2, 500), 2500000);
    // Pathological huge product is capped at MAX_MONEY (no wrap).
    BOOST_CHECK_EQUAL(DepositMaturityInterest((uint64_t)MAX_MONEY, 4000000000U, 10000), MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(deposit_claim_entitlement_math)
{
    // Full pot covers all principal -> capped at par.
    BOOST_CHECK_EQUAL(DepositClaimEntitlement(100000, 1000000, 100000), 100000);
    // Pot is half the snapshot -> pro-rata half.
    BOOST_CHECK_EQUAL(DepositClaimEntitlement(100000, 500000, 1000000), 50000);
    // Degenerate inputs -> 0.
    BOOST_CHECK_EQUAL(DepositClaimEntitlement(100000, 500000, 0), 0);
    BOOST_CHECK_EQUAL(DepositClaimEntitlement(0, 500000, 1000000), 0);
    BOOST_CHECK_EQUAL(DepositClaimEntitlement(100000, 0, 1000000), 0);
}

BOOST_AUTO_TEST_CASE(deposit_shape_valid)
{
    CValidationState state;
    BOOST_CHECK(CheckDepositTransactionShape(CTransaction(MakeOriginateTx(1, {100000})), state));
    BOOST_CHECK(CheckDepositTransactionShape(CTransaction(MakeOriginateTx(1, {50000, 150000, 300000})), state));
}

BOOST_AUTO_TEST_CASE(deposit_shape_rejections)
{
    CValidationState state;
    // Unknown op
    {
        CMutableTransaction mtx = MakeOriginateTx(1, {100000});
        mtx.nDepositOp = 9;
        BOOST_CHECK(!CheckDepositTransactionShape(CTransaction(mtx), state));
    }
    // Parallel-array mismatch (rate vector short)
    {
        DepositOriginate org; org.nHouseID = 1;
        org.vPrincipal = {100000, 200000}; org.vRateBps = {500}; org.vMaturityHeight = {120000, 120001};
        org.vApproverIndex = {0}; org.vApproverSig = {std::vector<unsigned char>(70, 0x30)};
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_ORIGINATE;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << org;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())));
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())));
        BOOST_CHECK(!CheckDepositTransactionShape(CTransaction(mtx), state));
    }
    // Zero principal
    {
        CMutableTransaction mtx = MakeOriginateTx(1, {100000});
        DepositOriginate org; org.nHouseID = 1; org.vPrincipal = {0}; org.vRateBps = {500}; org.vMaturityHeight = {120000};
        org.vApproverIndex = {0}; org.vApproverSig = {std::vector<unsigned char>(70, 0x30)};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << org;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        BOOST_CHECK(!CheckDepositTransactionShape(CTransaction(mtx), state));
    }
    // Wrong receipt output value (not dust)
    {
        CMutableTransaction mtx = MakeOriginateTx(1, {100000});
        mtx.vout[0] = CTxOut(DEPOSIT_DUST_VALUE + 1, DepositScriptForPubKey(FreshPubKey()));
        BOOST_CHECK(!CheckDepositTransactionShape(CTransaction(mtx), state));
    }
    // Oversized payload
    {
        CMutableTransaction mtx = MakeOriginateTx(1, {100000});
        mtx.vchDepositPayload = std::vector<unsigned char>(40000, 0x00);
        BOOST_CHECK(!CheckDepositTransactionShape(CTransaction(mtx), state));
    }
}

BOOST_AUTO_TEST_CASE(deposit_coin_tag_roundtrip)
{
    // A receipt coin's fDeposit tag + terms survive coin serialization AND the
    // undo-record serialization (or a reorg-restored receipt loses its terms).
    Coin coin(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())), 500, false, false, false, uint256());
    coin.SetDeposit(7, 250000, 450, 120000, 480);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << coin;
    Coin c2;
    ss >> c2;
    BOOST_CHECK(c2.fDeposit);
    BOOST_CHECK_EQUAL(c2.nHouseID, 7);
    BOOST_CHECK_EQUAL(c2.nDepositPrincipal, 250000);
    BOOST_CHECK_EQUAL(c2.nDepositRateBps, 450);
    BOOST_CHECK_EQUAL(c2.nDepositMaturityHeight, 120000);
    BOOST_CHECK_EQUAL(c2.nDepositOriginationHeight, 480);

    // Undo-record round-trip (TxInUndoSerializer / Deserializer).
    CTxUndo undo;
    undo.vprevout.push_back(coin);
    CDataStream ssu(SER_NETWORK, PROTOCOL_VERSION);
    ssu << undo;
    CTxUndo u2;
    ssu >> u2;
    BOOST_REQUIRE_EQUAL(u2.vprevout.size(), 1);
    BOOST_CHECK(u2.vprevout[0].fDeposit);
    BOOST_CHECK_EQUAL(u2.vprevout[0].nDepositPrincipal, 250000);
    BOOST_CHECK_EQUAL(u2.vprevout[0].nDepositMaturityHeight, 120000);
    BOOST_CHECK_EQUAL(u2.vprevout[0].nDepositOriginationHeight, 480);
}

BOOST_AUTO_TEST_CASE(deposit_addcoins_self_tags_receipts)
{
    // AddCoins DECODES the v14 payload and tags the receipt outputs from it -
    // no threaded dense id (the note self-tagging model, so connect ==
    // rollforward). ORIGINATE stamps origination = the connect height.
    CMutableTransaction mtx = MakeOriginateTx(9, {100000, 250000});
    const int nHeight = 777;
    CTransaction tx(mtx);

    CCoinsView base;
    CCoinsViewCache cache(&base);
    AddCoins(cache, tx, nHeight);

    const Coin& c0 = cache.AccessCoin(COutPoint(tx.GetHash(), 0));
    const Coin& c1 = cache.AccessCoin(COutPoint(tx.GetHash(), 1));
    BOOST_CHECK(c0.fDeposit);
    BOOST_CHECK_EQUAL(c0.nHouseID, 9);
    BOOST_CHECK_EQUAL(c0.nDepositPrincipal, 100000);
    BOOST_CHECK_EQUAL(c0.nDepositRateBps, 500);
    BOOST_CHECK_EQUAL(c0.nDepositMaturityHeight, 100000);
    BOOST_CHECK_EQUAL(c0.nDepositOriginationHeight, (uint32_t)nHeight);
    BOOST_CHECK(c1.fDeposit);
    BOOST_CHECK_EQUAL(c1.nDepositPrincipal, 250000);
    BOOST_CHECK_EQUAL(c1.nDepositMaturityHeight, 100001);
    // Not a note / escrow.
    BOOST_CHECK(!c0.fNote);
    BOOST_CHECK(!c0.fHouseEscrow);
}

// Add a receipt coin (P2PKH to `holderPub`, house `h`) to the cache and return
// its outpoint.
static COutPoint AddReceipt(CCoinsViewCache& cache, uint32_t h, const std::vector<unsigned char>& holderPub,
                           uint64_t principal, const uint256& txid, uint32_t n = 0)
{
    Coin coin(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(holderPub)), 100, false, false, false, uint256());
    coin.SetDeposit(h, principal, 500, 120000, 50);
    COutPoint op(txid, n);
    cache.AddCoin(op, std::move(coin), false);
    return op;
}

BOOST_AUTO_TEST_CASE(deposit_spend_guard)
{
    CKey keyHolder; keyHolder.MakeNewKey(true);
    const CPubKey pubHolder = keyHolder.GetPubKey();
    std::vector<unsigned char> holderPub(pubHolder.begin(), pubHolder.end());

    // A plain (non-v14) tx cannot spend a receipt coin (drain protection).
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        COutPoint r = AddReceipt(cache, 5, holderPub, 100000, uint256S("aa"));
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(r));
        mtx.vout.push_back(CTxOut(500, DepositScriptForPubKey(FreshPubKey())));
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-spend-deposit-coin");
    }
    // An ORIGINATE (which must spend NO receipt) spending a receipt is rejected.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        COutPoint r = AddReceipt(cache, 5, holderPub, 100000, uint256S("bb"));
        CMutableTransaction mtx = MakeOriginateTx(5, {100000});
        mtx.vin.clear();
        mtx.vin.push_back(CTxIn(r));
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-spend-deposit-coin");
    }
    // Two receipts of DIFFERENT houses cannot mix in one TRANSFER.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        COutPoint r1 = AddReceipt(cache, 5, holderPub, 100000, uint256S("cc"), 0);
        COutPoint r2 = AddReceipt(cache, 6, holderPub, 100000, uint256S("dd"), 0);
        DepositTransfer x; x.nHouseID = 5; x.nPrincipal = 100000; x.nRateBps = 500;
        x.nMaturityHeight = 120000; x.nOriginationHeight = 50;
        x.vchSenderPubKey = holderPub; x.vchSenderSig = std::vector<unsigned char>(70, 0x30);
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_TRANSFER;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << x;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(r1)); mtx.vin.push_back(CTxIn(r2));
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())));
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-inputs-mixed-house");
    }
    // A receipt spent by a TRANSFER whose declared sender is NOT the holder.
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        COutPoint r = AddReceipt(cache, 5, holderPub, 100000, uint256S("ee"));
        DepositTransfer x; x.nHouseID = 5; x.nPrincipal = 100000; x.nRateBps = 500;
        x.nMaturityHeight = 120000; x.nOriginationHeight = 50;
        x.vchSenderPubKey = FreshPubKey();   // a DIFFERENT key
        x.vchSenderSig = std::vector<unsigned char>(70, 0x30);
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_TRANSFER;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << x;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(r));
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())));
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-input-not-holder");
    }
}

// An effectively-Open multi-partner house with ample capital cap.
static CHouse MakeOpenDepositHouse(uint32_t nHouseID)
{
    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;      // lambda = 3.0
    house.nThresholdM = 1;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    HousePartner p;
    p.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p.amountPledge = 100 * COIN;                 // capital cap = 3 * 100 COIN
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);
    return house;
}

BOOST_AUTO_TEST_CASE(deposit_originate_gate)
{
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };

    // Not effectively Open -> refused (a stressed house cannot take deposits).
    {
        CHouse house = MakeOpenDepositHouse(3);
        house.nLastAttestHeight = 2000; house.nStressSinceHeight = 2000;   // Stressed
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 3) { out = house; return true; } return false; };
        CMutableTransaction mtx = MakeOriginateTx(3, {100000});
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 2000, fnGetHouse, fnNoCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-originate-house-not-open");
    }
    // Maturity in the past -> refused (term must be > 0).
    {
        CHouse house = MakeOpenDepositHouse(3);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 3) { out = house; return true; } return false; };
        DepositOriginate org; org.nHouseID = 3; org.vPrincipal = {100000};
        org.vRateBps = {500}; org.vMaturityHeight = {900};   // 900 <= nHeight 1000
        org.vApproverIndex = {0}; org.vApproverSig = {std::vector<unsigned char>(70, 0x30)};
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_ORIGINATE;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << org;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())));
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnGetHouse, fnNoCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-originate-not-future");
    }
    // Over the shared capital cap (N + D + batch > lambda*E) -> refused. The
    // house already has notes + deposits near the cap.
    {
        CHouse house = MakeOpenDepositHouse(3);
        // capital cap = 3 * 100 COIN = 30,000,000,000 units. Fill most of it.
        house.nMintedUnits = 29000000000ULL;
        house.nDepositUnits = 900000000ULL;
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 3) { out = house; return true; } return false; };
        CMutableTransaction mtx = MakeOriginateTx(3, {200000000});   // would exceed
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnGetHouse, fnNoCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-originate-over-cap");
    }
}

BOOST_AUTO_TEST_CASE(deposit_transfer_gate)
{
    CKey keySender; keySender.MakeNewKey(true);
    const CPubKey pubSender = keySender.GetPubKey();   // named - begin()/end() must be ONE object
    std::vector<unsigned char> senderPub(pubSender.begin(), pubSender.end());
    const uint32_t H = 5; const uint64_t P = 100000; const uint32_t R = 500, M = 120000, O = 50;
    const std::vector<unsigned char> destPub = FreshPubKey();   // FIXED, so hashOutputs is stable

    auto build = [&](uint64_t pPayload, uint32_t mPayload, const std::vector<unsigned char>& sig) {
        DepositTransfer x; x.nHouseID = H; x.nPrincipal = pPayload; x.nRateBps = R;
        x.nMaturityHeight = mPayload; x.nOriginationHeight = O;
        x.vchSenderPubKey = senderPub; x.vchSenderSig = sig;
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_TRANSFER;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << x;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("de"), 0)));
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(destPub)));
        return mtx;
    };

    // The receipt being transferred carries the REAL terms.
    Coin receipt(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(senderPub)), 100, false, false, false, uint256());
    receipt.SetDeposit(H, P, R, M, O);
    auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
        if (o == COutPoint(uint256S("de"), 0)) { c = receipt; return true; } return false;
    };
    auto fnNoHouse = [](uint32_t, CHouse&) { return false; };
    // v0.2.19: a TRANSFER needs its (open) house, for the members-only rule; it fails closed without one
    auto fnOpenHouse = [&](uint32_t id, CHouse& h) { if (id != H) return false; h = CHouse(); h.nHouseID = H; return true; };

    // hashOutputs is over vout only (stable across payload/sig), so sign once.
    CMutableTransaction tmp = build(P, M, std::vector<unsigned char>(70, 0x30));
    const uint256 sighash = DepositTransferSigHash(H, P, R, M, O, BillHashOutputs(CTransaction(tmp)));
    std::vector<unsigned char> sig; BOOST_REQUIRE(keySender.Sign(sighash, sig));

    // Positive: matching terms + valid sender sig -> accepted, NO house change.
    {
        CMutableTransaction mtx = build(P, M, sig);
        CValidationState state; CHouse houseOut; bool fChanged = true;
        BOOST_CHECK(CheckDepositOperation(CTransaction(mtx), state, 1000, fnOpenHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK(!fChanged);   // TRANSFER changes no house state
        // ...and without its house it fails closed (review F3)
        CValidationState state2;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state2, 1000, fnNoHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-deposit-unknown-house");
    }
    // Terms mismatch (payload principal != the receipt's) -> rejected before sig.
    {
        CMutableTransaction mtx = build(P + 1, M, std::vector<unsigned char>(70, 0x30));
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnNoHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-transfer-terms-mismatch");
    }
    // Right terms but a bad signature (a different key signed) -> rejected.
    {
        CKey other; other.MakeNewKey(true);
        std::vector<unsigned char> badsig; other.Sign(sighash, badsig);
        CMutableTransaction mtx = build(P, M, badsig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnNoHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-transfer-sig");
    }
}

BOOST_AUTO_TEST_CASE(deposit_withdraw_gate)
{
    CKey keyHolder; keyHolder.MakeNewKey(true);
    const CPubKey pubH = keyHolder.GetPubKey();
    std::vector<unsigned char> holderPub(pubH.begin(), pubH.end());
    const uint32_t H = 5; const uint64_t P = 100000; const uint32_t R = 500, MAT = 1000, ORIG = 50;

    // The matured receipt being withdrawn.
    Coin receipt(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(holderPub)), 60, false, false, false, uint256());
    receipt.SetDeposit(H, P, R, MAT, ORIG);
    auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
        if (o == COutPoint(uint256S("wd"), 0)) { c = receipt; return true; } return false;
    };

    // A WITHDRAW tx paying `payout` to the holder; signed if `sign`.
    auto build = [&](CAmount payout, const std::vector<unsigned char>& sig) {
        DepositWithdraw wd; wd.nHouseID = H; wd.vchHolderPubKey = holderPub; wd.vchHolderSig = sig;
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_WITHDRAW;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << wd;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("wd"), 0)));
        mtx.vout.push_back(CTxOut(payout, DepositScriptForPubKey(holderPub)));
        return mtx;
    };

    const int nHeight = 2000;   // matured (>= MAT 1000)
    const uint32_t nBlocks = (uint32_t)nHeight - ORIG;
    const CAmount interest = DepositMaturityInterest(P, nBlocks, R);
    const CAmount due = (CAmount)P + interest;

    // Sign over the exact payout (>= floor).
    CMutableTransaction tmp = build(due, std::vector<unsigned char>(70, 0x30));
    const uint256 sighash = DepositWithdrawSigHash(H, P, MAT, ORIG, BillHashOutputs(CTransaction(tmp)));
    std::vector<unsigned char> sig; BOOST_REQUIRE(keyHolder.Sign(sighash, sig));

    // Positive: Open, matured, paid the floor, valid sig -> accepted, D decremented.
    {
        CHouse house = MakeOpenDepositHouse(H);
        house.nLastAttestHeight = nHeight - 100;   // fresh -> effectively Open at nHeight
        house.nDepositUnits = P;
        house.SetDepositWtMaturity((unsigned __int128)P * MAT);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = house; return true; } return false; };
        CMutableTransaction mtx = build(due, sig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(CheckDepositOperation(CTransaction(mtx), state, nHeight, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK(fChanged);
        BOOST_CHECK_EQUAL(houseOut.nDepositUnits, 0);
        BOOST_CHECK(houseOut.DepositWtMaturity() == (unsigned __int128)0);
    }
    // Not matured (nHeight < maturity) -> refused.
    {
        CHouse house = MakeOpenDepositHouse(H); house.nDepositUnits = P;
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = house; return true; } return false; };
        CMutableTransaction mtx = build(due, sig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 900, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-not-matured");
    }
    // House not Open (Stressed) -> refused (junior; queues behind notes).
    {
        CHouse house = MakeOpenDepositHouse(H); house.nDepositUnits = P;
        house.nLastAttestHeight = nHeight; house.nStressSinceHeight = nHeight;   // Stressed
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = house; return true; } return false; };
        CMutableTransaction mtx = build(due, sig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, nHeight, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-withdraw-house-not-open");
    }
    // Underpaid (payout below principal + accrued) -> refused (interest is a FLOOR).
    {
        CHouse house = MakeOpenDepositHouse(H); house.nDepositUnits = P;
        house.nLastAttestHeight = nHeight - 100;   // effectively Open
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = house; return true; } return false; };
        CMutableTransaction mtx = build(due - 1, sig);   // one sat short
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, nHeight, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-withdraw-underpaid");
    }
}

BOOST_AUTO_TEST_CASE(deposit_claim_gate)
{
    CKey keyHolder; keyHolder.MakeNewKey(true);
    const CPubKey pubH = keyHolder.GetPubKey();
    std::vector<unsigned char> holderPub(pubH.begin(), pubH.end());
    const uint32_t H = 5; const uint64_t P = 100000; const uint32_t R = 500, MAT = 1000, ORIG = 50;
    const uint256 houseID = uint256S("f00d");

    // The receipt being claimed, and an escrow-pot coin to pay from.
    Coin receipt(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(holderPub)), 60, false, false, false, uint256());
    receipt.SetDeposit(H, P, R, MAT, ORIG);
    const COutPoint rOut(uint256S("cl"), 0);
    const COutPoint eOut(uint256S("es"), 0);
    auto makeEscrow = [&](CAmount v) {
        Coin c(CTxOut(v, HouseEscrowScript(houseID)), 40, false, false, false, uint256());
        c.SetHouseEscrow(H);
        return c;
    };

    // CLAIM tx: burn the receipt + spend `escrowVal` of escrow, pay it to holder.
    auto build = [&](CAmount escrowVal, const std::vector<unsigned char>& sig) {
        DepositClaim clm; clm.nHouseID = H; clm.fEscrowChange = 0;
        clm.vchHolderPubKey = holderPub; clm.vchHolderSig = sig;
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_CLAIM;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << clm;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(rOut));
        mtx.vin.push_back(CTxIn(eOut));
        mtx.vout.push_back(CTxOut(escrowVal, DepositScriptForPubKey(holderPub)));
        return mtx;
    };

    // An INSOLVENT house with a frozen snapshot: no notes, pot 1e6, one deposit.
    auto insolventHouse = [&]() {
        CHouse h = MakeOpenDepositHouse(H);
        h.houseID = houseID;
        h.status = HOUSE_STATUS_INSOLVENT;      // stored terminal -> effective Insolvent
        h.nInsolventHeight = 900;               // v0.2.28: E for the collect-then-pay gate (the book is empty: open)
        h.nMintedUnits = 0; h.nInsolventUnits = 0;
        h.amountInsolventPot = 1000000;
        h.nDepositUnits = P; h.nInsolventDepositPrincipal = P;
        h.SetDepositWtMaturity((unsigned __int128)P * MAT);
        return h;
    };

    // Sign over a payout == entitlement (par = principal here, since pot >> par).
    CMutableTransaction tmp = build((CAmount)P, std::vector<unsigned char>(70, 0x30));
    const uint256 sighash = DepositClaimSigHash(H, P, BillHashOutputs(CTransaction(tmp)));
    std::vector<unsigned char> sig; BOOST_REQUIRE(keyHolder.Sign(sighash, sig));

    // Not insolvent -> refused (the subordinated waterfall is only at insolvency).
    {
        CHouse h = MakeOpenDepositHouse(H); h.houseID = houseID; h.nDepositUnits = P;
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = h; return true; } return false; };
        auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
            if (o == rOut) { c = receipt; return true; } if (o == eOut) { c = makeEscrow(P); return true; } return false; };
        CMutableTransaction mtx = build((CAmount)P, sig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-claim-not-insolvent");
    }
    // Positive: insolvent, escrow taken == entitlement, valid sig -> accepted, D-=P.
    {
        CHouse h = insolventHouse();
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = h; return true; } return false; };
        auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
            if (o == rOut) { c = receipt; return true; } if (o == eOut) { c = makeEscrow(P); return true; } return false; };
        CMutableTransaction mtx = build((CAmount)P, sig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(CheckDepositOperation(CTransaction(mtx), state, 1000, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK(fChanged);
        BOOST_CHECK_EQUAL(houseOut.nDepositUnits, 0);
    }
    // Over-entitlement: escrow taken (2*P) exceeds the capped entitlement (P) -> refused.
    {
        CHouse h = insolventHouse();
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = h; return true; } return false; };
        auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
            if (o == rOut) { c = receipt; return true; } if (o == eOut) { c = makeEscrow(2 * (CAmount)P); return true; } return false; };
        // Sign over the larger payout so the sig passes and the entitlement check fires.
        CMutableTransaction t2 = build(2 * (CAmount)P, std::vector<unsigned char>(70, 0x30));
        const uint256 sh2 = DepositClaimSigHash(H, P, BillHashOutputs(CTransaction(t2)));
        std::vector<unsigned char> s2; BOOST_REQUIRE(keyHolder.Sign(sh2, s2));
        CMutableTransaction mtx = build(2 * (CAmount)P, s2);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-claim-over-entitlement");
    }
    // v0.2.28 (FAILED_HOUSE_DESIGN.md B, E): collect, then pay - a claim waits while the book has not run off, and
    // none is taken once the house is CLOSEd.
    {
        CHouse h = insolventHouse();
        h.nLoanBookFace = 1000;                 // a bill still in the book; 1000 < E (900) + nCollectWindow
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = h; return true; } return false; };
        auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
            if (o == rOut) { c = receipt; return true; } if (o == eOut) { c = makeEscrow(P); return true; } return false; };
        CMutableTransaction mtx = build((CAmount)P, sig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-claim-collecting");
    }
    {
        CHouse h = insolventHouse();
        if (h.vPartner.empty()) h.vPartner.push_back(HousePartner());
        for (HousePartner& pt : h.vPartner) pt.status = HOUSE_PARTNER_SETTLED;
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == H) { out = h; return true; } return false; };
        auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
            if (o == rOut) { c = receipt; return true; } if (o == eOut) { c = makeEscrow(P); return true; } return false; };
        CMutableTransaction mtx = build((CAmount)P, sig);
        CValidationState state; CHouse houseOut; bool fChanged = false;
        BOOST_CHECK(!CheckDepositOperation(CTransaction(mtx), state, 1000, fnGetHouse, fnGetCoin, houseOut, fChanged));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-deposit-claim-house-closed");
    }
    // The junior-tranche math: with notes senior (nInsolventUnits > 0), the deposit
    // pot is only the residual pot - notePar, so deposits provably cannot reach the
    // note tranche.
    {
        // pot 1e6, notes claim 800000 par, deposit principal 500000 -> depositPot =
        // 200000, so a 500000-principal deposit is capped at 200000, NOT 500000.
        BOOST_CHECK_EQUAL(DepositClaimEntitlement(500000, /*depositPot=*/200000, /*snap=*/500000), 200000);
        // And the senior tranche (800000) is untouched: pot(1e6) - depositTake(<=200000) >= 800000.
    }
}

BOOST_AUTO_TEST_CASE(deposit_match_funding_helpers)
{
    CHouse house;
    // No deposits -> WAM 0, match-funding trivially OK.
    BOOST_CHECK_EQUAL(HouseDepositWAM(house, 1000), 0);
    BOOST_CHECK(HouseMatchFundingOK(house, 1000));

    // Two deposits: 100000 @ maturity 5000, 100000 @ maturity 9000.
    // WtMaturity = 100000*5000 + 100000*9000 = 1.4e9; units = 200000;
    // WAM height = 1.4e9 / 200000 = 7000. At h=1000 -> remaining 6000.
    house.nDepositUnits = 200000;
    house.SetDepositWtMaturity((unsigned __int128)100000 * 5000 + (unsigned __int128)100000 * 9000);
    BOOST_CHECK_EQUAL(HouseDepositWAM(house, 1000), 6000);
    BOOST_CHECK_EQUAL(HouseDepositWAM(house, 7000), 0);      // at the average maturity
    BOOST_CHECK_EQUAL(HouseDepositWAM(house, 8000), 0);      // past it -> clamped 0
    // With an EMPTY loan book the slice is 0, so match-funding is satisfied no
    // matter what the deposits look like (B1: D>0 alone never binds).
    BOOST_CHECK_EQUAL(HouseLoanBookSlice(house), 0);
    BOOST_CHECK(HouseMatchFundingOK(house, 1000));
    BOOST_CHECK(HouseMatchFundingOK(house, 8000));           // even when all matured
}

// ===========================================================================
// v0.2.29 deposit DEMAND / PROTEST / DISCHARGE (FAILED_HOUSE_DESIGN.md D)
// ===========================================================================
namespace {
struct DemandScene {
    CKey key;
    std::vector<unsigned char> pub;
    uint32_t H = 5;
    uint64_t P = 100000;
    uint32_t R = 500, MAT = 1000, ORIG = 50;
    std::vector<unsigned char> payout;
    DemandScene() {
        key.MakeNewKey(true);
        const CPubKey pk = key.GetPubKey();
        pub = std::vector<unsigned char>(pk.begin(), pk.end());
        const CScript sp = DepositScriptForPubKey(pub);
        payout = std::vector<unsigned char>(sp.begin(), sp.end());
    }
    std::vector<unsigned char> PreAuth(const std::vector<unsigned char>& vchPayout) const {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(DepositPreAuthSigHash(H, P, R, MAT, ORIG, vchPayout), sig));
        return sig;
    }
    Coin Receipt(uint32_t nTag) const {
        Coin c(CTxOut(DEPOSIT_DUST_VALUE, nTag ? NotePreAuthScript(pub) : DepositScriptForPubKey(pub)), 60, false,
               false, false, uint256());
        c.SetDeposit(H, P, R, MAT, ORIG);
        c.nDemandHeight = nTag;
        return c;
    }
};

static std::string RunDeposit(const CMutableTransaction& mtx, int nHeight, const CHouse& house, const Coin& receipt,
                              CHouse* pOut = nullptr, bool* pfChanged = nullptr)
{
    const COutPoint rOut(uint256S("rc"), 0);
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnGetCoin = [&](const COutPoint& o, Coin& c) { if (o == rOut) { c = receipt; return true; } return false; };
    CValidationState state; CHouse houseOut; bool fChanged = false;
    const bool f = CheckDepositOperation(CTransaction(mtx), state, nHeight, fnGetHouse, fnGetCoin, houseOut, fChanged);
    if (pOut) *pOut = houseOut;
    if (pfChanged) *pfChanged = fChanged;
    return f ? std::string("OK") : state.GetRejectReason();
}

static CMutableTransaction MakeDemandTx(const DemandScene& sc, const std::vector<unsigned char>& vchPayout,
                                        const std::vector<unsigned char>& vchPreAuth, const CScript& scriptOut)
{
    DepositDemand d;
    d.nHouseID = sc.H; d.nPrincipal = sc.P; d.nRateBps = sc.R; d.nMaturityHeight = sc.MAT; d.nOriginationHeight = sc.ORIG;
    d.vchHolderPubKey = sc.pub; d.vchPayoutScript = vchPayout; d.vchPreAuthSig = vchPreAuth;
    CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_DEMAND;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << d;
    mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("rc"), 0)));
    mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, scriptOut));
    return mtx;
}

static CMutableTransaction MakeProtestTx(const DemandScene& sc, uint32_t nTag, const CHouse& h,
                                        const std::vector<unsigned char>& vchPreAuth,
                                        const std::vector<unsigned char>& vchPayout = {},
                                        const CScript& scriptCustody = CScript())
{
    DepositProtest pr;
    pr.nHouseID = sc.H; pr.nPrincipal = sc.P; pr.nRateBps = sc.R; pr.nMaturityHeight = sc.MAT;
    pr.nOriginationHeight = sc.ORIG; pr.nDemandTag = nTag; pr.vchHolderPubKey = sc.pub;
    pr.nPrevProtestOpen = h.nProtestOpen; pr.nPrevProtestHeight = h.nProtestHeight;
    pr.nPrevProtestDemandHeight = h.nProtestDemandHeight;
    pr.vchPayoutScript = vchPayout.empty() ? sc.payout : vchPayout; pr.vchPreAuthSig = vchPreAuth;
    CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_PROTEST;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("rc"), 0)));
    mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, scriptCustody.empty() ? NotePreAuthScript(sc.pub) : scriptCustody));
    BOOST_REQUIRE(sc.key.Sign(DepositProtestSigHash(pr.nHouseID, pr.nPrincipal, pr.nOriginationHeight, pr.nDemandTag,
                                                    BillHashOutputs(CTransaction(mtx))), pr.vchHolderSig));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << pr;
    mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

static CMutableTransaction MakeDischargeTx(const DemandScene& sc, const CHouse& h, CAmount amount,
                                          const std::vector<unsigned char>& vchPreAuth, const CScript& scriptPay,
                                          const std::vector<unsigned char>& vchPayout = {})
{
    DepositDischarge dc;
    dc.nHouseID = sc.H; dc.vchHolderPubKey = sc.pub; dc.vchPayoutScript = vchPayout.empty() ? sc.payout : vchPayout;
    dc.vchPreAuthSig = vchPreAuth;
    dc.nPrevProtestOpen = h.nProtestOpen;
    CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_DISCHARGE;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << dc;
    mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("rc"), 0)));
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("ff"), 0)));   // the payer's funding
    mtx.vout.push_back(CTxOut(amount, scriptPay));
    return mtx;
}
} // namespace

BOOST_AUTO_TEST_CASE(deposit_demand_gate)
{
    const DemandScene sc;
    CHouse house = MakeOpenDepositHouse(sc.H);
    house.nDepositUnits = sc.P;
    const Coin plain = sc.Receipt(0);
    const CScript custody = NotePreAuthScript(sc.pub);
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    CHouse out;
    bool fChanged = true;
    BOOST_CHECK_EQUAL(RunDeposit(MakeDemandTx(sc, sc.payout, preauth, custody), 1100, house, plain, &out, &fChanged), "OK");
    BOOST_CHECK(!fChanged);   // no house state, no house slot: the demand lives on the coin
    BOOST_CHECK_EQUAL(RunDeposit(MakeDemandTx(sc, sc.payout, preauth, custody), 999, house, plain), "bad-deposit-demand-early");
    CHouse hDeferred = house;
    hDeferred.nDeferInvokedHeight = 1050; hDeferred.nLastAttestHeight = 1090;
    BOOST_CHECK_EQUAL(RunDeposit(MakeDemandTx(sc, sc.payout, preauth, custody), 1100, hDeferred, plain),
                      "bad-deposit-demand-house-status");
    const CScript escrow = HouseEscrowScript(house.houseID);
    const std::vector<unsigned char> vEscrow(escrow.begin(), escrow.end());
    BOOST_CHECK_EQUAL(RunDeposit(MakeDemandTx(sc, vEscrow, sc.PreAuth(vEscrow), custody), 1100, house, plain),
                      "bad-deposit-demand-payout-script");
    BOOST_CHECK_EQUAL(RunDeposit(MakeDemandTx(sc, sc.payout, preauth, NotePreAuthScript(FreshPubKey())), 1100, house, plain),
                      "bad-deposit-demand-custody-script");
    const CScript other = DepositScriptForPubKey(FreshPubKey());
    BOOST_CHECK_EQUAL(RunDeposit(MakeDemandTx(sc, sc.payout, sc.PreAuth(std::vector<unsigned char>(other.begin(), other.end())),
                      custody), 1100, house, plain), "bad-deposit-demand-preauth-sig");
}

BOOST_AUTO_TEST_CASE(deposit_protest_gate)
{
    const DemandScene sc;
    CHouse house = MakeOpenDepositHouse(sc.H);
    house.nDepositUnits = sc.P;
    const uint32_t nTag = 1100 | NOTE_DEMAND_PREAUTH_BIT;
    const Coin demanded = sc.Receipt(nTag);
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    const int nAt = 1100 + (int)Params().GetConsensus().nDemandWindow;
    house.nLastAttestHeight = (uint32_t)nAt - 5;   // Open at the protest
    CHouse out;
    BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, house, preauth), nAt, house, demanded, &out), "OK");
    BOOST_CHECK_EQUAL(out.nProtestOpen, 1U);
    BOOST_CHECK_EQUAL(out.nProtestHeight, (uint32_t)nAt);
    BOOST_CHECK_EQUAL(out.nProtestDemandHeight, 1100U);
    BOOST_CHECK(HouseEffectiveStatus(out, nAt) == HOUSE_STATUS_STRESSED);   // the protest stresses the house
    BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, house, preauth), nAt - 1, house, demanded),
                      "bad-deposit-protest-early");
    CHouse hStale = house; hStale.nProtestOpen = 3;
    BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, house, preauth), nAt, hStale, demanded), "bad-deposit-protest-prior");
    const CScript other = DepositScriptForPubKey(FreshPubKey());
    BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, house, sc.PreAuth(std::vector<unsigned char>(other.begin(), other.end()))),
                      nAt, house, demanded), "bad-deposit-protest-preauth-sig");
    CHouse hDeferred = house; hDeferred.nDeferInvokedHeight = (uint32_t)nAt - 50;
    BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, hDeferred, preauth), nAt, hDeferred, demanded),
                      "bad-deposit-protest-house-status");
    // A demand tag with no height (the mempool view's) can never be protested.
    BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, NOTE_DEMAND_PREAUTH_BIT, house, preauth), nAt, house,
                      sc.Receipt(NOTE_DEMAND_PREAUTH_BIT)), "bad-deposit-protest-no-demand-height");
}

BOOST_AUTO_TEST_CASE(deposit_discharge_gate)
{
    const DemandScene sc;
    CHouse house = MakeOpenDepositHouse(sc.H);
    house.nDepositUnits = sc.P;
    house.SetDepositWtMaturity((unsigned __int128)sc.P * sc.MAT);
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    const CScript scriptPay(sc.payout.begin(), sc.payout.end());
    const int nAt = 1100;
    const CAmount due = (CAmount)sc.P + DepositMaturityInterest(sc.P, (uint32_t)nAt - sc.ORIG, sc.R);
    {
        CHouse out;
        BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due, preauth, scriptPay), nAt, house,
                          sc.Receipt(1000 | NOTE_DEMAND_PREAUTH_BIT), &out), "OK");
        BOOST_CHECK_EQUAL(out.nDepositUnits, 0U);
        BOOST_CHECK(out.DepositWtMaturity() == 0);
    }
    // A protested receipt paid: one fewer open protest.
    {
        CHouse h = house; h.nProtestOpen = 1; h.nProtestHeight = 1090;
        CHouse out;
        BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, h, due, preauth, scriptPay), nAt, h,
                          sc.Receipt(1000 | NOTE_DEMAND_PREAUTH_BIT | NOTE_DEMAND_PROTESTED_BIT), &out), "OK");
        BOOST_CHECK_EQUAL(out.nProtestOpen, 0U);
    }
    const Coin demanded = sc.Receipt(1000 | NOTE_DEMAND_PREAUTH_BIT);
    BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due - 1, preauth, scriptPay), nAt, house, demanded),
                      "bad-deposit-discharge-underpaid");
    BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due, preauth, DepositScriptForPubKey(FreshPubKey())), nAt, house,
                      demanded), "bad-deposit-discharge-underpaid");
    const CScript other = DepositScriptForPubKey(FreshPubKey());
    BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due, sc.PreAuth(std::vector<unsigned char>(other.begin(), other.end())),
                      scriptPay), nAt, house, demanded), "bad-deposit-discharge-preauth-sig");
    CHouse hStale = house; hStale.nProtestOpen = 2;
    BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due, preauth, scriptPay), nAt, hStale, demanded),
                      "bad-deposit-discharge-prior");
    // Suspended: deposits stay junior to the noteholders it has stopped paying.
    CHouse hDeferred = house; hDeferred.nDeferInvokedHeight = 1050; hDeferred.nLastAttestHeight = 1090;
    BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, hDeferred, due, preauth, scriptPay), nAt, hDeferred, demanded),
                      "bad-deposit-discharge-house-status");
    BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due, preauth, scriptPay), nAt, house, sc.Receipt(0)),
                      "bad-deposit-discharge-no-receipt");
}

BOOST_AUTO_TEST_CASE(deposit_demand_input_layer)
{
    const DemandScene sc;
    auto inputs = [&](const CMutableTransaction& mtx, const Coin& receipt) {
        CCoinsView base; CCoinsViewCache cache(&base);
        cache.AddCoin(COutPoint(uint256S("rc"), 0), Coin(receipt), false);
        cache.AddCoin(COutPoint(uint256S("ff"), 0),
                      Coin(CTxOut(10 * COIN, DepositScriptForPubKey(FreshPubKey())), 60, false, false, false, uint256()), false);
        CValidationState state; CAmount fee = 0;
        if (Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 2000, fee))
            return std::string("OK");
        return state.GetRejectReason();
    };
    const uint32_t nTag = 1100 | NOTE_DEMAND_PREAUTH_BIT;
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    CHouse house = MakeOpenDepositHouse(sc.H);
    // A demanded receipt leaves only by PROTEST / DISCHARGE / CLAIM; a plain one never by those first two.
    {
        DepositTransfer x; x.nHouseID = sc.H; x.nPrincipal = sc.P; x.nRateBps = sc.R; x.nMaturityHeight = sc.MAT;
        x.nOriginationHeight = sc.ORIG; x.vchSenderPubKey = sc.pub; x.vchSenderSig = std::vector<unsigned char>(70, 0x30);
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_TRANSFER;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << x;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("rc"), 0)));
        mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(FreshPubKey())));
        BOOST_CHECK_EQUAL(inputs(mtx, sc.Receipt(nTag)), "bad-deposit-demanded");
    }
    BOOST_CHECK_EQUAL(inputs(MakeDemandTx(sc, sc.payout, preauth, NotePreAuthScript(sc.pub)), sc.Receipt(nTag)),
                      "bad-deposit-demanded");
    BOOST_CHECK_EQUAL(inputs(MakeProtestTx(sc, nTag, house, preauth), sc.Receipt(0)), "bad-deposit-not-demanded");
    BOOST_CHECK_EQUAL(inputs(MakeDischargeTx(sc, house, 200000, preauth, DepositScriptForPubKey(sc.pub)), sc.Receipt(0)),
                      "bad-deposit-not-demanded");
    // The payload's terms are what AddCoins re-tags from: pinned to the spent receipt.
    {
        Coin r = sc.Receipt(0); r.nDepositPrincipal = sc.P + 1;
        BOOST_CHECK_EQUAL(inputs(MakeDemandTx(sc, sc.payout, preauth, NotePreAuthScript(sc.pub)), r),
                          "bad-deposit-demand-terms-mismatch");
    }
    {
        BOOST_CHECK_EQUAL(inputs(MakeProtestTx(sc, nTag, house, preauth), sc.Receipt(nTag + 1)),
                          "bad-deposit-protest-terms-mismatch");
    }
    // The custody pin: a demanded receipt of ANOTHER key cannot be discharged under this payload's key.
    {
        Coin r = sc.Receipt(nTag);
        r.out.scriptPubKey = NotePreAuthScript(FreshPubKey());
        BOOST_CHECK_EQUAL(inputs(MakeDischargeTx(sc, house, 200000, preauth, DepositScriptForPubKey(sc.pub)), r),
                          "bad-deposit-input-not-holder");
    }
    // An insolvency CLAIM of a demanded receipt is pinned to the custody script of the payload's key.
    {
        DepositClaim c; c.nHouseID = sc.H; c.vchHolderPubKey = sc.pub; c.vchHolderSig = std::vector<unsigned char>(70, 0x30);
        CMutableTransaction mtx; mtx.nVersion = TRANSACTION_DEPOSIT_VERSION; mtx.nDepositOp = DEPOSIT_OP_CLAIM;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << c;
        mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("rc"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("ff"), 0)));
        mtx.vout.push_back(CTxOut(1000, DepositScriptForPubKey(sc.pub)));
        BOOST_CHECK_EQUAL(inputs(mtx, sc.Receipt(nTag)), "OK");
        Coin r = sc.Receipt(nTag);
        r.out.scriptPubKey = NotePreAuthScript(FreshPubKey());
        BOOST_CHECK_EQUAL(inputs(mtx, r), "bad-deposit-input-not-holder");
    }
    // A plain DEMAND of a plain receipt passes the input layer.
    BOOST_CHECK_EQUAL(inputs(MakeDemandTx(sc, sc.payout, preauth, NotePreAuthScript(sc.pub)), sc.Receipt(0)), "OK");
}

namespace {
// Decode a deposit payload, change it, encode it back (the tx's other fields untouched).
template <typename T>
CMutableTransaction Repack(CMutableTransaction mtx, const std::function<void(T&)>& f)
{
    T p;
    BOOST_REQUIRE(DecodeDepositPayload(mtx.vchDepositPayload, p));
    f(p);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << p;
    mtx.vchDepositPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    return mtx;
}

CMutableTransaction Garbled(CMutableTransaction mtx)
{
    mtx.vchDepositPayload = {0x01};
    return mtx;
}
} // namespace

// v0.2.29 mutation follow-up: the DEMAND / PROTEST / DISCHARGE shape refusals (CheckDepositTransactionShape), each
// pinned by its reason.
BOOST_AUTO_TEST_CASE(deposit_demand_shape)
{
    const DemandScene sc;
    const CScript custody = NotePreAuthScript(sc.pub);
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    const CHouse house = MakeOpenDepositHouse(sc.H);
    const uint32_t nTag = 1100 | NOTE_DEMAND_PREAUTH_BIT;
    auto shape = [](const CMutableTransaction& mtx) {
        CValidationState state;
        return CheckDepositTransactionShape(CTransaction(mtx), state) ? std::string("OK") : state.GetRejectReason();
    };

    const CMutableTransaction demand = MakeDemandTx(sc, sc.payout, preauth, custody);
    BOOST_CHECK_EQUAL(shape(demand), "OK");
    BOOST_CHECK_EQUAL(shape(Garbled(demand)), "bad-deposit-demand-payload");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDemand>(demand, [](DepositDemand& d) { d.nPrincipal = 0; })),
                      "bad-deposit-demand-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDemand>(demand, [](DepositDemand& d) { d.nPrincipal = (uint64_t)MAX_MONEY + 1; })),
                      "bad-deposit-demand-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDemand>(demand, [](DepositDemand& d) { d.vchPayoutScript.clear(); })),
                      "bad-deposit-demand-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDemand>(demand, [](DepositDemand& d) { d.vchPayoutScript.assign(129, 0x51); })),
                      "bad-deposit-demand-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDemand>(demand, [](DepositDemand& d) { d.vchHolderPubKey = {0x02}; })),
                      "bad-deposit-demand-sig-shape");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDemand>(demand, [](DepositDemand& d) { d.vchPreAuthSig.clear(); })),
                      "bad-deposit-demand-sig-shape");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDemand>(demand, [](DepositDemand& d) { d.vchPreAuthSig.assign(81, 0x30); })),
                      "bad-deposit-demand-sig-shape");
    {
        CMutableTransaction m = demand; m.vout.clear();
        BOOST_CHECK_EQUAL(shape(m), "bad-deposit-demand-vout");
        m = demand; m.vout[0].nValue = DEPOSIT_DUST_VALUE + 1;
        BOOST_CHECK_EQUAL(shape(m), "bad-deposit-demand-vout");
        m = demand; m.vout[0].scriptPubKey = DepositScriptForPubKey(sc.pub);
        BOOST_CHECK_EQUAL(shape(m), "bad-deposit-demand-vout");
    }

    const CMutableTransaction protest = MakeProtestTx(sc, nTag, house, preauth);
    BOOST_CHECK_EQUAL(shape(protest), "OK");
    BOOST_CHECK_EQUAL(shape(Garbled(protest)), "bad-deposit-protest-payload");
    BOOST_CHECK_EQUAL(shape(Repack<DepositProtest>(protest, [](DepositProtest& p) { p.nPrincipal = 0; })),
                      "bad-deposit-protest-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositProtest>(protest, [](DepositProtest& p) { p.nDemandTag = 1100; })),
                      "bad-deposit-protest-fields");   // not a pre-authorized demand
    BOOST_CHECK_EQUAL(shape(Repack<DepositProtest>(protest, [](DepositProtest& p) { p.nDemandTag |= NOTE_DEMAND_PROTESTED_BIT; })),
                      "bad-deposit-protest-fields");   // already protested
    BOOST_CHECK_EQUAL(shape(Repack<DepositProtest>(protest, [](DepositProtest& p) { p.vchHolderSig.clear(); })),
                      "bad-deposit-demand-sig-shape");
    {
        CMutableTransaction m = protest; m.vout[0].scriptPubKey = DepositScriptForPubKey(sc.pub);
        BOOST_CHECK_EQUAL(shape(m), "bad-deposit-demand-vout");
    }

    const CMutableTransaction discharge = MakeDischargeTx(sc, house, 200000, preauth, DepositScriptForPubKey(sc.pub));
    BOOST_CHECK_EQUAL(shape(discharge), "OK");
    BOOST_CHECK_EQUAL(shape(Garbled(discharge)), "bad-deposit-discharge-payload");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDischarge>(discharge, [](DepositDischarge& d) { d.vchHolderPubKey = {0x02}; })),
                      "bad-deposit-discharge-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDischarge>(discharge, [](DepositDischarge& d) { d.vchPayoutScript.clear(); })),
                      "bad-deposit-discharge-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDischarge>(discharge, [](DepositDischarge& d) { d.vchPayoutScript.assign(129, 0x51); })),
                      "bad-deposit-discharge-fields");
    BOOST_CHECK_EQUAL(shape(Repack<DepositDischarge>(discharge, [](DepositDischarge& d) { d.vchPreAuthSig.clear(); })),
                      "bad-deposit-discharge-fields");
    {
        CMutableTransaction m = discharge; m.vout.clear();
        BOOST_CHECK_EQUAL(shape(m), "bad-deposit-discharge-vout");
    }
}

// v0.2.29 mutation follow-up: the contextual refusals the gates above leave out - the payloads, the protest's own
// signature, the payout families at PROTEST / DISCHARGE, the protest's custody, and the discharge's accounting.
BOOST_AUTO_TEST_CASE(deposit_demand_context_more)
{
    const DemandScene sc;
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    CHouse house = MakeOpenDepositHouse(sc.H);
    house.nDepositUnits = sc.P;
    house.SetDepositWtMaturity((unsigned __int128)sc.P * sc.MAT);
    const CScript escrow = HouseEscrowScript(house.houseID);
    const std::vector<unsigned char> vEscrow(escrow.begin(), escrow.end());

    BOOST_CHECK_EQUAL(RunDeposit(Garbled(MakeDemandTx(sc, sc.payout, preauth, NotePreAuthScript(sc.pub))), 1100, house,
                      sc.Receipt(0)), "bad-deposit-demand-payload");

    // PROTEST, as in deposit_protest_gate.
    {
        const uint32_t nTag = 1100 | NOTE_DEMAND_PREAUTH_BIT;
        const Coin demanded = sc.Receipt(nTag);
        const int nAt = 1100 + (int)Params().GetConsensus().nDemandWindow;
        CHouse h = house; h.nLastAttestHeight = (uint32_t)nAt - 5;
        BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, h, preauth), nAt, h, demanded), "OK");
        BOOST_CHECK_EQUAL(RunDeposit(Garbled(MakeProtestTx(sc, nTag, h, preauth)), nAt, h, demanded),
                          "bad-deposit-protest-payload");
        CMutableTransaction m = MakeProtestTx(sc, nTag, h, preauth);
        m.vout.push_back(CTxOut(1000, DepositScriptForPubKey(FreshPubKey())));   // outputs changed after signing
        BOOST_CHECK_EQUAL(RunDeposit(m, nAt, h, demanded), "bad-deposit-protest-sig");
        BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, h, sc.PreAuth(vEscrow), vEscrow), nAt, h, demanded),
                          "bad-deposit-protest-payout-script");
        BOOST_CHECK_EQUAL(RunDeposit(MakeProtestTx(sc, nTag, h, preauth, {}, NotePreAuthScript(FreshPubKey())), nAt, h,
                          demanded), "bad-deposit-protest-custody-script");
    }

    // DISCHARGE, as in deposit_discharge_gate.
    {
        const Coin demanded = sc.Receipt(1000 | NOTE_DEMAND_PREAUTH_BIT);
        const CScript scriptPay(sc.payout.begin(), sc.payout.end());
        const int nAt = 1100;
        const CAmount due = (CAmount)sc.P + DepositMaturityInterest(sc.P, (uint32_t)nAt - sc.ORIG, sc.R);
        BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due, preauth, scriptPay), nAt, house, demanded), "OK");
        BOOST_CHECK_EQUAL(RunDeposit(Garbled(MakeDischargeTx(sc, house, due, preauth, scriptPay)), nAt, house, demanded),
                          "bad-deposit-discharge-payload");
        BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, house, due, sc.PreAuth(vEscrow), escrow, vEscrow), nAt, house,
                          demanded), "bad-deposit-discharge-payout-script");
        CHouse hShort = house; hShort.nDepositUnits = sc.P - 1;   // the liability can never go below zero
        BOOST_CHECK_EQUAL(RunDeposit(MakeDischargeTx(sc, hShort, due, preauth, scriptPay), nAt, hShort, demanded),
                          "bad-deposit-discharge-accounting");
    }
}

// v0.2.29: AddCoins re-issues the receipt with its demand tag - DEMAND stamps the connect height and the pre-auth bit,
// PROTEST adds the protested bit to the payload's tag - and the tag survives coin and undo serialization.
BOOST_AUTO_TEST_CASE(deposit_demand_addcoins_tags)
{
    const DemandScene sc;
    const CHouse house = MakeOpenDepositHouse(sc.H);
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    CCoinsView base;
    CCoinsViewCache cache(&base);

    const CTransaction demand(MakeDemandTx(sc, sc.payout, preauth, NotePreAuthScript(sc.pub)));
    AddCoins(cache, demand, 1100);
    const Coin& cd = cache.AccessCoin(COutPoint(demand.GetHash(), 0));
    BOOST_CHECK(cd.fDeposit);
    BOOST_CHECK_EQUAL(cd.nHouseID, sc.H);
    BOOST_CHECK_EQUAL(cd.nDepositPrincipal, sc.P);
    BOOST_CHECK_EQUAL(cd.nDepositOriginationHeight, sc.ORIG);   // the receipt's own clock, not the demand's height
    BOOST_CHECK_EQUAL(cd.nDemandHeight, 1100U | NOTE_DEMAND_PREAUTH_BIT);

    const uint32_t nTag = 1100 | NOTE_DEMAND_PREAUTH_BIT;
    const CTransaction protest(MakeProtestTx(sc, nTag, house, preauth));
    AddCoins(cache, protest, 1120);
    const Coin& cp = cache.AccessCoin(COutPoint(protest.GetHash(), 0));
    BOOST_CHECK(cp.fDeposit);
    BOOST_CHECK_EQUAL(cp.nDemandHeight, nTag | NOTE_DEMAND_PROTESTED_BIT);   // the demand's height kept, not 1120

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << cp;
    Coin c2;
    ss >> c2;
    BOOST_CHECK_EQUAL(c2.nDemandHeight, nTag | NOTE_DEMAND_PROTESTED_BIT);
    CTxUndo undo;
    undo.vprevout.push_back(cp);
    CDataStream ssu(SER_NETWORK, PROTOCOL_VERSION);
    ssu << undo;
    CTxUndo u2;
    ssu >> u2;
    BOOST_REQUIRE_EQUAL(u2.vprevout.size(), 1U);
    BOOST_CHECK_EQUAL(u2.vprevout[0].nDemandHeight, nTag | NOTE_DEMAND_PROTESTED_BIT);
}

// v0.2.29 mutation follow-up: the input layer's one-receipt and house pins for the three ops.
BOOST_AUTO_TEST_CASE(deposit_demand_input_pins)
{
    const DemandScene sc;
    const COutPoint rc(uint256S("rc"), 0), r2(uint256S("b2"), 0), ff(uint256S("ff"), 0);
    auto inputs = [&](const CMutableTransaction& mtx, const Coin& receipt, const Coin* pSecond = nullptr) {
        CCoinsView base; CCoinsViewCache cache(&base);
        cache.AddCoin(rc, Coin(receipt), false);
        if (pSecond) cache.AddCoin(r2, Coin(*pSecond), false);
        cache.AddCoin(ff, Coin(CTxOut(10 * COIN, DepositScriptForPubKey(FreshPubKey())), 60, false, false, false, uint256()),
                      false);
        CValidationState state; CAmount fee = 0;
        if (Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 2000, fee))
            return std::string("OK");
        return state.GetRejectReason();
    };
    const uint32_t nTag = 1100 | NOTE_DEMAND_PREAUTH_BIT;
    const std::vector<unsigned char> preauth = sc.PreAuth(sc.payout);
    const CHouse house = MakeOpenDepositHouse(sc.H);
    const CMutableTransaction discharge = MakeDischargeTx(sc, house, 200000, preauth, DepositScriptForPubKey(sc.pub));
    BOOST_CHECK_EQUAL(inputs(discharge, sc.Receipt(nTag)), "OK");

    // Exactly one receipt: none, or two.
    {
        CMutableTransaction m = MakeDemandTx(sc, sc.payout, preauth, NotePreAuthScript(sc.pub));
        m.vin[0] = CTxIn(ff);   // a plain coin, not a receipt
        BOOST_CHECK_EQUAL(inputs(m, sc.Receipt(0)), "bad-deposit-demand-inputs");
    }
    {
        CMutableTransaction m = discharge; m.vin.push_back(CTxIn(r2));
        const Coin second = sc.Receipt(nTag);
        BOOST_CHECK_EQUAL(inputs(m, sc.Receipt(nTag), &second), "bad-deposit-demand-inputs");
    }
    // The payload's house is the receipt's (DISCHARGE has no terms pin before it).
    {
        Coin r = sc.Receipt(nTag); r.nHouseID = sc.H + 1;
        BOOST_CHECK_EQUAL(inputs(discharge, r), "bad-deposit-input-house-mismatch");
    }
    // An unreadable DISCHARGE payload names no house.
    BOOST_CHECK_EQUAL(inputs(Garbled(discharge), sc.Receipt(nTag)), "bad-deposit-payload");
    // House escrow never feeds these ops: the escrow guard refuses it first (so the op-spends-escrow check after it is
    // a second line, not reachable on its own).
    {
        Coin esc(CTxOut(1000, HouseEscrowScript(house.houseID)), 60, false, false, false, uint256());
        esc.fHouseEscrow = true; esc.nHouseID = sc.H;
        CMutableTransaction m = discharge; m.vin.push_back(CTxIn(r2));
        BOOST_CHECK_EQUAL(inputs(m, sc.Receipt(nTag), &esc), "bad-txns-spend-house-coin");
    }
}

BOOST_AUTO_TEST_SUITE_END()
