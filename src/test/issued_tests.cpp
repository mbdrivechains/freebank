// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Issued tokens (tx v18, gram-notes release, docs-local/GOLD_USD_SCOPE.md step 2): the annex's shape, units conserved
// per token, the issuer and freeze keys, frozen units that follow the annex, and the annex bound by every input
// signature.

#include <issued.h>
#include <house.h>   // HOUSE_OP_TILL, HOUSE_OP_CLOSE, MutualFundScript (the vault-freeze test)

#include <chainparams.h>
#include <pool.h>
#include <pricefeed.h>

#include <coins.h>
#include <consensus/validation.h>
#include <creditbind.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <units.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

namespace {

template <typename T>
std::vector<unsigned char> Enc(const T& payload)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CScript P2PKH(const CKey& key) { return GetScriptForDestination(key.GetPubKey().GetID()); }

std::string ShapeReason(const CMutableTransaction& mtx)
{
    std::string strReason;
    CheckIssuedShape(CTransaction(mtx), strReason);
    return strReason;
}

std::string FlowReason(const CMutableTransaction& mtx, const std::vector<Coin>& vCoin)
{
    std::vector<const Coin*> vSpent;
    for (const Coin& c : vCoin)
        vSpent.push_back(&c);
    std::string strReason;
    CheckIssuedFlow(CTransaction(mtx), vSpent, strReason);
    return strReason;
}

Coin IssuedCoin(const uint256& token, uint64_t nUnits, uint64_t nFrozen = 0, int nHeight = 5)
{
    Coin c(CTxOut(ISSUED_COIN_VALUE, CScript() << OP_TRUE), nHeight, false, false, false, uint256());
    c.SetIssued(token, nUnits, nFrozen);
    return c;
}

CMutableTransaction TokenTx(uint8_t nOp, size_t nIn, size_t nOut)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_TOKEN_VERSION;
    mtx.nIssuedOp = nOp;
    for (size_t i = 0; i < nIn; i++)
        mtx.vin.emplace_back(COutPoint(uint256S(strprintf("%02x", (int)i + 1)), 0));
    for (size_t i = 0; i < nOut; i++)
        mtx.vout.emplace_back(ISSUED_COIN_VALUE, CScript() << OP_TRUE);
    return mtx;
}

CIssuedOut Out(uint32_t n, const uint256& token, uint64_t nUnits, uint64_t nFrozen = 0)
{
    CIssuedOut o;
    o.nOut = n;
    o.tokenID = token;
    o.nUnits = nUnits;
    o.nFrozen = nFrozen;
    return o;
}

/** A coins view with the given coins at the token tx's prevouts (vin[i] spends vCoin[i]). */
struct Inputs {
    CCoinsView base;
    CCoinsViewCache view{&base};
    Inputs(const CMutableTransaction& mtx, const std::vector<Coin>& vCoin)
    {
        for (size_t i = 0; i < vCoin.size(); i++)
            view.AddCoin(mtx.vin[i].prevout, Coin(vCoin[i]), false);
    }
};

std::string ConnectReason(const CMutableTransaction& mtx, const CCoinsViewCache& view, CUnitsView& units, int nHeight = 10)
{
    CValidationState state;
    if (ConnectIssuedTx(CTransaction(mtx), view, units, nHeight, state))
        return "";
    return state.GetRejectReason();
}

IssuedCreate MakeCreate(const CKey& issuer, const CKey* pFreeze)
{
    IssuedCreate c;
    c.nKind = ISSUED_KIND_GOLD_MG;
    c.strTicker = "GOLDA";
    c.vchIssuerKey = ToByteVector(issuer.GetPubKey());
    if (pFreeze)
        c.vchFreezeKey = ToByteVector(pFreeze->GetPubKey());
    c.vchBackingContract = std::vector<unsigned char>(20, 0xaa);
    c.vchBackingAddress = std::vector<unsigned char>(20, 0xbb);
    static uint32_t nAddr = 0;   // one token per backing address (review round 1, G1g): a fresh one per token
    nAddr++;
    c.vchBackingAddress[0] = (unsigned char)(nAddr >> 8);
    c.vchBackingAddress[1] = (unsigned char)nAddr;
    c.strUpstream = "acme-gold";
    return c;
}

/** CREATE a token into `units`; returns its id. */
uint256 CreateToken(CUnitsView& units, const CKey& issuer, const CKey* pFreeze)
{
    CMutableTransaction mtx = TokenTx(ISSUED_OP_CREATE, 1, 1);
    IssuedCreate c = MakeCreate(issuer, pFreeze);
    mtx.vchIssuedPayload = Enc(c);
    BOOST_REQUIRE(issuer.Sign(IssuedSigHash(CTransaction(mtx)), c.vchIssuerSig));
    mtx.vchIssuedPayload = Enc(c);
    BOOST_REQUIRE_EQUAL(ShapeReason(mtx), "");
    Inputs in(mtx, {});
    BOOST_REQUIRE_EQUAL(ConnectReason(mtx, in.view, units), "");
    return CTransaction(mtx).GetHash();
}

} // namespace

// D-2026-11-04-1 (3b): a token or pool creation burns 1 g at the payout price; these tests have no price feed, so they
// turn the burn off (issued_create_needs_a_price checks it on).
struct IssuedTestingSetup : public BasicTestingSetup {
    IssuedTestingSetup() { UpdateCreateFeeForTest(0); }
    ~IssuedTestingSetup() { UpdateCreateFeeForTest(Consensus::GramParams().nCreateFeeMg); }
};

BOOST_FIXTURE_TEST_SUITE(issued_tests, IssuedTestingSetup)

BOOST_AUTO_TEST_CASE(issued_annex_roundtrips_and_binds)
{
    const uint256 token = uint256S("aa");
    CMutableTransaction mtx = TokenTx(ISSUED_OP_TRANSFER, 1, 2);
    mtx.vIssuedOut = {Out(0, token, 700), Out(1, token, 300, 300)};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << CTransaction(mtx);
    CMutableTransaction back;
    ss >> back;
    BOOST_CHECK(back.vIssuedOut == mtx.vIssuedOut);
    BOOST_CHECK_EQUAL(back.nIssuedOp, ISSUED_OP_TRANSFER);
    BOOST_CHECK(CTransaction(back).GetHash() == CTransaction(mtx).GetHash());

    // Every input signature binds the annex: moving units between outputs changes the binding hash.
    BOOST_CHECK(IsCreditBindingVersion(TRANSACTION_TOKEN_VERSION));
    const uint256 h = CreditBindingHash(CTransaction(mtx));
    mtx.vIssuedOut = {Out(0, token, 300), Out(1, token, 700, 300)};
    BOOST_CHECK(CreditBindingHash(CTransaction(mtx)) != h);

    // A plain transaction carries no annex on the wire.
    CMutableTransaction plain;
    plain.nVersion = 2;
    plain.vin.emplace_back(COutPoint(uint256S("01"), 0));
    plain.vout.emplace_back(1000, CScript() << OP_TRUE);
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << CTransaction(plain);
    CMutableTransaction plainBack;
    ss2 >> plainBack;
    BOOST_CHECK(plainBack.vIssuedOut.empty() && ss2.empty());
}

BOOST_AUTO_TEST_CASE(issued_annex_shape)
{
    const uint256 token = uint256S("aa");
    CMutableTransaction mtx = TokenTx(ISSUED_OP_TRANSFER, 1, 3);
    mtx.vIssuedOut = {Out(0, token, 5), Out(2, token, 5)};
    BOOST_CHECK_EQUAL(ShapeReason(mtx), "");

    CMutableTransaction m = mtx;
    m.vIssuedOut = {Out(2, token, 5), Out(0, token, 5)};
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-order");
    m.vIssuedOut = {Out(0, token, 5), Out(0, token, 5)};
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-order");
    m.vIssuedOut = {Out(3, token, 5)};
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-out");
    m.vIssuedOut = {Out(0, token, 0)};
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-units");
    m.vIssuedOut = {Out(0, token, 5, 6)};
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-units");
    m.vIssuedOut = {Out(0, uint256(), 5)};
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-units");
    m = mtx;
    m.vout[2].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-unspendable");

    // Nine tokens in one transaction is one too many.
    m = TokenTx(ISSUED_OP_TRANSFER, 1, 9);
    for (uint32_t n = 0; n < 9; n++)
        m.vIssuedOut.push_back(Out(n, uint256S(strprintf("%02x", (int)n + 1)), 1));
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-annex-tokens");

    // Credit ops don't carry issued units until their own rules learn them.
    CMutableTransaction house;
    house.nVersion = TRANSACTION_HOUSE_VERSION;
    house.vin.emplace_back(COutPoint(uint256S("01"), 0));
    house.vout.emplace_back(1000, CScript() << OP_TRUE);
    house.vIssuedOut = {Out(0, token, 5)};
    BOOST_CHECK_EQUAL(ShapeReason(house), "bad-issued-annex-op");
    // A TRANSFER with nothing to move is no transfer.
    m = TokenTx(ISSUED_OP_TRANSFER, 1, 1);
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-transfer-empty");
    // An unknown op.
    m = TokenTx(99, 1, 1);
    BOOST_CHECK_EQUAL(ShapeReason(m), "bad-issued-op");
}

BOOST_AUTO_TEST_CASE(issued_units_are_conserved)
{
    const uint256 a = uint256S("aa"), b = uint256S("bb");
    CMutableTransaction mtx = TokenTx(ISSUED_OP_TRANSFER, 2, 3);
    mtx.vIssuedOut = {Out(0, a, 60), Out(1, a, 40), Out(2, b, 7)};
    BOOST_CHECK_EQUAL(FlowReason(mtx, {IssuedCoin(a, 100), IssuedCoin(b, 7)}), "");
    BOOST_CHECK_EQUAL(FlowReason(mtx, {IssuedCoin(a, 101), IssuedCoin(b, 7)}), "bad-issued-flow");   // a unit lost
    BOOST_CHECK_EQUAL(FlowReason(mtx, {IssuedCoin(a, 100), IssuedCoin(b, 6)}), "bad-issued-flow");   // a unit made

    // MINT adds exactly its units, BURN removes exactly its units.
    IssuedMint mint;
    mint.tokenID = a;
    mint.nUnits = 50;
    CMutableTransaction m = TokenTx(ISSUED_OP_MINT, 1, 1);
    m.vchIssuedPayload = Enc(mint);
    m.vIssuedOut = {Out(0, a, 50)};
    Coin plainCoin(CTxOut(10000, CScript() << OP_TRUE), 5, false, false, false, uint256());
    BOOST_CHECK_EQUAL(FlowReason(m, {plainCoin}), "");
    m.vIssuedOut = {Out(0, a, 51)};
    BOOST_CHECK_EQUAL(FlowReason(m, {plainCoin}), "bad-issued-mint-flow");
    m.vIssuedOut = {Out(0, b, 50)};   // minting one token can't make another's units
    BOOST_CHECK(FlowReason(m, {plainCoin}) != "");

    IssuedBurn burn;
    burn.tokenID = a;
    burn.nUnits = 30;
    burn.vchEthDest = std::vector<unsigned char>(20, 1);
    m = TokenTx(ISSUED_OP_BURN, 1, 1);
    m.vchIssuedPayload = Enc(burn);
    m.vIssuedOut = {Out(0, a, 70)};
    BOOST_CHECK_EQUAL(FlowReason(m, {IssuedCoin(a, 100)}), "");
    m.vIssuedOut = {Out(0, a, 71)};
    BOOST_CHECK_EQUAL(FlowReason(m, {IssuedCoin(a, 100)}), "bad-issued-burn-flow");

    // Issued coins never move in a plain transaction (their units would vanish) or a credit op without an annex.
    CMutableTransaction plain;
    plain.nVersion = 2;
    plain.vin.emplace_back(COutPoint(uint256S("01"), 0));
    plain.vout.emplace_back(1000, CScript() << OP_TRUE);
    BOOST_CHECK_EQUAL(FlowReason(plain, {IssuedCoin(a, 100)}), "bad-issued-input-op");
    CMutableTransaction house = plain;
    house.nVersion = TRANSACTION_HOUSE_VERSION;
    BOOST_CHECK_EQUAL(FlowReason(house, {IssuedCoin(a, 100)}), "bad-issued-input-op");
}

BOOST_AUTO_TEST_CASE(issued_create_mint_burn_against_the_units_state)
{
    CUnitsView units(nullptr);
    CKey issuer, other;
    issuer.MakeNewKey(true);
    other.MakeNewKey(true);
    const uint256 token = CreateToken(units, issuer, nullptr);
    CIssuedToken rec;
    BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
    BOOST_CHECK_EQUAL(rec.nSupply, 0u);
    BOOST_CHECK_EQUAL(rec.strUpstream, "acme-gold");
    BOOST_CHECK_EQUAL(rec.nCreateHeight, 10);

    // MINT: only the issuer key; the signature is bound to this transaction's inputs, outputs and annex.
    IssuedMint mint;
    mint.tokenID = token;
    mint.nUnits = 1000;
    CMutableTransaction m = TokenTx(ISSUED_OP_MINT, 1, 1);
    m.vIssuedOut = {Out(0, token, 1000)};
    m.vchIssuedPayload = Enc(mint);
    BOOST_REQUIRE(other.Sign(IssuedSigHash(CTransaction(m)), mint.vchIssuerSig));
    m.vchIssuedPayload = Enc(mint);
    Coin fund(CTxOut(10000, P2PKH(issuer)), 5, false, false, false, uint256());
    Inputs in(m, {fund});
    BOOST_CHECK_EQUAL(ConnectReason(m, in.view, units), "bad-issued-mint-sig");
    BOOST_REQUIRE(issuer.Sign(IssuedSigHash(CTransaction(m)), mint.vchIssuerSig));
    m.vchIssuedPayload = Enc(mint);
    BOOST_CHECK_EQUAL(ConnectReason(m, in.view, units), "");
    BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
    BOOST_CHECK_EQUAL(rec.nSupply, 1000u);

    // The same signature in another transaction (another input) mints nothing.
    CMutableTransaction replay = m;
    replay.vin[0].prevout = COutPoint(uint256S("77"), 0);
    Inputs in2(replay, {fund});
    BOOST_CHECK_EQUAL(ConnectReason(replay, in2.view, units), "bad-issued-mint-sig");

    // MINT of an unknown token.
    IssuedMint ghost = mint;
    ghost.tokenID = uint256S("99");
    CMutableTransaction g = TokenTx(ISSUED_OP_MINT, 1, 1);
    g.vIssuedOut = {Out(0, ghost.tokenID, 1000)};
    g.vchIssuedPayload = Enc(ghost);
    BOOST_CHECK_EQUAL(ConnectReason(g, in.view, units), "bad-issued-mint-token");

    // BURN: supply falls, the burn joins the queue with its Ethereum destination.
    IssuedBurn burn;
    burn.tokenID = token;
    burn.nUnits = 300;
    burn.vchEthDest = std::vector<unsigned char>(20, 0xcc);
    CMutableTransaction b = TokenTx(ISSUED_OP_BURN, 1, 1);
    b.vIssuedOut = {Out(0, token, 700)};
    b.vchIssuedPayload = Enc(burn);
    Inputs inB(b, {IssuedCoin(token, 1000)});
    BOOST_CHECK_EQUAL(ConnectReason(b, inB.view, units, 12), "");
    BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
    BOOST_CHECK_EQUAL(rec.nSupply, 700u);
    BOOST_CHECK_EQUAL(rec.nBurnSeq, 1u);
    CIssuedBurn queued;
    BOOST_REQUIRE(units.Get(IssuedBurnKey(token, 0), queued));
    BOOST_CHECK_EQUAL(queued.nUnits, 300u);
    BOOST_CHECK_EQUAL(queued.nHeight, 12);
    BOOST_CHECK(queued.vchEthDest == burn.vchEthDest);
}

BOOST_AUTO_TEST_CASE(issued_frozen_units_follow_the_annex)
{
    CUnitsView units(nullptr);
    CKey issuer, freezer;
    issuer.MakeNewKey(true);
    freezer.MakeNewKey(true);
    const uint256 token = CreateToken(units, issuer, &freezer);

    // A held coin of 100 units; the freeze key freezes 40 of them.
    const COutPoint held(uint256S("51"), 0);
    CCoinsView base;
    CCoinsViewCache view(&base);
    view.AddCoin(held, IssuedCoin(token, 100), false);

    IssuedFreeze fz;
    fz.tokenID = token;
    fz.vOutpoint = {held};
    fz.vFrozen = {40};
    CMutableTransaction f = TokenTx(ISSUED_OP_FREEZE, 1, 1);
    f.vchIssuedPayload = Enc(fz);
    BOOST_REQUIRE(issuer.Sign(IssuedSigHash(CTransaction(f)), fz.vchFreezeSig));   // the issuer key isn't the freeze key
    f.vchIssuedPayload = Enc(fz);
    BOOST_CHECK_EQUAL(ConnectReason(f, view, units), "bad-issued-freeze-sig");
    BOOST_REQUIRE(freezer.Sign(IssuedSigHash(CTransaction(f)), fz.vchFreezeSig));
    f.vchIssuedPayload = Enc(fz);
    BOOST_CHECK_EQUAL(ConnectReason(f, view, units), "");
    uint64_t nFrozen = 0;
    BOOST_REQUIRE(units.Get(IssuedFrozenKey(held.hash, held.n), nFrozen));
    BOOST_CHECK_EQUAL(nFrozen, 40u);
    // FREEZE only raises: freezing to 40 again is refused.
    BOOST_CHECK_EQUAL(ConnectReason(f, view, units), "bad-issued-freeze-direction");

    // Spending it: the 40 frozen units must go on, frozen, wherever the annex puts them.
    CMutableTransaction t = TokenTx(ISSUED_OP_TRANSFER, 1, 2);
    t.vin[0].prevout = held;
    t.vIssuedOut = {Out(0, token, 60), Out(1, token, 40)};
    BOOST_CHECK_EQUAL(ConnectReason(t, view, units), "bad-issued-frozen-flow");   // shed the freeze: refused
    t.vIssuedOut = {Out(0, token, 60, 0), Out(1, token, 40, 40)};
    BOOST_CHECK_EQUAL(ConnectReason(t, view, units), "");
    BOOST_CHECK(!units.Have(IssuedFrozenKey(held.hash, held.n)));   // the record went with the coin

    // A coin created frozen by an annex counts as frozen when spent, with no record at all.
    const COutPoint born(uint256S("52"), 1);
    view.AddCoin(born, IssuedCoin(token, 40, 40), false);
    CMutableTransaction t2 = TokenTx(ISSUED_OP_TRANSFER, 1, 1);
    t2.vin[0].prevout = born;
    t2.vIssuedOut = {Out(0, token, 40, 0)};
    BOOST_CHECK_EQUAL(ConnectReason(t2, view, units), "bad-issued-frozen-flow");
    t2.vIssuedOut = {Out(0, token, 40, 40)};
    BOOST_CHECK_EQUAL(ConnectReason(t2, view, units), "");

    // UNFREEZE lowers; a token with no freeze key can't be frozen at all.
    IssuedFreeze un = fz;
    un.vOutpoint = {born};
    un.vFrozen = {0};
    CMutableTransaction u = TokenTx(ISSUED_OP_UNFREEZE, 1, 1);
    u.vchIssuedPayload = Enc(un);
    BOOST_REQUIRE(freezer.Sign(IssuedSigHash(CTransaction(u)), un.vchFreezeSig));
    u.vchIssuedPayload = Enc(un);
    BOOST_CHECK_EQUAL(ConnectReason(u, view, units), "");
    BOOST_REQUIRE(units.Get(IssuedFrozenKey(born.hash, born.n), nFrozen));
    BOOST_CHECK_EQUAL(nFrozen, 0u);

    const uint256 plainToken = CreateToken(units, issuer, nullptr);
    const COutPoint held2(uint256S("53"), 0);
    view.AddCoin(held2, IssuedCoin(plainToken, 10), false);
    IssuedFreeze fz2;
    fz2.tokenID = plainToken;
    fz2.vOutpoint = {held2};
    fz2.vFrozen = {10};
    CMutableTransaction f2 = TokenTx(ISSUED_OP_FREEZE, 1, 1);
    f2.vchIssuedPayload = Enc(fz2);
    BOOST_CHECK_EQUAL(ConnectReason(f2, view, units), "bad-issued-freeze-no-key");
}

BOOST_AUTO_TEST_CASE(issued_coin_tags_from_the_annex)
{
    const uint256 token = uint256S("aa");
    CMutableTransaction mtx = TokenTx(ISSUED_OP_TRANSFER, 1, 3);
    mtx.vIssuedOut = {Out(1, token, 9, 4)};
    const CTransaction tx(mtx);
    for (uint32_t n = 0; n < 3; n++) {
        Coin c(tx.vout[n], 7, false, false, false, uint256());
        ApplyIssuedCoinTags(tx, n, c);
        BOOST_CHECK_EQUAL(c.fIssued, n == 1);
        if (n == 1) {
            BOOST_CHECK(c.assetID == token && c.nIssuedUnits == 9u && c.nIssuedFrozen == 4u);
            BOOST_CHECK(c.IsAssetColoured() && !c.IsV10Asset());
        }
    }
    // The coin round-trips through its disk record with its units.
    Coin c(tx.vout[1], 7, false, false, false, uint256());
    ApplyIssuedCoinTags(tx, 1, c);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << c;
    Coin back;
    ss >> back;
    BOOST_CHECK(back.fIssued && back.assetID == token && back.nIssuedUnits == 9u && back.nIssuedFrozen == 4u);
}

BOOST_AUTO_TEST_CASE(issued_bond_valued_in_grams_and_topped_up)
{
    CUnitsView units(nullptr);
    CKey issuer;
    issuer.MakeNewKey(true);
    const uint256 token = CreateToken(units, issuer, nullptr);

    // The bond script: its own 36-byte form, readable back to the token.
    const CScript script = IssuedBondScript(token);
    uint256 back;
    BOOST_CHECK(IsIssuedBondScript(script, &back) && back == token);
    BOOST_CHECK(!IsIssuedBondScript(CScript() << std::vector<unsigned char>(token.begin(), token.end()) << OP_DROP << OP_TRUE));

    // A price: three reporters at 100,000 sats per gram, fixed at height 9.
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(0);
    const ReporterCounts fnAll = [](uint32_t) { return true; };
    COracleObs obs;
    obs.nStream = ORACLE_STREAM_GOLD_ECX;
    obs.nValue = 100000;
    for (uint32_t id = 1; id <= 3; id++)
        PriceFeedRecord(units, id, {obs}, 9);
    PriceFeedEndBlock(units, 9, gp, 3, fnAll);

    // BOND 10 ECX at height 10: 1e9 sats / 100,000 sats per gram = 10,000 g = 10,000,000 mg.
    IssuedBond bond;
    bond.tokenID = token;
    CMutableTransaction b = TokenTx(ISSUED_OP_BOND, 1, 1);
    b.vout[0] = CTxOut(10 * COIN, IssuedBondScript(token));
    b.vchIssuedPayload = Enc(bond);
    BOOST_CHECK_EQUAL(ShapeReason(b), "");
    BOOST_REQUIRE(issuer.Sign(IssuedSigHash(CTransaction(b)), bond.vchIssuerSig));
    b.vchIssuedPayload = Enc(bond);
    Coin fund(CTxOut(11 * COIN, P2PKH(issuer)), 5, false, false, false, uint256());
    Inputs in(b, {fund});
    BOOST_CHECK_EQUAL(ConnectReason(b, in.view, units, 10), "");
    CIssuedToken rec;
    BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
    BOOST_CHECK_EQUAL(rec.nBondSats, 10 * COIN);
    BOOST_CHECK_EQUAL(rec.nBondMgAtLock, 10000000u);
    BOOST_CHECK(rec.bondOutpoint == COutPoint(CTransaction(b).GetHash(), 0));

    // A second BOND that doesn't consolidate the first is refused; a stray bond script elsewhere is refused by shape.
    CMutableTransaction b2 = b;
    b2.vin[0].prevout = COutPoint(uint256S("66"), 0);
    IssuedBond bond2 = bond;
    BOOST_REQUIRE(issuer.Sign(IssuedSigHash(CTransaction(b2)), bond2.vchIssuerSig));   // the signature binds the inputs
    b2.vchIssuedPayload = Enc(bond2);
    Inputs in2(b2, {fund});
    BOOST_CHECK_EQUAL(ConnectReason(b2, in2.view, units, 11), "bad-issued-bond-not-consolidated");
    CMutableTransaction stray = b;
    stray.vout.push_back(CTxOut(COIN, IssuedBondScript(token)));
    BOOST_CHECK_EQUAL(ShapeReason(stray), "bad-issued-bond-stray");

    // ECX falls to 200,000 sats per gram: the bond is worth 5,000 g, below its 10,000 g at lock, so the 30-day top-up
    // clock starts; k stays 1 (no pool yet).
    obs.nValue = 200000;
    for (uint32_t id = 1; id <= 3; id++)
        PriceFeedRecord(units, id, {obs}, 200);
    PriceFeedEndBlock(units, 200, gp, 3, fnAll);
    const auto fnNo = [](const CIssuedToken&) { return false; };
    IssuedTokensEndBlock(units, 200, gp, fnNo, fnNo);
    BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
    BOOST_CHECK_EQUAL(rec.nBondTopUpDeadline, 200 + (int)ISSUED_BOND_TOPUP_BLOCKS);
    BOOST_CHECK_EQUAL(rec.nK, 1u);
}

BOOST_AUTO_TEST_CASE(issued_token_pool_create_swap_and_view)
{
    CUnitsView units(nullptr);
    CKey issuer, freezer;
    issuer.MakeNewKey(true);
    freezer.MakeNewKey(true);
    const uint256 token = CreateToken(units, issuer, nullptr);
    // A supply of 1,000,000 mg (as a mint would have made it).
    CIssuedToken rec;
    BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
    rec.nSupply = 1000000;
    units.Put(IssuedTokenKey(token), rec);

    // CREATE: 600,000 mg and 66,000,000 sats (110,000 sats per gram).
    uint64_t nLpOut = 0, nLpSupply = 0;
    BOOST_REQUIRE(PoolLpMintInitial(600000, 66000000, nLpOut, nLpSupply));
    IssuedPoolCreate pc;
    pc.tokenID = token;
    pc.nFeeBps = 30;
    pc.nInitUnits = 600000;
    pc.nInitSats = 66000000;
    pc.nLpOut = nLpOut;
    CMutableTransaction c = TokenTx(ISSUED_OP_POOL_CREATE, 2, 4);
    c.vout[0] = CTxOut(ISSUED_COIN_VALUE, TokenPoolScript(token));
    c.vout[1] = CTxOut(66000000, TokenPoolScript(token));
    c.vIssuedOut = {Out(0, token, 600000), Out(2, LpTokenID(token), nLpOut), Out(3, token, 400000)};
    c.vchIssuedPayload = Enc(pc);
    BOOST_CHECK_EQUAL(ShapeReason(c), "");
    Coin plain(CTxOut(COIN, CScript() << OP_TRUE), 5, false, false, false, uint256());
    BOOST_CHECK_EQUAL(FlowReason(c, {IssuedCoin(token, 1000000), plain}), "");
    Inputs inC(c, {IssuedCoin(token, 1000000), plain});
    BOOST_CHECK_EQUAL(ConnectReason(c, inC.view, units, 20), "");
    CTokenPool pool;
    BOOST_REQUIRE(units.Get(TokenPoolKey(token), pool));
    BOOST_CHECK_EQUAL(pool.nUnits, 600000u);
    BOOST_CHECK_EQUAL(pool.nLpSupply, nLpSupply);
    CIssuedToken lp;
    BOOST_REQUIRE(units.Get(IssuedTokenKey(LpTokenID(token)), lp));
    BOOST_CHECK_EQUAL(lp.nSupply, nLpOut);
    // One pool per token.
    BOOST_CHECK_EQUAL(ConnectReason(c, inC.view, units, 21), "bad-issued-pool-exists");

    // SWAP: sell 10,000 mg; the reserves are the custody coins the swap spends.
    const uint256 txCreate = CTransaction(c).GetHash();
    Coin custodyToken = IssuedCoin(token, 600000);
    custodyToken.out = CTxOut(ISSUED_COIN_VALUE, TokenPoolScript(token));
    custodyToken.SetOracleBond();
    Coin custodySats(CTxOut(66000000, TokenPoolScript(token)), 20, false, false, false, uint256());
    custodySats.SetOracleBond();
    uint64_t nOut = 0;
    BOOST_REQUIRE(PoolSwapOut(10000, 600000, 66000000, 30, nOut));
    IssuedPoolSwap sw;
    sw.tokenID = token;
    sw.fSellTokens = 1;
    sw.nAmountIn = 10000;
    sw.nAmountOut = nOut;
    CMutableTransaction s1 = TokenTx(ISSUED_OP_POOL_SWAP, 3, 2);
    s1.vin[0].prevout = COutPoint(txCreate, 0);
    s1.vin[1].prevout = COutPoint(txCreate, 1);
    s1.vout[0] = CTxOut(ISSUED_COIN_VALUE, TokenPoolScript(token));
    s1.vout[1] = CTxOut(66000000 - (CAmount)nOut, TokenPoolScript(token));
    s1.vIssuedOut = {Out(0, token, 610000)};
    s1.vchIssuedPayload = Enc(sw);
    BOOST_CHECK_EQUAL(ShapeReason(s1), "");
    Inputs inS(s1, {custodyToken, custodySats, IssuedCoin(token, 10000)});
    BOOST_CHECK_EQUAL(ConnectReason(s1, inS.view, units, 22), "");
    BOOST_REQUIRE(units.Get(TokenPoolKey(token), pool));
    BOOST_CHECK_EQUAL(pool.nUnits, 610000u);
    BOOST_CHECK_EQUAL(pool.nSats, 66000000 - (CAmount)nOut);
    // An amount out that isn't the formula's is refused (one sat too many).
    IssuedPoolSwap greedy = sw;
    greedy.nAmountOut = nOut + 1;
    CMutableTransaction s2 = s1;
    s2.vout[1].nValue -= 1;
    s2.vchIssuedPayload = Enc(greedy);
    BOOST_CHECK_EQUAL(ConnectReason(s2, inS.view, units, 22), "bad-issued-pool-swap-amount");

    // A freeze-keyed token has no pool (R1-6).
    const uint256 fzToken = CreateToken(units, issuer, &freezer);
    IssuedPoolCreate pf = pc;
    pf.tokenID = fzToken;
    CMutableTransaction cf = c;
    cf.vout[0] = CTxOut(ISSUED_COIN_VALUE, TokenPoolScript(fzToken));
    cf.vout[1] = CTxOut(66000000, TokenPoolScript(fzToken));
    cf.vIssuedOut = {Out(0, fzToken, 600000), Out(2, LpTokenID(fzToken), nLpOut), Out(3, fzToken, 400000)};
    cf.vchIssuedPayload = Enc(pf);
    Inputs inF(cf, {IssuedCoin(fzToken, 1000000), plain});
    BOOST_CHECK_EQUAL(ConnectReason(cf, inF.view, units, 23), "bad-issued-pool-freeze-key");

    // The pool view: 61% of supply in the pool, so deep. Review round 1 (G1c): an untrusted token's pool sets no price;
    // a trusted token held in a vault counts once its pool has a full window of such samples.
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(0);
    TokenPoolsEndBlock(units, 22, gp);
    uint64_t nView = 0;
    bool fDeep = false, fCounts = true;
    BOOST_REQUIRE(TokenPoolView(units, token, 22, gp, nView, fDeep, &fCounts));
    BOOST_CHECK(fDeep);
    BOOST_CHECK(!fCounts);   // not trusted, not held: the pool doesn't count
    BOOST_CHECK_EQUAL(nView, (uint64_t)((unsigned __int128)(66000000 - nOut) * 1000 / 610000));
    uint64_t nPayout = 0;
    BOOST_CHECK(!PayoutPrice(units, 22, gp, nPayout));   // no oracle, no counting pool
    {
        CIssuedToken rec;
        BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
        rec.fTrusted = 1;
        units.Put(IssuedTokenKey(token), rec);
        units.Put(VaultTotalKey(token), (uint64_t)1000);   // a house holds some
    }
    for (int h = 23; h < 23 + (int)gp.nPoolViewBlocks - 1; h++) {
        TokenPoolsEndBlock(units, h, gp);
        BOOST_CHECK(!PayoutPrice(units, h, gp, nPayout));   // the window isn't full of counting samples yet
    }
    // Up to here the window still held the untrusted sample at 22; at 22 + 144 it holds 144 counting samples.
    const int hFull = 22 + (int)gp.nPoolViewBlocks;
    TokenPoolsEndBlock(units, hFull, gp);
    BOOST_REQUIRE(PayoutPrice(units, hFull, gp, nPayout));
    BOOST_CHECK_EQUAL(nPayout, nView);

    // An oracle far above the pool is capped at the pool view + 5% (D-2026-11-01-6 item 4).
    COracleObs obs;
    obs.nStream = ORACLE_STREAM_GOLD_ECX;
    obs.nValue = nView * 2;
    const ReporterCounts fnAll = [](uint32_t) { return true; };
    for (uint32_t id = 1; id <= 3; id++)
        PriceFeedRecord(units, id, {obs}, hFull);
    PriceFeedEndBlock(units, hFull, gp, 3, fnAll);
    BOOST_REQUIRE(PayoutPrice(units, hFull, gp, nPayout));
    BOOST_CHECK_EQUAL(nPayout, nView * 10500 / 10000);
}

// 5b: a claim's gold share - pro rata to what is left, capped at par, zero shares dropped, order-independent.
BOOST_AUTO_TEST_CASE(gold_claim_shares)
{
    uint256 a, b;
    a.SetHex("01");
    b.SetHex("02");
    std::map<uint256, uint64_t> pot{{a, 600}, {b, 300}};
    // 1,000 units outstanding, a claim of 100: 60 of A, 30 of B.
    std::vector<std::pair<uint256, uint64_t>> v = GoldClaimShares(100, pot, 1000);
    BOOST_CHECK_EQUAL(v.size(), 2U);
    BOOST_CHECK(v[0].first == a && v[0].second == 60);
    BOOST_CHECK(v[1].first == b && v[1].second == 30);
    // A pot richer than the notes: capped at par in all, every token scaled by the same factor (review round 1, G1e).
    std::map<uint256, uint64_t> rich{{a, 5000}, {b, 5000}};
    v = GoldClaimShares(100, rich, 1000);
    BOOST_CHECK_EQUAL(v.size(), 2U);
    BOOST_CHECK(v[0].first == a && v[0].second == 50 && v[1].first == b && v[1].second == 50);
    // Rounding down to zero drops the token; nothing outstanding pays nothing.
    std::map<uint256, uint64_t> thin{{a, 9}, {b, 600}};
    v = GoldClaimShares(100, thin, 1000);
    BOOST_CHECK_EQUAL(v.size(), 1U);
    BOOST_CHECK(v[0].first == b && v[0].second == 60);
    BOOST_CHECK(GoldClaimShares(100, pot, 0).empty());
    // Two claims in sequence against the shrinking pot take what one claim of their sum would, give or take rounding.
    std::map<uint256, uint64_t> p2 = pot;
    uint64_t nOut = 1000, nA = 0;
    for (int k = 0; k < 10; k++) {
        for (const auto& g : GoldClaimShares(100, p2, nOut)) {
            p2[g.first] -= g.second;
            if (g.first == a) nA += g.second;
        }
        nOut -= 100;
    }
    BOOST_CHECK(nA >= 590 && nA <= 600);
    // The moves: drawn from the entries in order, sorted for the shape check.
    std::vector<CVaultEntry> vEntry{{VAULT_TILL, 0, a, 20}, {VAULT_CAPITAL, 1, a, 50}, {VAULT_CAPITAL, 0, b, 40}};
    std::map<uint256, uint64_t> due{{a, 60}, {b, 30}};
    std::vector<CVaultMove> m = GoldClaimMoves(7, vEntry, due);
    BOOST_CHECK_EQUAL(m.size(), 3U);
    int64_t nA2 = 0, nB2 = 0;
    for (const CVaultMove& x : m) {
        BOOST_CHECK(x.nHouseID == 7 && x.nDelta < 0);
        (x.tokenID == a ? nA2 : nB2) += -x.nDelta;
    }
    BOOST_CHECK_EQUAL(nA2, 60);
    BOOST_CHECK_EQUAL(nB2, 30);
    for (size_t k = 1; k < m.size(); k++)
        BOOST_CHECK(std::make_tuple(m[k - 1].nHouseID, m[k - 1].nKind, m[k - 1].nPartner, m[k - 1].tokenID) <
                    std::make_tuple(m[k].nHouseID, m[k].nKind, m[k].nPartner, m[k].tokenID));
}

// R3-12: a capital draw split pro rata over the partners (floors, remainder one unit each in partner order), and the
// queued-demand index read as "units queued before this height".
BOOST_AUTO_TEST_CASE(capital_draw_split_and_queue_index)
{
    std::vector<std::pair<uint32_t, uint64_t>> v{{0, 600}, {1, 300}, {2, 100}};
    std::map<uint32_t, uint64_t> m = CapitalDrawSplit(100, v);
    BOOST_CHECK(m == (std::map<uint32_t, uint64_t>{{0, 60}, {1, 30}, {2, 10}}));
    m = CapitalDrawSplit(7, v);   // floors 4, 2, 0 = 6; the remainder goes to partner 0
    BOOST_CHECK(m == (std::map<uint32_t, uint64_t>{{0, 5}, {1, 2}}));
    uint64_t nSum = 0;
    for (const auto& p : CapitalDrawSplit(999, v)) nSum += p.second;
    BOOST_CHECK_EQUAL(nSum, 999U);
    BOOST_CHECK(CapitalDrawSplit(1001, v).empty());   // more than the capital holds
    BOOST_CHECK(CapitalDrawSplit(0, v).empty());

    // The index: 50 units queued at height 10 and 20 at height 30, for house 4; house 5's don't count.
    CUnitsView units(nullptr);
    units.Put(QueueKey(4, 10), (uint64_t)50);
    units.Put(QueueKey(4, 30), (uint64_t)20);
    units.Put(QueueKey(5, 1), (uint64_t)99);
    UnitsCheckScope scope(&units);
    BOOST_CHECK_EQUAL(HouseQueueUnitsBeforeForChecks(4, 10), 0U);   // the oldest: nothing before it
    BOOST_CHECK_EQUAL(HouseQueueUnitsBeforeForChecks(4, 11), 50U);
    BOOST_CHECK_EQUAL(HouseQueueUnitsBeforeForChecks(4, 31), 70U);
    BOOST_CHECK_EQUAL(HouseQueueUnitsBeforeForChecks(6, 1000), 0U);
}

// 5b: an issuer's freeze on a house's vault gold - stays in the vault (payouts take only the unfrozen part), counts zero
// after a 30-day grace that restarts only after 180 clean days, and rides frozen into the fund at CLOSE.
BOOST_AUTO_TEST_CASE(issued_vault_freeze)
{
    CUnitsView units(nullptr);
    CKey issuer, freezer;
    issuer.MakeNewKey(true);
    freezer.MakeNewKey(true);
    const uint256 token = CreateToken(units, issuer, &freezer);
    {
        CIssuedToken rec;   // trusted (as if bonded and backed at the last block's end), so its vault gold is valued
        BOOST_REQUIRE(units.Get(IssuedTokenKey(token), rec));
        rec.fTrusted = 1;
        units.Put(IssuedTokenKey(token), rec);
    }
    units.Put(VaultKey(7, VAULT_CAPITAL, 0, token), (uint64_t)1000);
    units.Put(VaultKey(7, VAULT_TILL, 0, token), (uint64_t)200);
    units.Put(VaultTotalKey(token), (uint64_t)1200);
    CCoinsView base;
    CCoinsViewCache view(&base);
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(0);

    auto freeze = [&](uint8_t nOp, uint64_t nFrozen, uint32_t nHouse, int nHeight) {
        IssuedFreeze fz;
        fz.tokenID = token;
        CVaultFreezeTarget t;
        t.nHouseID = nHouse;
        t.nFrozen = nFrozen;
        fz.vVault = {t};
        CMutableTransaction f = TokenTx(nOp, 1, 1);
        f.vchIssuedPayload = Enc(fz);
        BOOST_REQUIRE(freezer.Sign(IssuedSigHash(CTransaction(f)), fz.vchFreezeSig));
        f.vchIssuedPayload = Enc(fz);
        const std::string strShape = ShapeReason(f);
        return strShape.empty() ? ConnectReason(f, view, units, nHeight) : strShape;
    };
    BOOST_CHECK_EQUAL(freeze(ISSUED_OP_FREEZE, 1300, 7, 100), "bad-issued-freeze-units");   // more than the house holds
    BOOST_CHECK_EQUAL(freeze(ISSUED_OP_FREEZE, 500, 7, 100), "");
    CVaultFrozen f;
    BOOST_REQUIRE(units.Get(VaultFrozenKey(7, token), f));
    BOOST_CHECK(f.nFrozen == 500 && f.nGraceStart == 100 && f.nClearSince == 0);
    BOOST_CHECK_EQUAL(freeze(ISSUED_OP_FREEZE, 500, 7, 101), "bad-issued-freeze-direction");

    // Counting: inside the grace nothing counts zero; after it, the 500.
    {
        UnitsCheckScope scope(&units);
        BOOST_CHECK(HouseVaultFrozenZeroForChecks(7, 100 + (int)gp.nFreezeGraceBlocks - 1).empty());
        BOOST_CHECK_EQUAL(HouseVaultFrozenZeroForChecks(7, 100 + (int)gp.nFreezeGraceBlocks)[token], 500U);
        BOOST_CHECK_EQUAL(HouseVaultFreeTotalsForChecks(7, 200)[token], 700U);
    }

    // A payout or move takes at most the unfrozen 700.
    auto till = [&](int64_t nDelta) {
        CMutableTransaction m;
        m.nVersion = TRANSACTION_HOUSE_VERSION;
        m.nHouseOp = HOUSE_OP_TILL;
        m.vin.resize(1);
        m.vin[0].prevout = COutPoint(uint256S("71"), 0);
        m.vout.resize(1);
        m.vout[0] = CTxOut(ISSUED_COIN_VALUE, CScript() << OP_TRUE);
        CVaultMove mv;
        mv.nHouseID = 7;
        mv.nKind = VAULT_CAPITAL;
        mv.tokenID = token;
        mv.nDelta = nDelta;
        m.vVaultMove = {mv};
        m.vIssuedOut = {Out(0, token, (uint64_t)(-nDelta))};
        return ConnectReason(m, view, units, 200);
    };
    BOOST_CHECK_EQUAL(till(-701), "bad-vault-move-frozen");

    // UNFREEZE to zero starts the clean clock; a freeze soon after keeps the old grace (counts zero at once)...
    BOOST_CHECK_EQUAL(freeze(ISSUED_OP_UNFREEZE, 0, 7, 5000), "");
    BOOST_REQUIRE(units.Get(VaultFrozenKey(7, token), f));
    BOOST_CHECK(f.nFrozen == 0 && f.nClearSince == 5000);
    BOOST_CHECK_EQUAL(freeze(ISSUED_OP_FREEZE, 100, 7, 5100), "");
    BOOST_REQUIRE(units.Get(VaultFrozenKey(7, token), f));
    BOOST_CHECK(f.nGraceStart == 100 && f.nClearSince == 0);
    // ...and only after 180 clean days does a new freeze get a new grace.
    BOOST_CHECK_EQUAL(freeze(ISSUED_OP_UNFREEZE, 0, 7, 6000), "");
    const int nLater = 6000 + (int)gp.nFreezeClearBlocks;
    BOOST_CHECK_EQUAL(freeze(ISSUED_OP_FREEZE, 100, 7, nLater), "");
    BOOST_REQUIRE(units.Get(VaultFrozenKey(7, token), f));
    BOOST_CHECK_EQUAL(f.nGraceStart, (uint32_t)nLater);

    // CLOSE drains every entry; the frozen 100 ride into the fund still frozen, and the record goes to zero.
    CMutableTransaction c;
    c.nVersion = TRANSACTION_HOUSE_VERSION;
    c.nHouseOp = HOUSE_OP_CLOSE;
    c.vin.resize(1);
    c.vin[0].prevout = COutPoint(uint256S("72"), 0);
    c.vout.resize(1);
    c.vout[0] = CTxOut(ISSUED_COIN_VALUE, MutualFundScript());
    CVaultMove a, b;
    a.nHouseID = b.nHouseID = 7;
    a.nKind = VAULT_CAPITAL;
    b.nKind = VAULT_TILL;
    a.tokenID = b.tokenID = token;
    a.nDelta = -1000;
    b.nDelta = -200;
    c.vVaultMove = {a, b};
    c.vIssuedOut = {Out(0, token, 1200, 0)};
    BOOST_CHECK_EQUAL(ConnectReason(c, view, units, nLater + 1), "bad-issued-frozen-flow");   // the freeze shed
    c.vIssuedOut = {Out(0, token, 1200, 100)};
    BOOST_CHECK_EQUAL(ConnectReason(c, view, units, nLater + 1), "");
    BOOST_REQUIRE(units.Get(VaultFrozenKey(7, token), f));
    BOOST_CHECK(f.nFrozen == 0 && f.nClearSince == (uint32_t)(nLater + 1));
}

// The exit (D-2026-11-01-5, dormant): sigma bands from 730 daily log changes in integer fixed point, and the steps.
BOOST_AUTO_TEST_CASE(exit_sigma_and_steps)
{
    // log2 in Q32: exact at powers of two, close elsewhere.
    BOOST_CHECK_EQUAL(Log2Q32(1), 0);
    BOOST_CHECK_EQUAL(Log2Q32(1024), (int64_t)10 << 32);
    BOOST_CHECK(std::llabs(Log2Q32(3) - (int64_t)(1.5849625007 * 4294967296.0)) < 8);

    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(0);
    auto fill = [&](CUnitsView& units, double dUp) {   // alternate the price up and down by dUp each day
        double p = 100000;
        for (uint32_t d = 0; d <= gp.nExitDays; d++) {
            units.Put(UnitsKey(UNITS_ORACLE_DAY).U32(d), (uint64_t)p);
            p = (d % 2 == 0) ? p * (1 + dUp) : p / (1 + dUp);
        }
    };
    int nBand = -1;
    {
        CUnitsView units(nullptr);
        BOOST_CHECK(!PriceFeedExitBand(units, gp.nExitDays, gp, nBand));   // no history: dormant
        fill(units, 0.0);
        BOOST_REQUIRE(PriceFeedExitBand(units, gp.nExitDays, gp, nBand));
        BOOST_CHECK_EQUAL(nBand, 0);   // flat: calm
        BOOST_CHECK(!PriceFeedExitBand(units, gp.nExitDays + 1, gp, nBand));   // a missing day: not measurable
    }
    {
        CUnitsView units(nullptr);
        fill(units, 0.0265);   // daily |log change| ~ 0.02615: sigma ~ 50% a year
        BOOST_REQUIRE(PriceFeedExitBand(units, gp.nExitDays, gp, nBand));
        BOOST_CHECK_EQUAL(nBand, 1);
    }
    {
        CUnitsView units(nullptr);
        fill(units, 0.05);     // sigma ~ 93%
        BOOST_REQUIRE(PriceFeedExitBand(units, gp.nExitDays, gp, nBand));
        BOOST_CHECK_EQUAL(nBand, 2);
    }

    // The steps: measurable from the first day boundary; one step per period while calm, to 4; then falling when stormy.
    CUnitsView units(nullptr);
    fill(units, 0.0);
    const int h0 = (int)(gp.nExitDays * 144 + 143);   // the last block of day nExitDays
    BOOST_CHECK_EQUAL(PriceFeedExitStep(units), 0);
    PriceFeedExitEndBlock(units, h0, gp);
    BOOST_CHECK_EQUAL(PriceFeedExitStep(units), 0);   // measurable now; the first step is a period away
    int h = h0;
    for (int k = 1; k <= 5; k++) {
        h += (int)gp.nExitStepBlocks;
        h += 143 - (h % 144);   // a day's last block
        for (uint32_t d = h0 / 144 + 1; d <= (uint32_t)(h / 144); d++)
            units.Put(UnitsKey(UNITS_ORACLE_DAY).U32(d), (uint64_t)100000);
        PriceFeedExitEndBlock(units, h, gp);
        BOOST_CHECK_EQUAL(PriceFeedExitStep(units), std::min(k, 4));
    }
}

// The no-price path (D-2026-11-01-6 item 3): runs of blocks with no payout price, and the count an overdue clock skips.
BOOST_AUTO_TEST_CASE(no_price_runs)
{
    CUnitsView units(nullptr);
    for (int h = 1; h <= 10; h++)
        PriceFeedNoPriceEndBlock(units, h, false);   // the chain's start: no price yet
    for (int h = 11; h <= 20; h++)
        PriceFeedNoPriceEndBlock(units, h, true);
    for (int h = 21; h <= 25; h++)
        PriceFeedNoPriceEndBlock(units, h, false);   // a stale spell
    PriceFeedNoPriceEndBlock(units, 26, true);
    PriceFeedNoPriceEndBlock(units, 30, false);      // one more, alone
    uint32_t nEnd = 0;
    BOOST_REQUIRE(units.Get(UnitsKey(UNITS_NOPRICE).U32(1), nEnd));
    BOOST_CHECK_EQUAL(nEnd, 10U);
    BOOST_REQUIRE(units.Get(UnitsKey(UNITS_NOPRICE).U32(21), nEnd));
    BOOST_CHECK_EQUAL(nEnd, 25U);
    BOOST_CHECK_EQUAL(PriceFeedUnpricedBlocks(units, 0, 30), 16U);    // 1-10, 21-25, 30
    BOOST_CHECK_EQUAL(PriceFeedUnpricedBlocks(units, 10, 20), 0U);    // (10, 20] all priced
    BOOST_CHECK_EQUAL(PriceFeedUnpricedBlocks(units, 22, 29), 3U);    // 23, 24, 25
    BOOST_CHECK_EQUAL(PriceFeedUnpricedBlocks(units, 25, 30), 1U);    // 30
    BOOST_CHECK_EQUAL(PriceFeedUnpricedBlocks(units, 30, 30), 0U);
}

BOOST_AUTO_TEST_CASE(issued_create_needs_a_price)
{
    // D-2026-11-04-1 (3b): with the burn on and no payout price, a CREATE is refused.
    UpdateCreateFeeForTest(Consensus::GramParams().nCreateFeeMg);
    CKey issuer;
    issuer.MakeNewKey(true);
    CUnitsView units(nullptr);
    CMutableTransaction mtx = TokenTx(ISSUED_OP_CREATE, 1, 1);
    IssuedCreate c = MakeCreate(issuer, nullptr);
    mtx.vchIssuedPayload = Enc(c);
    BOOST_REQUIRE(issuer.Sign(IssuedSigHash(CTransaction(mtx)), c.vchIssuerSig));
    mtx.vchIssuedPayload = Enc(c);
    Inputs in(mtx, {});
    BOOST_CHECK_EQUAL(ConnectReason(mtx, in.view, units), "bad-issued-create-no-price");
    UpdateCreateFeeForTest(0);
    BOOST_CHECK_EQUAL(ConnectReason(mtx, in.view, units), "");
}

BOOST_AUTO_TEST_CASE(issued_burn_overdue_rule)
{
    // D-2026-11-04-1 (3d, R2-ops-7; review 11-04): burns older than 1,008 blocks that the reports don't show paid, in
    // total units, beyond max(10 g, 0.5% of supply), make the token untrusted. A small burn the issuer can't pay
    // doesn't.
    Consensus::GramParams gp;   // nBurnPayBlocks 1008, nBurnUnpaidMinMg 10000, nBurnUnpaidBps 50
    CUnitsView units(nullptr);
    CIssuedToken token;
    token.tokenID = uint256S("0x77");
    token.nSupply = 1000000;   // 0.5% = 5,000 mg: the 10 g floor applies
    BOOST_CHECK(!IssuedBurnOverdue(units, token, 0, 5000, gp));   // nothing queued
    const auto fnBurn = [&](uint64_t n, int h) {
        CIssuedBurn b, prev;
        b.nUnits = n;
        b.nHeight = h;
        b.nCumUnits = n + (token.nBurnSeq && units.Get(IssuedBurnKey(token.tokenID, token.nBurnSeq - 1), prev) ? prev.nCumUnits : 0);
        units.Put(IssuedBurnKey(token.tokenID, token.nBurnSeq++), b);
    };
    fnBurn(1000, 100);     // an unpayable gram (the sender's loss)
    BOOST_CHECK(!IssuedBurnOverdue(units, token, 0, 5000, gp));   // 1,000 mg unpaid: below the 10 g threshold
    fnBurn(20000, 900);    // 20 g
    BOOST_CHECK(!IssuedBurnOverdue(units, token, 0, 1908, gp));   // that burn is 1,008 blocks old: still in time
    BOOST_CHECK(IssuedBurnOverdue(units, token, 0, 1909, gp));    // 1,009: 21,000 mg overdue and unpaid
    BOOST_CHECK(!IssuedBurnOverdue(units, token, 20000, 1909, gp)); // 20 g reported paid: 1,000 unpaid, below
    fnBurn(50000, 2000);   // a new burn, not due yet
    BOOST_CHECK(!IssuedBurnOverdue(units, token, 20000, 2500, gp));
    BOOST_CHECK(IssuedBurnOverdue(units, token, 20000, 3009, gp));  // now due: 51,000 unpaid
    token.nSupply = 20000000;  // 0.5% = 100,000 mg: above what is unpaid
    BOOST_CHECK(!IssuedBurnOverdue(units, token, 20000, 3009, gp));
}

BOOST_AUTO_TEST_SUITE_END()
