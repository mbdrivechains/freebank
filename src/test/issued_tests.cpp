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

#include <coins.h>
#include <consensus/validation.h>
#include <creditbind.h>
#include <key.h>
#include <script/standard.h>
#include <streams.h>
#include <arith_uint256.h>
#include <hash.h>
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
    c.nKind = ISSUED_KIND_USD_CENTS;   // Gold B: no gold kind
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
    ~IssuedTestingSetup() { UpdateCreateFeeForTest(Consensus::GramParams().nCreateFeeSats); }
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

BOOST_AUTO_TEST_CASE(issued_token_pool_create_and_swap)
{
    // Gold B: tokens are dollar tokens now, whose pools open at nDollarPoolTime; open them for the test.
    UpdateLaterRuleTimes(Params().GetConsensus().nNotePoolTime, 0);
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
    custodyToken.SetCustody();
    Coin custodySats(CTxOut(66000000, TokenPoolScript(token)), 20, false, false, false, uint256());
    custodySats.SetCustody();
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

    UpdateLaterRuleTimes(Params().GetConsensus().nNotePoolTime, Consensus::LATER_RULE_NEVER);
}

BOOST_AUTO_TEST_CASE(issued_create_burns_the_fixed_fee)
{
    // D-2026-11-04-1 (3b), Gold B (hole 4): with the burn on, a CREATE that burns less than nCreateFeeSats is refused; no
    // price is needed.
    UpdateCreateFeeForTest(Consensus::GramParams().nCreateFeeSats);
    CKey issuer;
    issuer.MakeNewKey(true);
    CUnitsView units(nullptr);
    CMutableTransaction mtx = TokenTx(ISSUED_OP_CREATE, 1, 1);
    IssuedCreate c = MakeCreate(issuer, nullptr);
    mtx.vchIssuedPayload = Enc(c);
    BOOST_REQUIRE(issuer.Sign(IssuedSigHash(CTransaction(mtx)), c.vchIssuerSig));
    mtx.vchIssuedPayload = Enc(c);
    Inputs in(mtx, {});
    BOOST_CHECK_EQUAL(ConnectReason(mtx, in.view, units), "bad-issued-create-fee");
    UpdateCreateFeeForTest(0);
    BOOST_CHECK_EQUAL(ConnectReason(mtx, in.view, units), "");
}

BOOST_AUTO_TEST_SUITE_END()
