// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BitAssets v0.2.18 (D-2026-10-03-1): the shared colouring rule, the genesis
// shape and metadata rule, and the signature binding of the metadata. Each
// case names the layer-B review finding it pins (docs-local/reviews/
// 2026-10-02-layer-b/assets.md).

#include <asset.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/test_bitcoin.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(asset_tests, BasicTestingSetup)

static CScript P2PKHish(unsigned char c)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, c) << OP_EQUALVERIFY << OP_CHECKSIG;
}

static Coin Plain(CAmount v)
{
    return Coin(CTxOut(v, P2PKHish(1)), 10, false, false, false, uint256());
}

static Coin Units(CAmount v, const uint256& id)
{
    return Coin(CTxOut(v, P2PKHish(2)), 10, false, true, false, id);
}

static Coin Control(const uint256& id)
{
    return Coin(CTxOut(ASSET_CONTROL_VALUE, P2PKHish(3)), 10, false, false, true, id);
}

static CMutableTransaction Spend(size_t nIn, const std::vector<CAmount>& vOut, int nVersion = 2)
{
    CMutableTransaction mtx;
    mtx.nVersion = nVersion;
    for (size_t i = 0; i < nIn; i++)
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("aa"), i)));
    for (CAmount v : vOut)
        mtx.vout.push_back(CTxOut(v, P2PKHish(9)));
    return mtx;
}

static bool Tags(const CMutableTransaction& mtx, const std::vector<Coin>& vCoin, AssetTags& tags, std::string& reason)
{
    std::vector<const Coin*> v;
    for (const Coin& c : vCoin) v.push_back(&c);
    return ComputeAssetTags(CTransaction(mtx), v, tags, reason);
}

static CMutableTransaction Genesis(CAmount nSupply = 1000000)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BITASSET_CREATE_VERSION;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("bb"), 0)));
    mtx.vout.push_back(CTxOut(ASSET_CONTROL_VALUE, P2PKHish(3)));
    mtx.vout.push_back(CTxOut(nSupply, P2PKHish(4)));
    mtx.vout.push_back(CTxOut(5000, P2PKHish(5)));    // change
    mtx.ticker = "GOLD";
    mtx.headline = "1 unit = 1 mg";
    mtx.nDecimals = 3;
    return mtx;
}

BOOST_AUTO_TEST_CASE(asset_metadata_limits)
{
    // Q13 / B6: ticker 1-12 of A-Z 0-9, nothing else.
    BOOST_CHECK(IsValidAssetTicker("A"));
    BOOST_CHECK(IsValidAssetTicker("GOLD2026XAU1"));
    BOOST_CHECK(!IsValidAssetTicker(""));
    BOOST_CHECK(!IsValidAssetTicker("GOLD2026XAU12"));         // 13
    BOOST_CHECK(!IsValidAssetTicker("gold"));
    BOOST_CHECK(!IsValidAssetTicker("GO LD"));
    BOOST_CHECK(!IsValidAssetTicker("G\xD0\x9E" "LD"));          // Cyrillic O look-alike

    // Headline: <= 64 bytes of strict UTF-8, no control / invisible code points.
    BOOST_CHECK(IsValidAssetHeadline(""));
    BOOST_CHECK(IsValidAssetHeadline("Gold held by X, audited monthly"));
    BOOST_CHECK(IsValidAssetHeadline("\xC3\xA9tain \xE2\x82\xAC"));          // é, €
    BOOST_CHECK(IsValidAssetHeadline(std::string(64, 'a')));
    BOOST_CHECK(!IsValidAssetHeadline(std::string(65, 'a')));
    BOOST_CHECK(!IsValidAssetHeadline("a\nb"));
    BOOST_CHECK(!IsValidAssetHeadline(std::string("a\0b", 3)));
    BOOST_CHECK(!IsValidAssetHeadline("a\x7f"));
    BOOST_CHECK(!IsValidAssetHeadline("a\xE2\x80\x8B" "b"));                  // U+200B zero width space
    BOOST_CHECK(!IsValidAssetHeadline("a\xE2\x80\xAE" "b"));                  // U+202E RLO
    BOOST_CHECK(!IsValidAssetHeadline("\xEF\xBB\xBF" "a"));                   // U+FEFF BOM
    BOOST_CHECK(!IsValidAssetHeadline("\xC2\x85"));                           // C1 NEL
    BOOST_CHECK(!IsValidAssetHeadline("\xC0\xAF"));                           // overlong '/'
    BOOST_CHECK(!IsValidAssetHeadline("\xED\xA0\x80"));                       // surrogate
    BOOST_CHECK(!IsValidAssetHeadline("\xF4\x90\x80\x80"));                   // > U+10FFFF
    BOOST_CHECK(!IsValidAssetHeadline("\xE2\x82"));                           // truncated
    BOOST_CHECK(!IsValidAssetHeadline("\xF3\xA0\x80\x81"));                   // U+E0001 tag
}

BOOST_AUTO_TEST_CASE(asset_genesis_shape)
{
    std::string r;
    BOOST_CHECK(CheckAssetGenesisShape(CTransaction(Genesis()), r));

    CMutableTransaction m = Genesis();
    m.vout.resize(1);
    BOOST_CHECK(!CheckAssetGenesisShape(CTransaction(m), r) && r == "bad-asset-genesis-vout-count");

    m = Genesis();
    m.vout[0].scriptPubKey = CScript() << OP_RETURN;       // control must be spendable (B3)
    BOOST_CHECK(!CheckAssetGenesisShape(CTransaction(m), r) && r == "bad-asset-genesis-control-dest");

    m = Genesis();
    m.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(!CheckAssetGenesisShape(CTransaction(m), r) && r == "bad-asset-genesis-supply-dest");

    m = Genesis(0);
    BOOST_CHECK(!CheckAssetGenesisShape(CTransaction(m), r) && r == "bad-asset-genesis-supply");

    m = Genesis();
    m.ticker = "gold";
    BOOST_CHECK(!CheckAssetGenesisShape(CTransaction(m), r) && r == "bad-asset-genesis-ticker");

    m = Genesis();
    m.headline = "x\ty";
    BOOST_CHECK(!CheckAssetGenesisShape(CTransaction(m), r) && r == "bad-asset-genesis-headline");

    m = Genesis();
    m.nDecimals = 9;
    BOOST_CHECK(!CheckAssetGenesisShape(CTransaction(m), r) && r == "bad-asset-genesis-decimals");
}

BOOST_AUTO_TEST_CASE(asset_genesis_tags)
{
    AssetTags t;
    std::string r;
    const CMutableTransaction g = Genesis();
    BOOST_REQUIRE(Tags(g, {Plain(2000000)}, t, r));
    BOOST_CHECK(t.assetID == CTransaction(g).GetHash());       // identity = txid
    BOOST_CHECK_EQUAL(t.Get(0), ASSET_OUT_CONTROL);
    BOOST_CHECK_EQUAL(t.Get(1), ASSET_OUT_UNITS);
    BOOST_CHECK_EQUAL(t.Get(2), ASSET_OUT_PLAIN);

    // B2: a genesis spends no coloured coin - units, control, or a bare id.
    const uint256 idA = uint256S("a1");
    BOOST_CHECK(!Tags(g, {Units(10, idA)}, t, r) && r == "bad-asset-genesis-coloured-input");
    CMutableTransaction g2 = g;
    g2.vin.push_back(CTxIn(COutPoint(uint256S("bc"), 1)));
    BOOST_CHECK(!Tags(g2, {Plain(5), Control(idA)}, t, r) && r == "bad-asset-genesis-coloured-input");
}

BOOST_AUTO_TEST_CASE(asset_mixed_inputs_A1)
{
    // A1 (CRITICAL): [junk A, plain, real B] used to pass because the plain
    // input reset the remembered id. Both orders must fail.
    const uint256 idA = uint256S("a1"), idB = uint256S("b2");
    AssetTags t;
    std::string r;
    CMutableTransaction m = Spend(3, {1000001, 10000});
    BOOST_CHECK(!Tags(m, {Units(1000000, idA), Plain(20000), Units(1, idB)}, t, r) && r == "bad-asset-inputs-mixed");
    BOOST_CHECK(!Tags(m, {Units(1, idB), Plain(20000), Units(1000000, idA)}, t, r) && r == "bad-asset-inputs-mixed");
    // Control of A next to units of B.
    CMutableTransaction m2 = Spend(2, {ASSET_CONTROL_VALUE, 5});
    BOOST_CHECK(!Tags(m2, {Control(idA), Units(5, idB)}, t, r) && r == "bad-asset-inputs-mixed");
    // A coloured coin with a null id (A5).
    BOOST_CHECK(!Tags(Spend(1, {5}), {Units(5, uint256())}, t, r) && r == "bad-asset-input-tag");
}

BOOST_AUTO_TEST_CASE(asset_transfer_exact_sum_B1)
{
    const uint256 id = uint256S("c3");
    AssetTags t;
    std::string r;
    // 700 + 300 units in -> 600 to them, 400 back, then plain change.
    CMutableTransaction m = Spend(3, {600, 400, 9000});
    BOOST_REQUIRE(Tags(m, {Units(700, id), Units(300, id), Plain(10000)}, t, r));
    BOOST_CHECK(t.assetID == id);
    BOOST_CHECK_EQUAL(t.Get(0), ASSET_OUT_UNITS);
    BOOST_CHECK_EQUAL(t.Get(1), ASSET_OUT_UNITS);
    BOOST_CHECK_EQUAL(t.Get(2), ASSET_OUT_PLAIN);

    // Over-colouring is impossible: the leading outputs must hit the input sum exactly.
    BOOST_CHECK(!Tags(Spend(2, {600, 9500}), {Units(1000, id), Plain(10000)}, t, r) && r == "bad-asset-units-not-conserved");
    BOOST_CHECK(!Tags(Spend(1, {600}), {Units(1000, id)}, t, r) && r == "bad-asset-units-not-conserved");
    BOOST_CHECK(!Tags(Spend(2, {0, 1000}), {Units(1000, id), Plain(10)}, t, r) && r == "bad-asset-units-zero-output");

    // Burning: units to an OP_RETURN output, exact.
    CMutableTransaction b = Spend(2, {1000, 9000});
    b.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(Tags(b, {Units(1000, id), Plain(10000)}, t, r) && t.Get(0) == ASSET_OUT_UNITS);
}

BOOST_AUTO_TEST_CASE(asset_control_B3)
{
    const uint256 id = uint256S("d4");
    AssetTags t;
    std::string r;
    // Control alone: passes to vout[0], no unit outputs.
    BOOST_REQUIRE(Tags(Spend(2, {ASSET_CONTROL_VALUE, 5000}), {Control(id), Plain(10000)}, t, r));
    BOOST_CHECK(t.assetID == id && t.Get(0) == ASSET_OUT_CONTROL && t.Get(1) == ASSET_OUT_PLAIN);
    // Control + units of the same asset: control at vout[0], units right after.
    BOOST_REQUIRE(Tags(Spend(3, {ASSET_CONTROL_VALUE, 50, 9000}), {Control(id), Units(50, id), Plain(10000)}, t, r));
    BOOST_CHECK(t.Get(0) == ASSET_OUT_CONTROL && t.Get(1) == ASSET_OUT_UNITS && t.Get(2) == ASSET_OUT_PLAIN);
    // Two control coins in one tx.
    BOOST_CHECK(!Tags(Spend(2, {ASSET_CONTROL_VALUE}), {Control(id), Control(id)}, t, r) && r == "bad-asset-control-multiple");
    // The control may not be burned.
    CMutableTransaction m = Spend(2, {ASSET_CONTROL_VALUE, 5000});
    m.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(!Tags(m, {Control(id), Plain(10000)}, t, r) && r == "bad-asset-control-dest");
}

BOOST_AUTO_TEST_CASE(asset_coloured_inputs_only_in_transfers_A5)
{
    const uint256 id = uint256S("e5");
    AssetTags t;
    std::string r;
    for (int nVersion : {TRANSACTION_BILL_VERSION, TRANSACTION_HOUSE_VERSION, TRANSACTION_NOTE_VERSION,
                         TRANSACTION_DEPOSIT_VERSION, TRANSACTION_POOL_VERSION, TRANSACTION_SETTLE_VERSION,
                         TRANSACTION_ORACLE_VERSION}) {
        BOOST_CHECK(!Tags(Spend(1, {5}, nVersion), {Units(5, id)}, t, r) && r == "bad-asset-input-op");
        BOOST_CHECK(!Tags(Spend(1, {5}, nVersion), {Control(id)}, t, r) && r == "bad-asset-input-op");
    }
    // Not out through a withdrawal (B1): a sidechain-object output.
    CMutableTransaction m = Spend(2, {5, 1000});
    const std::vector<unsigned char> vObj{(unsigned char)OP_RETURN, 0xAC, 0xDC, 0xF6, 0x6F, 0x00};
    m.vout.push_back(CTxOut(0, CScript(vObj.begin(), vObj.end())));
    std::vector<unsigned char> vch;
    BOOST_REQUIRE(m.vout.back().scriptPubKey.IsSidechainObj(vch));
    BOOST_CHECK(!Tags(m, {Units(5, id), Plain(2000)}, t, r) && r == "bad-asset-input-withdrawal");
    // A plain tx spending plain coins moves no asset.
    BOOST_CHECK(Tags(Spend(1, {5}), {Plain(10)}, t, r) && t.IsNull());
}

BOOST_AUTO_TEST_CASE(asset_addcoins_applies_tags)
{
    CCoinsView base;
    CCoinsViewCache cache(&base);
    const CMutableTransaction g = Genesis();
    AssetTags t;
    std::string r;
    BOOST_REQUIRE(Tags(g, {Plain(2000000)}, t, r));
    const CTransaction tx(g);
    AddCoins(cache, tx, 100, t);
    const Coin& c0 = cache.AccessCoin(COutPoint(tx.GetHash(), 0));
    const Coin& c1 = cache.AccessCoin(COutPoint(tx.GetHash(), 1));
    const Coin& c2 = cache.AccessCoin(COutPoint(tx.GetHash(), 2));
    BOOST_CHECK(c0.fBitAssetControl && !c0.fBitAsset && c0.assetID == tx.GetHash());
    BOOST_CHECK(c1.fBitAsset && !c1.fBitAssetControl && c1.assetID == tx.GetHash());
    BOOST_CHECK(!c2.IsAssetColoured());
}

BOOST_AUTO_TEST_CASE(asset_metadata_signed_A2)
{
    // A2: the metadata is in the txid (the identity), so every signature must
    // bind it. Changing any field changes both sighash forms.
    const CScript code = P2PKHish(7);
    const CMutableTransaction g = Genesis();
    auto Hashes = [&](const CMutableTransaction& m) {
        return std::make_pair(SignatureHash(code, m, 0, SIGHASH_ALL, 1000, SIGVERSION_BASE),
                              SignatureHash(code, m, 0, SIGHASH_ALL, 1000, SIGVERSION_WITNESS_V0));
    };
    const auto h0 = Hashes(g);
    CMutableTransaction m = g; m.ticker = "GOLE";
    BOOST_CHECK(Hashes(m).first != h0.first && Hashes(m).second != h0.second);
    m = g; m.headline = "1 unit = 2 mg";
    BOOST_CHECK(Hashes(m).first != h0.first && Hashes(m).second != h0.second);
    m = g; m.payload = uint256S("01");
    BOOST_CHECK(Hashes(m).first != h0.first && Hashes(m).second != h0.second);
    m = g; m.nDecimals = 2;
    BOOST_CHECK(Hashes(m).first != h0.first && Hashes(m).second != h0.second);
    // Even SIGHASH_NONE|ANYONECANPAY binds it.
    const int nNone = SIGHASH_NONE | SIGHASH_ANYONECANPAY;
    m = g; m.headline = "other";
    BOOST_CHECK(SignatureHash(code, m, 0, nNone, 1000, SIGVERSION_BASE) != SignatureHash(code, g, 0, nNone, 1000, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_SUITE_END()
