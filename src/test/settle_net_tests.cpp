// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// v0.2.22 netting (gateway/docs/freebank/NETTING_DESIGN.md, signed off 2026-10-09): settle op 4 NET. Codec and the
// slot reader; nets and burns; shape rules; the digest; the input layer per bundle; the contextual rules (eligibility,
// "attested since its last settle", priors, destinations, every signature); a large round with no cap on houses.

#include <settle.h>

#include <arith_uint256.h>
#include <bill.h>           // BillHashOutputs
#include <chainparams.h>
#include <consensus/consensus.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <house.h>
#include <key.h>
#include <note.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <functional>

bool CheckSettleNetOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                             const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                             std::vector<CHouse>& vHousesOut, bool fMempool = false);
bool CheckSettleOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                          const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                          CHouse& houseAOut, CHouse& houseBOut, bool fMempool = false);

BOOST_FIXTURE_TEST_SUITE(settle_net_tests, BasicTestingSetup)

static std::vector<unsigned char> PK(const CKey& k)
{
    const CPubKey p = k.GetPubKey();
    return std::vector<unsigned char>(p.begin(), p.end());
}

static std::vector<unsigned char> Encode(const SettleNet& n)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << n;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

static CHouse MakeHouse(uint32_t id, const std::vector<CKey>& partners, uint32_t nThresholdM, uint64_t nMinted,
                        const CKey& redeem)
{
    CHouse h;
    h.nHouseID = id;
    h.nThresholdM = nThresholdM;
    for (const CKey& k : partners) {
        HousePartner p;
        p.vchPubKey = PK(k);
        p.amountPledge = 100000;
        h.vPartner.push_back(p);
    }
    h.nMintedUnits = nMinted;
    h.amountLastAttestReserves = nMinted / 5;   // 2000 bps, above the floor
    h.nLastAttestHeight = 1000;
    h.vchRedemptionDestPK = PK(redeem);
    return h;
}

/** Three houses, the design's example 1: house 1 holds 50,000 of house 2's notes, house 2 holds 80,000 of house 3's,
 * house 3 holds 30,000 of house 1's. Nets: +20,000, +30,000, -50,000. House 2 is 2-of-2. */
struct NetSetup {
    std::map<uint32_t, std::vector<CKey>> appr;
    std::map<uint32_t, CKey> pres, red;
    std::map<uint32_t, CHouse> houses;

    NetSetup()
    {
        for (uint32_t id = 1; id <= 3; id++) {
            CKey a1, a2, p, r;
            a1.MakeNewKey(true); a2.MakeNewKey(true); p.MakeNewKey(true); r.MakeNewKey(true);
            appr[id] = id == 2 ? std::vector<CKey>{a1, a2} : std::vector<CKey>{a1};
            pres[id] = p;
            red[id] = r;
            houses[id] = MakeHouse(id, appr[id], id == 2 ? 2 : 1, 1000000 * id, r);
        }
    }

    /** The round, signed by everyone unless fSign is false. Priors come from `hs`. */
    CMutableTransaction Build(SettleNet& n, const std::map<uint32_t, CHouse>& hs, bool fSign = true,
                              uint32_t nExpiry = 0) const
    {
        n = SettleNet();
        n.vHouseID = {1, 2, 3};
        n.vReceive = {20000, 30000, 0};
        for (const uint32_t id : n.vHouseID) {
            n.vPrevMintedUnits.push_back(hs.at(id).nMintedUnits);
            n.vPrevLastSettleHeight.push_back(hs.at(id).nLastSettleHeight);
            n.vPresentKey.push_back(PK(pres.at(id)));
        }
        SettleNetBundle b;
        b.nCount = 1;
        b.nPresenter = 1; b.nIssuer = 2; b.nUnits = 50000; n.vBundle.push_back(b);
        b.nPresenter = 2; b.nIssuer = 3; b.nUnits = 80000; n.vBundle.push_back(b);
        b.nPresenter = 3; b.nIssuer = 1; b.nUnits = 30000; n.vBundle.push_back(b);
        n.nExpiryHeight = nExpiry;
        n.vPresentSig.assign(3, std::vector<unsigned char>());
        n.vApproverIndex.assign(3, std::vector<uint32_t>());
        n.vApproverSig.assign(3, std::vector<std::vector<unsigned char>>());

        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_SETTLE_VERSION;
        mtx.nSettleOp = SETTLE_OP_NET;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xa0"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xb0"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xc0"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xd0"), 0)));
        mtx.vout.emplace_back(20000, NoteScriptForPubKey(hs.at(1).vchRedemptionDestPK));
        mtx.vout.emplace_back(30000, NoteScriptForPubKey(hs.at(2).vchRedemptionDestPK));

        if (fSign) {
            const CTransaction ctx(mtx);
            const uint256 sighash = SettleNetSigHash(n, SettleHashPrevouts(ctx), BillHashOutputs(ctx));
            for (size_t i = 0; i < 3; i++) {
                const uint32_t id = n.vHouseID[i];
                for (size_t k = 0; k < appr.at(id).size(); k++) {
                    std::vector<unsigned char> sig;
                    BOOST_REQUIRE(appr.at(id)[k].Sign(sighash, sig));
                    n.vApproverIndex[i].push_back((uint32_t)k);
                    n.vApproverSig[i].push_back(sig);
                }
                BOOST_REQUIRE(pres.at(id).Sign(sighash, n.vPresentSig[i]));
            }
        } else {
            for (size_t i = 0; i < 3; i++) {
                n.vPresentSig[i].assign(70, 0x01);
                n.vApproverIndex[i] = {0};
                n.vApproverSig[i] = {std::vector<unsigned char>(70, 0x02)};
            }
        }
        mtx.vchSettlePayload = Encode(n);
        return mtx;
    }
};

static std::string ShapeReject(const CMutableTransaction& mtx)
{
    CValidationState state;
    if (CheckSettleTransactionShape(CTransaction(mtx), state))
        return "OK";
    return state.GetRejectReason();
}

static std::string NetOpReject(const CMutableTransaction& mtx, const std::map<uint32_t, CHouse>& houses, int nHeight,
                               std::vector<CHouse>* pOut = nullptr)
{
    auto fnGetHouse = [&houses](uint32_t nID, CHouse& h) {
        auto it = houses.find(nID);
        if (it == houses.end()) return false;
        h = it->second;
        return true;
    };
    CValidationState state;
    std::vector<CHouse> vOut;
    if (!CheckSettleNetOperation(CTransaction(mtx), state, nHeight, fnGetHouse, vOut))
        return state.GetRejectReason();
    if (pOut) *pOut = vOut;
    return "OK";
}

BOOST_AUTO_TEST_CASE(net_codec_and_slot_reader)
{
    NetSetup s;
    SettleNet n;
    CMutableTransaction mtx = s.Build(n, s.houses);

    SettleNet back;
    BOOST_CHECK(DecodeSettlePayload(mtx.vchSettlePayload, back));
    BOOST_CHECK(Encode(back) == mtx.vchSettlePayload);
    std::vector<unsigned char> trailing = mtx.vchSettlePayload;
    trailing.push_back(0x00);
    BOOST_CHECK(!DecodeSettlePayload(trailing, back));

    std::vector<uint32_t> vSlots;
    BOOST_CHECK(SettleSlotHouses(CTransaction(mtx), vSlots));
    BOOST_CHECK(vSlots == std::vector<uint32_t>({1, 2, 3}));

    // A short or empty payload takes no slots (and fails shape).
    CMutableTransaction m = mtx;
    m.vchSettlePayload.resize(5);
    BOOST_CHECK(!SettleSlotHouses(CTransaction(m), vSlots));
    m.vchSettlePayload.clear();
    BOOST_CHECK(!SettleSlotHouses(CTransaction(m), vSlots));

    // The exchange still reads its pair.
    CMutableTransaction ex;
    ex.nVersion = TRANSACTION_SETTLE_VERSION;
    ex.nSettleOp = SETTLE_OP_EXCHANGE;
    ex.vchSettlePayload = {7, 0, 0, 0, 9, 0, 0, 0};
    BOOST_CHECK(SettleSlotHouses(CTransaction(ex), vSlots));
    BOOST_CHECK(vSlots == std::vector<uint32_t>({7, 9}));
}

BOOST_AUTO_TEST_CASE(net_positions)
{
    NetSetup s;
    SettleNet n;
    s.Build(n, s.houses);
    std::vector<int64_t> vNet;
    std::vector<uint64_t> vBurn;
    BOOST_REQUIRE(SettleNetPositions(n, vNet, vBurn));
    BOOST_CHECK(vNet == std::vector<int64_t>({20000, 30000, -50000}));
    BOOST_CHECK(vBurn == std::vector<uint64_t>({30000, 50000, 80000}));

    // A cycle of equal amounts nets to zero everywhere.
    for (SettleNetBundle& b : n.vBundle)
        b.nUnits = 50000;
    BOOST_REQUIRE(SettleNetPositions(n, vNet, vBurn));
    BOOST_CHECK(vNet == std::vector<int64_t>({0, 0, 0}));

    // A bundle naming a house outside the round.
    n.vBundle[0].nIssuer = 4;
    BOOST_CHECK(!SettleNetPositions(n, vNet, vBurn));
}

BOOST_AUTO_TEST_CASE(net_shape_vectors)
{
    NetSetup s;
    SettleNet n;
    const CMutableTransaction good = s.Build(n, s.houses, false);
    BOOST_CHECK_EQUAL(ShapeReject(good), "OK");

    auto withPayload = [&good](const SettleNet& x) {
        CMutableTransaction m = good;
        m.vchSettlePayload = Encode(x);
        return m;
    };

    // Ops 2 and 3 stay reserved.
    { CMutableTransaction m = good; m.nSettleOp = 2; BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-op"); }
    { CMutableTransaction m = good; m.vchSettlePayload.push_back(0); BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-payload"); }
    // Houses: two or more, strictly ascending, never 0.
    {
        SettleNet x = n;
        x.vHouseID = {1};
        BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-houses");
    }
    { SettleNet x = n; x.vHouseID = {1, 3, 2}; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-house-order"); }
    { SettleNet x = n; x.vHouseID = {0, 2, 3}; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-house-order"); }
    { SettleNet x = n; x.vPrevMintedUnits.pop_back(); BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-shape"); }
    { SettleNet x = n; x.vApproverSig.pop_back(); BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-shape"); }
    // Receive amounts.
    { SettleNet x = n; x.vReceive[2] = -1; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-receive"); }
    { SettleNet x = n; x.vReceive[2] = 5; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-receive"); }
    // Presentment keys and signatures.
    { SettleNet x = n; x.vPresentKey[0].assign(33, 0x05); BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-presenter-key"); }
    { SettleNet x = n; x.vPresentSig[0].clear(); BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-presenter-sig"); }
    { SettleNet x = n; x.vApproverIndex[1] = {1, 0}; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-approvers"); }
    // A presenting house must name a key; a key belongs to a presenting house.
    {
        SettleNet x = n;
        x.vPresentKey[0].clear();
        x.vPresentSig[0].clear();
        BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-presenter-key");
    }
    // Bundles: present, ascending unique pairs, inside the round, no self-presentment, bounded.
    { SettleNet x = n; x.vBundle.clear(); BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-bundles"); }
    { SettleNet x = n; std::swap(x.vBundle[0], x.vBundle[1]); BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-bundle-order"); }
    { SettleNet x = n; x.vBundle[1] = x.vBundle[0]; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-bundle-order"); }
    { SettleNet x = n; x.vBundle[2].nIssuer = 3; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-bundle-order"); }
    { SettleNet x = n; x.vBundle[2].nIssuer = 4; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-bundle-order"); }
    { SettleNet x = n; x.vBundle[0].nUnits = 0; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-units-range"); }
    { SettleNet x = n; x.vBundle[0].nCount = 0; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-bundle-count"); }
    { SettleNet x = n; x.vBundle[0].nCount = SETTLE_MAX_BUNDLE_INPUTS + 1; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-bundle-count"); }
    // Every house takes part.
    {
        SettleNet x = n;
        x.vHouseID = {1, 2, 3, 4};
        x.vReceive.push_back(0);
        x.vPrevMintedUnits.push_back(0);
        x.vPrevLastSettleHeight.push_back(0);
        x.vPresentKey.push_back(std::vector<unsigned char>());
        x.vPresentSig.push_back(std::vector<unsigned char>());
        x.vApproverIndex.push_back({0});
        x.vApproverSig.push_back({std::vector<unsigned char>(70, 0x02)});
        BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-net-idle-house");
    }
    // Inputs: at least the bundles' coins.
    { CMutableTransaction m = good; m.vin.resize(2); BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-vin-size"); }
    // Payments: in the band, at or above the minimum, at the front, in house order, exact value.
    { SettleNet x = n; x.vReceive[0] = 20200; BOOST_CHECK_EQUAL(ShapeReject(withPayload(x)), "bad-settle-band"); }
    {
        SettleNet x = n;
        x.vReceive[0] = 19900;   // 0.5% under par: inside the band, if the output says so too
        CMutableTransaction m = withPayload(x);
        m.vout[0].nValue = 19900;
        BOOST_CHECK_EQUAL(ShapeReject(m), "OK");
    }
    { CMutableTransaction m = good; std::swap(m.vout[0], m.vout[1]); BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-residual-out"); }
    { CMutableTransaction m = good; m.vout.pop_back(); BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-residual-out"); }
    {
        CMutableTransaction m = good;
        m.vout[0].scriptPubKey = CScript() << OP_TRUE;
        BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-residual-out");
    }
    {
        // A creditor below the 10,000 minimum: 5,000 of house 2's notes against 1,000 of house 1's.
        SettleNet x = n;
        x.vBundle[0].nUnits = 6000;    // house 1 presents 6,000, house 3 presents 30,000 of house 1's...
        x.vBundle[2].nUnits = 1000;    // ...now 1,000: house 1 nets +5,000
        x.vReceive = {5000, 74000, 0};
        CMutableTransaction m = withPayload(x);
        m.vout[0].nValue = 5000;
        m.vout[1].nValue = 74000;
        BOOST_CHECK_EQUAL(ShapeReject(m), "bad-settle-band");
    }
}

BOOST_AUTO_TEST_CASE(net_sighash_binds_terms_not_signatures)
{
    NetSetup s;
    SettleNet n;
    const CMutableTransaction mtx = s.Build(n, s.houses);
    const CTransaction ctx(mtx);
    const uint256 hp = SettleHashPrevouts(ctx), ho = BillHashOutputs(ctx);
    const uint256 base = SettleNetSigHash(n, hp, ho);

    std::vector<std::function<void(SettleNet&)>> vTerm = {
        [](SettleNet& x) { x.vHouseID[2] = 4; },
        [](SettleNet& x) { x.vReceive[0] += 1; },
        [](SettleNet& x) { x.vPrevMintedUnits[1] += 1; },
        [](SettleNet& x) { x.vPrevLastSettleHeight[0] = 7; },
        [](SettleNet& x) { x.vPresentKey[2][5] ^= 1; },
        [](SettleNet& x) { x.vBundle[1].nUnits += 1; },
        [](SettleNet& x) { x.vBundle[1].nCount += 1; },
        [](SettleNet& x) { x.vBundle[0].nPresenter = 3; },
        [](SettleNet& x) { x.nExpiryHeight = 5; },
    };
    for (const auto& f : vTerm) {
        SettleNet x = n;
        f(x);
        BOOST_CHECK(SettleNetSigHash(x, hp, ho) != base);
    }
    SettleNet x = n;
    x.vPresentSig[0].clear();
    x.vApproverIndex[1].clear();
    x.vApproverSig[1].clear();
    BOOST_CHECK(SettleNetSigHash(x, hp, ho) == base);
    BOOST_CHECK(SettleNetSigHash(n, uint256S("0x01"), ho) != base);
    BOOST_CHECK(SettleNetSigHash(n, hp, uint256S("0x01")) != base);
}

/** The input layer: vin[0..3) the three bundles, vin[3] plain funding from house 3. */
static void AddNetCoins(CCoinsViewCache& cache, const NetSetup& s)
{
    struct { const char* hash; uint32_t nIssuer; uint64_t nUnits; uint32_t nPresenter; } notes[] = {
        {"0xa0", 2, 50000, 1}, {"0xb0", 3, 80000, 2}, {"0xc0", 1, 30000, 3},
    };
    for (const auto& c : notes) {
        Coin coin(CTxOut(1000, NoteScriptForPubKey(PK(s.pres.at(c.nPresenter)))), 100, false, false, false, uint256());
        coin.SetNote(c.nIssuer, c.nUnits);
        cache.AddCoin(COutPoint(uint256S(c.hash), 0), std::move(coin), false);
    }
    Coin fund(CTxOut(60000, NoteScriptForPubKey(PK(s.pres.at(3)))), 100, false, false, false, uint256());
    cache.AddCoin(COutPoint(uint256S("0xd0"), 0), std::move(fund), false);
}

static std::string InputsReject(const CMutableTransaction& mtx, const CCoinsViewCache& cache)
{
    CValidationState state;
    CAmount fee = 0;
    if (Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee))
        return "OK";
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(net_input_vectors)
{
    NetSetup s;
    SettleNet n;
    const CMutableTransaction good = s.Build(n, s.houses);
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        AddNetCoins(cache, s);
        BOOST_CHECK_EQUAL(InputsReject(good, cache), "OK");
    }
    // Each bundle coin must be its issuer's note, undemanded, pure, on its presenter's key, summing exactly.
    auto withCoin = [&](const char* hash, const std::function<void(Coin&)>& f) {
        CCoinsView base; CCoinsViewCache cache(&base);
        AddNetCoins(cache, s);
        Coin coin = cache.AccessCoin(COutPoint(uint256S(hash), 0));
        f(coin);
        cache.SpendCoin(COutPoint(uint256S(hash), 0));
        cache.AddCoin(COutPoint(uint256S(hash), 0), std::move(coin), true);
        return InputsReject(good, cache);
    };
    BOOST_CHECK_EQUAL(withCoin("0xb0", [](Coin& c) { c.SetNote(1, 80000); }), "bad-settle-bundle-issuer");
    BOOST_CHECK_EQUAL(withCoin("0xb0", [](Coin& c) { c.nDemandHeight = 50; }), "bad-settle-demanded-note");
    BOOST_CHECK_EQUAL(withCoin("0xb0", [](Coin& c) { c.fPoolEscrow = true; }), "bad-settle-tagged-input");
    BOOST_CHECK_EQUAL(withCoin("0xb0", [](Coin& c) { c.fHouseEscrow = true; }), "bad-settle-tagged-input");
    BOOST_CHECK_EQUAL(withCoin("0xc0", [&s](Coin& c) { c.out.scriptPubKey = NoteScriptForPubKey(PK(s.pres.at(1))); }),
                      "bad-settle-input-not-presenter");
    BOOST_CHECK_EQUAL(withCoin("0xa0", [](Coin& c) { c.SetNote(2, 49999); }), "bad-settle-bundle-sum");
    // Funding after the bundles must be plain.
    BOOST_CHECK_EQUAL(withCoin("0xd0", [](Coin& c) { c.SetNote(2, 1); }), "bad-settle-tagged-input");
}

BOOST_AUTO_TEST_CASE(net_contextual_vectors)
{
    NetSetup s;
    const int H = 1100;
    SettleNet n;

    // Happy path: every record mutates by its burn and is stamped.
    {
        std::vector<CHouse> vOut;
        CMutableTransaction mtx = s.Build(n, s.houses);
        BOOST_CHECK_EQUAL(NetOpReject(mtx, s.houses, H, &vOut), "OK");
        BOOST_REQUIRE_EQUAL(vOut.size(), 3U);
        BOOST_CHECK_EQUAL(vOut[0].nMintedUnits, 1000000U - 30000);
        BOOST_CHECK_EQUAL(vOut[1].nMintedUnits, 2000000U - 50000);
        BOOST_CHECK_EQUAL(vOut[2].nMintedUnits, 3000000U - 80000);
        for (const CHouse& h : vOut)
            BOOST_CHECK_EQUAL(h.nLastSettleHeight, (uint32_t)H);
    }
    // Unknown house.
    {
        std::map<uint32_t, CHouse> hs = s.houses;
        CMutableTransaction mtx = s.Build(n, hs);
        hs.erase(3);
        BOOST_CHECK_EQUAL(NetOpReject(mtx, hs, H), "bad-settle-unknown-house");
    }
    // Ineligible: a stale attestation.
    {
        std::map<uint32_t, CHouse> hs = s.houses;
        hs[2].nLastAttestHeight = H - HOUSE_ATTEST_CADENCE - 1;
        BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, hs), hs, H), "bad-settle-house-ineligible");
    }
    // Settled since its last attestation: refused until it attests again.
    {
        std::map<uint32_t, CHouse> hs = s.houses;
        hs[3].nLastSettleHeight = 1050;   // attested at 1000, settled at 1050
        BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, hs), hs, H), "bad-settle-net-not-attested");
        hs[3].nLastAttestHeight = 1060;   // attested since: welcome back
        BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, hs), hs, H), "OK");
        hs[3].nLastAttestHeight = H;      // an attestation in this very block doesn't count
        BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, hs), hs, H), "bad-settle-net-not-attested");
    }
    // No once-a-day cadence for netting: a round 60 blocks after the last settle, attested in between.
    {
        std::map<uint32_t, CHouse> hs = s.houses;
        hs[1].nLastSettleHeight = H - 60;
        hs[1].nLastAttestHeight = H - 30;
        BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, hs), hs, H), "OK");
    }
    // Priors: a record moved after signing.
    {
        CMutableTransaction mtx = s.Build(n, s.houses);
        std::map<uint32_t, CHouse> hs = s.houses;
        hs[2].nMintedUnits += 1;
        BOOST_CHECK_EQUAL(NetOpReject(mtx, hs, H), "bad-settle-priors-mismatch");
    }
    // A burn larger than what the issuer has outstanding.
    {
        std::map<uint32_t, CHouse> hs = s.houses;
        hs[3].nMintedUnits = 79999;
        hs[3].amountLastAttestReserves = 79999;
        BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, hs), hs, H), "bad-settle-units-exceed-minted");
    }
    // A payment to anything but the creditor's redemption key.
    {
        std::map<uint32_t, CHouse> hs = s.houses;
        CMutableTransaction mtx = s.Build(n, hs);
        CKey other; other.MakeNewKey(true);
        hs[2].vchRedemptionDestPK = PK(other);
        BOOST_CHECK_EQUAL(NetOpReject(mtx, hs, H), "bad-settle-residual-dest");
    }
    // Expiry.
    BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, s.houses, true, H - 1), s.houses, H), "bad-settle-expired");
    BOOST_CHECK_EQUAL(NetOpReject(s.Build(n, s.houses, true, H), s.houses, H), "OK");
    // Signatures: one approver short, a wrong approver signature, a wrong presenter signature, a changed term.
    {
        CMutableTransaction mtx = s.Build(n, s.houses);
        SettleNet x = n;
        x.vApproverIndex[1].pop_back();
        x.vApproverSig[1].pop_back();
        mtx.vchSettlePayload = Encode(x);
        BOOST_CHECK_EQUAL(NetOpReject(mtx, s.houses, H), "bad-settle-approver");
    }
    {
        CMutableTransaction mtx = s.Build(n, s.houses);
        SettleNet x = n;
        std::swap(x.vApproverSig[0], x.vApproverSig[2]);
        mtx.vchSettlePayload = Encode(x);
        BOOST_CHECK_EQUAL(NetOpReject(mtx, s.houses, H), "bad-settle-approver");
    }
    {
        CMutableTransaction mtx = s.Build(n, s.houses);
        SettleNet x = n;
        std::swap(x.vPresentSig[0], x.vPresentSig[1]);
        mtx.vchSettlePayload = Encode(x);
        BOOST_CHECK_EQUAL(NetOpReject(mtx, s.houses, H), "bad-settle-presenter-sig-invalid");
    }
    {
        CMutableTransaction mtx = s.Build(n, s.houses);
        mtx.vout.emplace_back(500, CScript() << OP_TRUE);   // an output added after signing
        BOOST_CHECK_EQUAL(NetOpReject(mtx, s.houses, H), "bad-settle-approver");
    }
}

/** No cap on houses: a ring of 300 houses (the house list's length takes a 3-byte compact size), each presenting
 * 10,000 of the next house's notes - every net is zero, nothing is paid - passes shape, and the slot reader returns
 * all 300. */
BOOST_AUTO_TEST_CASE(net_large_round)
{
    const uint32_t N = 300;
    SettleNet n;
    CKey key; key.MakeNewKey(true);
    for (uint32_t i = 1; i <= N; i++) {
        n.vHouseID.push_back(i);
        n.vReceive.push_back(0);
        n.vPrevMintedUnits.push_back(1000000);
        n.vPrevLastSettleHeight.push_back(0);
        n.vPresentKey.push_back(PK(key));
        n.vPresentSig.push_back(std::vector<unsigned char>(70, 0x01));
        n.vApproverIndex.push_back({0});
        n.vApproverSig.push_back({std::vector<unsigned char>(70, 0x02)});
    }
    for (uint32_t i = 1; i <= N; i++) {
        SettleNetBundle b;
        b.nPresenter = i;
        b.nIssuer = i == N ? 1 : i + 1;
        b.nUnits = 10000;
        b.nCount = 1;
        n.vBundle.push_back(b);
    }
    std::sort(n.vBundle.begin(), n.vBundle.end(), [](const SettleNetBundle& a, const SettleNetBundle& b) {
        return std::make_pair(a.nPresenter, a.nIssuer) < std::make_pair(b.nPresenter, b.nIssuer);
    });
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_SETTLE_VERSION;
    mtx.nSettleOp = SETTLE_OP_NET;
    for (uint32_t i = 0; i < N; i++)
        mtx.vin.push_back(CTxIn(COutPoint(ArithToUint256(arith_uint256(i + 1)), 0)));
    mtx.vchSettlePayload = Encode(n);
    BOOST_CHECK_EQUAL(mtx.vchSettlePayload[0], 0xfd);   // 300 houses: a 3-byte compact size
    BOOST_CHECK_EQUAL(ShapeReject(mtx), "OK");

    std::vector<uint32_t> vSlots;
    BOOST_REQUIRE(SettleSlotHouses(CTransaction(mtx), vSlots));
    BOOST_CHECK_EQUAL(vSlots.size(), N);
    BOOST_CHECK_EQUAL(vSlots.front(), 1U);
    BOOST_CHECK_EQUAL(vSlots.back(), N);
}

/** The design's size claim (NETTING_DESIGN.md s5): 24 houses that all hold each other's notes, each 2-of-2, real
 * signatures and realistic input sizes, fit the 100,000-byte relay limit; and the round passes every contextual
 * check (48 approver and 24 presenter signatures). */
BOOST_AUTO_TEST_CASE(net_full_mesh_24_fits_relay)
{
    const uint32_t N = 24;
    const int H = 1100;
    std::map<uint32_t, CHouse> houses;
    std::map<uint32_t, std::vector<CKey>> appr;
    std::map<uint32_t, CKey> pres;
    SettleNet n;
    for (uint32_t id = 1; id <= N; id++) {
        CKey a1, a2, p, r;
        a1.MakeNewKey(true); a2.MakeNewKey(true); p.MakeNewKey(true); r.MakeNewKey(true);
        appr[id] = {a1, a2};
        pres[id] = p;
        houses[id] = MakeHouse(id, appr[id], 2, 1000000, r);
        n.vHouseID.push_back(id);
        n.vReceive.push_back(0);
        n.vPrevMintedUnits.push_back(1000000);
        n.vPrevLastSettleHeight.push_back(0);
        n.vPresentKey.push_back(PK(p));
    }
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_SETTLE_VERSION;
    mtx.nSettleOp = SETTLE_OP_NET;
    const CScript dummySig = CScript() << std::vector<unsigned char>(72, 0x30) << std::vector<unsigned char>(33, 0x02);
    uint32_t nCoin = 0;
    for (uint32_t p = 1; p <= N; p++) {
        for (uint32_t q = 1; q <= N; q++) {
            if (p == q) continue;
            SettleNetBundle b;
            b.nPresenter = p; b.nIssuer = q; b.nUnits = 10000; b.nCount = 1;
            n.vBundle.push_back(b);
            mtx.vin.push_back(CTxIn(COutPoint(ArithToUint256(arith_uint256(++nCoin)), 0), dummySig));
        }
    }
    mtx.vin.push_back(CTxIn(COutPoint(ArithToUint256(arith_uint256(++nCoin)), 0), dummySig));   // the starter's fee
    mtx.vout.emplace_back(50000, NoteScriptForPubKey(PK(pres[1])));                               // its change
    n.vPresentSig.assign(N, std::vector<unsigned char>());
    n.vApproverIndex.assign(N, std::vector<uint32_t>());
    n.vApproverSig.assign(N, std::vector<std::vector<unsigned char>>());
    const CTransaction ctx(mtx);
    const uint256 sighash = SettleNetSigHash(n, SettleHashPrevouts(ctx), BillHashOutputs(ctx));
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t k = 0; k < 2; k++) {
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(appr[i + 1][k].Sign(sighash, sig));
            n.vApproverIndex[i].push_back(k);
            n.vApproverSig[i].push_back(sig);
        }
        BOOST_REQUIRE(pres[i + 1].Sign(sighash, n.vPresentSig[i]));
    }
    mtx.vchSettlePayload = Encode(n);

    const unsigned int nWeight = GetTransactionWeight(CTransaction(mtx));
    BOOST_TEST_MESSAGE("24-house full mesh: " << mtx.vin.size() << " inputs, payload " << mtx.vchSettlePayload.size()
                       << " bytes, weight " << nWeight);
    BOOST_CHECK(nWeight < MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK_EQUAL(ShapeReject(mtx), "OK");
    std::vector<CHouse> vOut;
    BOOST_CHECK_EQUAL(NetOpReject(mtx, houses, H, &vOut), "OK");
    BOOST_REQUIRE_EQUAL(vOut.size(), N);
    for (const CHouse& h : vOut)
        BOOST_CHECK_EQUAL(h.nMintedUnits, 1000000U - 10000 * (N - 1));
}

/** The exchange after a NET round: the exchange's cadence counts from the round's stamp (the two share
 * nLastSettleHeight). */
BOOST_AUTO_TEST_CASE(net_then_exchange_cadence)
{
    CKey a1, a2, p1, p2, r1, r2;
    a1.MakeNewKey(true); a2.MakeNewKey(true); p1.MakeNewKey(true); p2.MakeNewKey(true);
    r1.MakeNewKey(true); r2.MakeNewKey(true);
    const uint32_t X = 1050;   // the NET round's height
    const uint32_t nCadence = Params().GetConsensus().nSettleCadence;
    std::map<uint32_t, CHouse> hs;
    hs[1] = MakeHouse(1, {a1}, 1, 1200000, r1);
    hs[2] = MakeHouse(2, {a2}, 1, 900000, r2);
    for (auto& kv : hs) {
        kv.second.nLastSettleHeight = X;
        kv.second.nLastAttestHeight = X + 10;   // attested after the round
    }
    auto fnBuild = [&]() {
        SettleExchange x;
        x.nHouseA = 1; x.nHouseB = 2; x.nMode = 1;
        x.nUnitsANotes = 60000; x.nUnitsBNotes = 45000; x.nCountANotes = 1; x.nCountBNotes = 1;
        x.vchPresentKeyOfANotes = PK(p1); x.vchPresentKeyOfBNotes = PK(p2);
        x.amountResidual = 15000;
        x.nPrevMintedUnitsA = hs[1].nMintedUnits; x.nPrevMintedUnitsB = hs[2].nMintedUnits;
        x.nPrevLastSettleHeightA = X; x.nPrevLastSettleHeightB = X;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_SETTLE_VERSION;
        mtx.nSettleOp = SETTLE_OP_EXCHANGE;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xa0"), 0)));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0xb0"), 0)));
        mtx.vout.emplace_back(15000, NoteScriptForPubKey(hs[2].vchRedemptionDestPK));
        const CTransaction ctx(mtx);
        const uint256 h = SettleExchangeSigHash(x, SettleHashPrevouts(ctx), BillHashOutputs(ctx));
        std::vector<unsigned char> s;
        BOOST_REQUIRE(a1.Sign(h, s)); x.vApproverIndexA = {0}; x.vApproverSigA = {s};
        BOOST_REQUIRE(a2.Sign(h, s)); x.vApproverIndexB = {0}; x.vApproverSigB = {s};
        BOOST_REQUIRE(p1.Sign(h, x.vchPresentSigOfANotes));
        BOOST_REQUIRE(p2.Sign(h, x.vchPresentSigOfBNotes));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << x;
        mtx.vchSettlePayload.assign(ss.begin(), ss.end());
        return mtx;
    };
    auto fnReject = [&](int nHeight) {
        auto fnGetHouse = [&hs](uint32_t nID, CHouse& h) { auto it = hs.find(nID); if (it == hs.end()) return false; h = it->second; return true; };
        CValidationState state;
        CHouse outA, outB;
        if (CheckSettleOperation(CTransaction(fnBuild()), state, nHeight, fnGetHouse, outA, outB))
            return std::string("OK");
        return state.GetRejectReason();
    };
    BOOST_CHECK_EQUAL(fnReject(X + nCadence - 1), "bad-settle-cadence");
    BOOST_CHECK_EQUAL(fnReject(X + nCadence), "OK");
}

BOOST_AUTO_TEST_SUITE_END()
