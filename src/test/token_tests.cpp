// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The token holders' claim at a failed house (token.h; gateway docs/freebank/TOKEN_CLAIM_DESIGN.md draft 3). Tokens
// come from a small test mint below (Cashu BDHKE + NUT-12 DLEQ on the node's secp256k1).

#include <cashu.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <house.h>
#include <key.h>
#include <note.h>
#include <settle.h>     // SettleNet (testing: S1X-37)
#include <bill.h>       // BillRetire (testing: family A)
#include <deposit.h>    // DepositWithdraw (testing: family A)
#include <random.h>
#include <streams.h>
#include <token.h>
#include <undo.h>
#include <test/sidechain_test_util.h>   // SideDBScope (S1X-27 token probe)
#include <test/test_bitcoin.h>
#include <txmempool.h>
#include <txdb.h>       // HouseDB (s1x_27 under Stage 0 rule A: a live insolvent house)
#include <keystore.h>   // s1x_37 under Stage 0 rule A: the NET signs its first input
#include <script/sign.h>
#include <utiltime.h>
#include <validation.h>
#include <utilstrencodings.h>
#include <version.h>

#include <secp256k1.h>

#include <algorithm>
#include <map>

#include <boost/test/unit_test.hpp>
#include <houserate.h>   // CChainClock, CSwapRecord, SwapOpen (S1X-5)
#include <issued.h>      // UnitsCheckScope (S1X-5)
#include <units.h>       // CUnitsView (S1X-5)

bool CheckTokenOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                         const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                         const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin,
                         const TokenView& view, TokenEffects& eff,
                         CHouse& houseOut, bool& fHouseChanged, bool fMempool = false,
                         const std::vector<CPubKey>* pvClaimY = nullptr);   // Stage 0 rule A
bool CheckNoteTransactionShape(const CTransaction& tx, CValidationState& state);
std::vector<COutPoint> EscrowChangeBeforeOp(const CHouse& house, const CTransaction& tx, const CTxUndo* pundo,
                                            uint32_t nChangeVout);

namespace {

secp256k1_context* Ctx()
{
    static secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return c;
}

CashuScalar RandScalar()
{
    CKey k;
    k.MakeNewKey(true);
    CashuScalar s;
    memcpy(s.data(), k.begin(), 32);
    return s;
}

CPubKey Ser(const secp256k1_pubkey& p)
{
    unsigned char buf[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(Ctx(), buf, &len, &p, SECP256K1_EC_COMPRESSED);
    return CPubKey(buf, buf + len);
}

CPubKey MulG(const CashuScalar& k)
{
    secp256k1_pubkey p;
    BOOST_REQUIRE(secp256k1_ec_pubkey_create(Ctx(), &p, k.data()));
    return Ser(p);
}

CPubKey MulPoint(const CPubKey& P, const CashuScalar& k)
{
    secp256k1_pubkey p;
    BOOST_REQUIRE(secp256k1_ec_pubkey_parse(Ctx(), &p, P.begin(), P.size()));
    BOOST_REQUIRE(secp256k1_ec_pubkey_tweak_mul(Ctx(), &p, k.data()));
    return Ser(p);
}

std::vector<unsigned char> V(const CPubKey& p) { return std::vector<unsigned char>(p.begin(), p.end()); }

/** A test mint: one key per amount exponent. */
struct TestMint {
    std::map<uint8_t, CashuScalar> k;
    std::vector<TokenKey> Keys()
    {
        std::vector<TokenKey> v;
        for (const auto& kv : k)
            v.emplace_back(kv.first, V(MulG(kv.second)));
        return v;
    }
    struct Token { std::vector<unsigned char> secret; CashuScalar r, e, s; CPubKey Y, B, C_; uint64_t amount; };
    Token Issue(uint8_t nExp, const std::string& strSecret)
    {
        Token t;
        t.amount = 1ULL << nExp;
        t.secret.assign(strSecret.begin(), strSecret.end());
        BOOST_REQUIRE(CashuHashToCurve(t.secret, t.Y));
        const CashuScalar& kk = k.at(nExp);
        const CPubKey A = MulG(kk);
        t.r = RandScalar();
        CPubKey C_;
        BOOST_REQUIRE(CashuReblind(A, t.Y, MulPoint(t.Y, kk), t.r, t.B, C_));   // B_ = Y + rG, C_ = k*B_
        BOOST_REQUIRE(MulPoint(t.B, kk) == C_);
        t.C_ = C_;
        // NUT-12: e = hash(nonce*G, nonce*B_, A, C_), s = nonce + e*k
        const CashuScalar nonce = RandScalar();
        BOOST_REQUIRE(CashuHashE({MulG(nonce), MulPoint(t.B, nonce), A, C_}, t.e));
        t.s = t.e;
        BOOST_REQUIRE(secp256k1_ec_privkey_tweak_mul(Ctx(), t.s.data(), kk.data()));
        BOOST_REQUIRE(secp256k1_ec_privkey_tweak_add(Ctx(), t.s.data(), nonce.data()));
        BOOST_REQUIRE(CashuVerifyDLEQ(A, t.B, C_, t.e, t.s));
        return t;
    }
};

/** The records a token op reads, in memory. */
struct Records {
    std::map<std::pair<uint32_t, uint64_t>, CTokenKeyset> keyset;
    std::map<std::pair<uint32_t, std::vector<unsigned char>>, CTokenMark> issued;
    std::map<std::pair<uint32_t, uint256>, CTokenMark> spent;
    std::map<std::pair<uint32_t, uint256>, CTokenClaim> claim;
    TokenView View()
    {
        TokenView v;
        v.fnGetKeyset = [this](uint32_t h, uint64_t id, CTokenKeyset& r) { auto it = keyset.find({h, id}); if (it == keyset.end()) return false; r = it->second; return true; };
        v.fnGetIssued = [this](uint32_t h, const std::vector<unsigned char>& b, CTokenMark& r) { auto it = issued.find({h, b}); if (it == issued.end()) return false; r = it->second; return true; };
        v.fnGetSpent = [this](uint32_t h, const uint256& y, CTokenMark& r) { auto it = spent.find({h, y}); if (it == spent.end()) return false; r = it->second; return true; };
        v.fnGetClaim = [this](uint32_t h, const uint256& y, CTokenClaim& r) { auto it = claim.find({h, y}); if (it == claim.end()) return false; r = it->second; return true; };
        return v;
    }
};

/** A house that went insolvent by the stress path: E = deadline + 1 + HOUSE_STRESSED_WINDOW. */
struct FailedHouse {
    CKey keyPartner;
    CHouse house;
    uint32_t E;
    FailedHouse()
    {
        keyPartner.MakeNewKey(true);
        house.nHouseID = 5;
        house.houseID = uint256S("f00d");
        house.nThresholdM = 1;
        house.strClassID = "mint";
        house.status = HOUSE_STATUS_OPEN;
        house.nRegisteredHeight = 100;
        house.nLastAttestHeight = 200;
        // Gram-notes release: the old missed-cadence origin (deadline + 1), stored, since that origin no longer
        // derives (stress starts only on unpaid demand); every height below is unchanged.
        house.nStressSinceHeight = 200 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1;
        house.amountLastAttestReserves = 100 * COIN;
        house.nMintedUnits = 1000000;
        house.nTokenUnits = 300000;
        HousePartner p;
        p.vchPubKey = V(keyPartner.GetPubKey());
        p.amountPledge = 10 * COIN;
        p.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(p);
        E = HouseInsolventSince(house, 100000);
    }
    std::function<bool(uint32_t, CHouse&)> Get() const
    {
        const CHouse h = house;
        return [h](uint32_t id, CHouse& out) { if (id != h.nHouseID) return false; out = h; return true; };
    }
};

CMutableTransaction NoteOpTx(uint8_t nOp)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = nOp;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("fee1"), 0)));
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    return mtx;
}

template <typename T>
void SetPayload(CMutableTransaction& mtx, const T& p)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    mtx.vchNotePayload.assign(ss.begin(), ss.end());
}

TokenClaimEntry Entry(uint32_t nHouseID, uint64_t nKeysetID, const TestMint::Token& t, const CScript& scriptPay,
                      uint16_t nFeeBps = 0, const CScript& scriptRelayer = CScript())
{
    TokenClaimEntry e;
    e.nKeysetID = nKeysetID;
    e.nAmount = t.amount;
    e.vchSecret = t.secret;
    e.vchB = V(t.B);
    e.vchC = V(t.C_);
    e.vchE.assign(t.e.begin(), t.e.end());
    e.vchS.assign(t.s.begin(), t.s.end());
    e.vchPayoutScript.assign(scriptPay.begin(), scriptPay.end());
    e.nFeeBps = nFeeBps;
    e.vchRelayerScript.assign(scriptRelayer.begin(), scriptRelayer.end());
    CKey keyR;
    keyR.Set(t.r.begin(), t.r.end(), true);
    BOOST_REQUIRE(keyR.Sign(TokenClaimSigHash(nHouseID, TokenYID(t.Y), e.vchPayoutScript, nFeeBps, e.vchRelayerScript), e.vchSig));
    return e;
}

std::string Run(const CMutableTransaction& mtx, int nHeight, const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                Records& rec, TokenEffects* pEff = nullptr, CHouse* pOut = nullptr,
                const std::function<bool(const COutPoint&, Coin&)>& fnGetCoin = [](const COutPoint&, Coin&) { return false; })
{
    CValidationState state;
    if (!CheckNoteTransactionShape(CTransaction(mtx), state))
        return state.GetRejectReason();
    TokenEffects eff;
    CHouse out;
    bool fChanged = false;
    if (!CheckTokenOperation(CTransaction(mtx), state, nHeight, fnGetHouse, fnGetCoin, rec.View(), eff, out, fChanged))
        return state.GetRejectReason();
    if (pEff) *pEff = eff;
    if (pOut) *pOut = out;
    return "OK";
}

} // namespace

// Stage 0 C1 test shim: the transaction with payload p serialized into its op field (a C1 digest takes the whole tx;
// the payload's signature fields are stripped, so it may be passed before or after they are filled).
template <typename T, typename P>
static CTransaction C1With(const T& tx, std::vector<unsigned char> CMutableTransaction::*field, const P& p)
{
    CMutableTransaction m(tx);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    (m.*field).assign(ss.begin(), ss.end());
    return CTransaction(m);
}

BOOST_FIXTURE_TEST_SUITE(token_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(token_helpers)
{
    // The keyset id is Cashu's NUT-02 id (the test mint lib/cashu_mint.py, seed "unit", amounts 1, 2, 4).
    std::vector<TokenKey> v;
    v.emplace_back(0, ParseHex("03bd8b5bf074ae948faf15fa76c8c2a2d530cc44db9a3cef239792bb297a5be531"));
    v.emplace_back(1, ParseHex("029945ada502aaa3f12ff4dabd3699dd78c2a8ef50f06b479210718c38ee9b365a"));
    v.emplace_back(2, ParseHex("022763fbce41e0125f30cc38ccd23ad57055cabe90ee86ceb574c43fdd2889f137"));
    BOOST_CHECK_EQUAL(strprintf("%016x", TokenKeysetID(v)), "00f32056617987bd");

    // The pro-rata cut, floored, 128-bit inside.
    BOOST_CHECK_EQUAL(TokenClaimUnits(131072, 299000, 327680), 119600U);
    BOOST_CHECK_EQUAL(TokenClaimUnits(65536, 299000, 327680), 59800U);
    BOOST_CHECK_EQUAL(TokenClaimUnits(500, 1000, 800), 500U);              // T <= B: in full
    BOOST_CHECK_EQUAL(TokenClaimUnits(1ULL << 50, (uint64_t)MAX_MONEY, std::numeric_limits<uint64_t>::max() / 2),
                      (uint64_t)(((unsigned __int128)(1ULL << 50) * MAX_MONEY) / (std::numeric_limits<uint64_t>::max() / 2)));
    BOOST_CHECK_EQUAL(TokenRelayerFee(119600, 100), 1196);
    BOOST_CHECK_EQUAL(TokenRelayerFee(119600, 0), 0);
    BOOST_CHECK_EQUAL(TokenRelayerFee(99, 100), 0);

    // NUT-10 secrets are JSON arrays.
    auto S = [](const std::string& s) { return std::vector<unsigned char>(s.begin(), s.end()); };
    BOOST_CHECK(IsTokenConditionSecret(S("[\"P2PK\",{}]")));
    BOOST_CHECK(IsTokenConditionSecret(S("  \n[\"HTLC\"]")));
    BOOST_CHECK(!IsTokenConditionSecret(S("daf4dd00a2b68a08")));
    BOOST_CHECK(!IsTokenConditionSecret(S("")));
}

BOOST_AUTO_TEST_CASE(insolvent_since_is_the_first_insolvent_height)
{
    // Stress path, deferral path, and a materialized house: E is the first height the chain counts it insolvent.
    FailedHouse f;
    CHouse deferred = f.house;
    deferred.nDeferInvokedHeight = 260;
    deferred.nLastAttestHeight = 300;
    for (const CHouse& h : {f.house, deferred}) {
        uint32_t nFirst = 0;
        for (int n = 100; n < 20000 && !nFirst; n++)
            if (HouseEffectiveStatus(h, n) == HOUSE_STATUS_INSOLVENT)
                nFirst = (uint32_t)n;
        BOOST_REQUIRE(nFirst != 0);
        BOOST_CHECK_EQUAL(HouseInsolventSince(h, nFirst), nFirst);
        BOOST_CHECK_EQUAL(HouseInsolventSince(h, nFirst + 5000), nFirst);
        BOOST_CHECK_EQUAL(HouseInsolventSince(h, nFirst - 1), 0U);
        CHouse mat = h;
        mat.status = HOUSE_STATUS_INSOLVENT;
        mat.nInsolventHeight = nFirst + 77;
        BOOST_CHECK_EQUAL(HouseInsolventSince(mat, nFirst + 100), nFirst);
    }
    CHouse wound = f.house;
    wound.status = HOUSE_STATUS_WOUNDDOWN;
    BOOST_CHECK_EQUAL(HouseInsolventSince(wound, 100000), 0U);
}

BOOST_AUTO_TEST_CASE(token_claim_rules)
{
    FailedHouse f;
    const uint32_t W = Params().GetConsensus().nTokenClaimWindow;
    TestMint mint;
    mint.k[16] = RandScalar();
    mint.k[17] = RandScalar();
    const std::vector<TokenKey> vKey = mint.Keys();
    const uint64_t id = TokenKeysetID(vKey);
    Records rec;
    CTokenKeyset ks;
    ks.nHeight = 150;
    ks.vKey = vKey;
    rec.keyset[{f.house.nHouseID, id}] = ks;
    const TestMint::Token t1 = mint.Issue(17, "a1"), t2 = mint.Issue(16, "a2");
    for (const TestMint::Token* t : {&t1, &t2}) {
        CTokenMark m;
        m.nHeight = 180;
        m.nKeysetID = id;
        m.nAmount = t->amount;
        rec.issued[{f.house.nHouseID, V(t->B)}] = m;
    }
    const CScript pay = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 7) << OP_EQUALVERIFY << OP_CHECKSIG;
    auto Claim = [&](std::vector<TokenClaimEntry> v) {
        CMutableTransaction mtx = NoteOpTx(NOTE_OP_TOKEN_CLAIM);
        NoteTokenClaim c;
        c.nHouseID = f.house.nHouseID;
        c.vEntry = v;
        SetPayload(mtx, c);
        return mtx;
    };
    const int nH = f.E + 1;

    // A good claim of two tokens. It writes no house record (no slot): its totals are staged for the block's end.
    TokenEffects eff;
    CHouse out;
    BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay), Entry(5, id, t2, pay)}), nH, f.Get(), rec, &eff, &out), "OK");
    BOOST_CHECK_EQUAL(eff.mapClaimTotals[5].first, t1.amount + t2.amount);
    BOOST_CHECK_EQUAL(eff.mapClaimTotals[5].second, 2U);
    BOOST_CHECK_EQUAL(eff.mapClaim.size(), 2U);

    // The window: not before E, not from E + W.
    BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay)}), f.E - 1, f.Get(), rec), "bad-token-claim-not-insolvent");
    BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay)}), f.E + W, f.Get(), rec), "bad-token-claim-window-closed");

    // The copier: same token, another payout, signed by someone who is not the holder (no r).
    TokenClaimEntry stolen = Entry(5, id, t1, pay);
    stolen.vchPayoutScript = std::vector<unsigned char>{OP_TRUE};
    BOOST_CHECK_EQUAL(Run(Claim({stolen}), nH, f.Get(), rec), "bad-token-claim-sig");
    CKey other;
    other.MakeNewKey(true);
    BOOST_REQUIRE(other.Sign(TokenClaimSigHash(5, TokenYID(t1.Y), stolen.vchPayoutScript, 0, {}), stolen.vchSig));
    BOOST_CHECK_EQUAL(Run(Claim({stolen}), nH, f.Get(), rec), "bad-token-claim-sig");

    // The DLEQ: a tampered proof, and a token claimed under the wrong amount's key (a lying issue record).
    TokenClaimEntry bad = Entry(5, id, t1, pay);
    bad.vchE[31] ^= 1;
    BOOST_CHECK_EQUAL(Run(Claim({bad}), nH, f.Get(), rec), "bad-token-claim-dleq");
    {
        Records r2 = rec;
        r2.issued[{5, V(t2.B)}].nAmount = 1ULL << 17;
        TokenClaimEntry big = Entry(5, id, t2, pay);
        big.nAmount = 1ULL << 17;
        BOOST_CHECK_EQUAL(Run(Claim({big}), nH, f.Get(), r2), "bad-token-claim-dleq");
    }

    // Records: issued after E (or never), spent, claimed, keyset recorded at E, a duplicate in one claim.
    {
        Records r2 = rec;
        r2.issued[{5, V(t1.B)}].nHeight = f.E;
        BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay)}), nH, f.Get(), r2), "bad-token-claim-not-issued");
        r2.issued.erase({5, V(t1.B)});
        BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay)}), nH, f.Get(), r2), "bad-token-claim-not-issued");
    }
    {
        Records r2 = rec;
        r2.spent[{5, TokenYID(t1.Y)}] = CTokenMark();
        BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay)}), nH, f.Get(), r2), "bad-token-claim-spent");
    }
    {
        Records r2 = rec;
        r2.claim[{5, TokenYID(t1.Y)}] = CTokenClaim();
        BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay)}), nH, f.Get(), r2), "bad-token-claim-claimed");
    }
    {
        Records r2 = rec;
        r2.keyset[{5, id}].nHeight = f.E;
        BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay)}), nH, f.Get(), r2), "bad-token-claim-keyset");
    }
    BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, t1, pay), Entry(5, id, t1, pay)}), nH, f.Get(), rec), "bad-token-claim-duplicate");

    // A locked (NUT-10) token can't claim: its sender knows r.
    const TestMint::Token tLocked = mint.Issue(16, "[\"P2PK\",{\"nonce\":\"00\",\"data\":\"02aa\"}]");
    {
        Records r2 = rec;
        CTokenMark m;
        m.nHeight = 180;
        m.nKeysetID = id;
        m.nAmount = tLocked.amount;
        r2.issued[{5, V(tLocked.B)}] = m;
        BOOST_CHECK_EQUAL(Run(Claim({Entry(5, id, tLocked, pay)}), nH, f.Get(), r2), "bad-token-claim-condition");
    }
}

BOOST_AUTO_TEST_CASE(token_post_and_keyset_rules)
{
    FailedHouse f;
    CHouse open = f.house;
    open.nLastAttestHeight = 1000;          // effectively Open at 1010
    auto GetOpen = [open](uint32_t id, CHouse& h) { if (id != open.nHouseID) return false; h = open; return true; };
    TestMint mint;
    mint.k[0] = RandScalar();
    mint.k[1] = RandScalar();
    NoteTokenKeyset ks;
    ks.nHouseID = 5;
    CKey keyPost;
    keyPost.MakeNewKey(true);
    ks.vchPostingPubKey = V(keyPost.GetPubKey());
    ks.vKey = mint.Keys();
    CMutableTransaction mtx = NoteOpTx(NOTE_OP_TOKEN_KEYSET);
    ks.vApproverIndex = {0};
    ks.vApproverSig = {std::vector<unsigned char>()};
    BOOST_REQUIRE(f.keyPartner.Sign(TokenKeysetSigHash(C1With(mtx, &CMutableTransaction::vchNotePayload, ks)), ks.vApproverSig[0]));
    SetPayload(mtx, ks);
    Records rec;
    TokenEffects eff;
    BOOST_CHECK_EQUAL(Run(mtx, 1010, GetOpen, rec, &eff), "OK");
    BOOST_CHECK_EQUAL(eff.mapKeyset.size(), 1U);
    // the same keyset again at this house is refused; at another house it is allowed (keys are unique within a house
    // only, Michael 2026-10-08: a copier only pays out its own backing); an insolvent house is refused
    {
        Records r2;
        r2.keyset[{5, TokenKeysetID(ks.vKey)}] = CTokenKeyset();
        BOOST_CHECK_EQUAL(Run(mtx, 1010, GetOpen, r2), "bad-token-keyset-exists");
        Records r3;
        r3.keyset[{9, TokenKeysetID(ks.vKey)}] = CTokenKeyset();
        BOOST_CHECK_EQUAL(Run(mtx, 1010, GetOpen, r3), "OK");
    }
    BOOST_CHECK_EQUAL(Run(mtx, f.E, f.Get(), rec), "bad-token-keyset-house-status");
    // the same key under two amounts never passes the shape check
    {
        NoteTokenKeyset dup = ks;
        dup.vKey[1].vchPubKey = dup.vKey[0].vchPubKey;
        CMutableTransaction m2 = NoteOpTx(NOTE_OP_TOKEN_KEYSET);
        SetPayload(m2, dup);
        BOOST_CHECK_EQUAL(Run(m2, 1010, GetOpen, rec), "bad-token-keyset-key");
    }

    // POST: the posting key signs; a record already present is skipped; refused once insolvent.
    const uint64_t id = TokenKeysetID(ks.vKey);
    CTokenKeyset rk;
    rk.nHeight = 1000;
    rk.vchPostingPubKey = ks.vchPostingPubKey;
    rk.vKey = ks.vKey;
    rec.keyset[{5, id}] = rk;
    const TestMint::Token t = mint.Issue(1, "p1"), u = mint.Issue(0, "p2");
    NoteTokenPost post;
    post.nHouseID = 5;
    post.nKeysetID = id;
    post.vIssued = {TokenIssued(V(t.B), 2), TokenIssued(V(u.B), 1)};
    post.vSpent = {TokenYID(u.Y)};
    CMutableTransaction mp = NoteOpTx(NOTE_OP_TOKEN_POST);
    BOOST_REQUIRE(keyPost.Sign(TokenPostSigHash(C1With(mp, &CMutableTransaction::vchNotePayload, post)), post.vchSig));
    SetPayload(mp, post);
    rec.issued[{5, V(u.B)}] = CTokenMark();   // already posted
    eff = TokenEffects();
    BOOST_CHECK_EQUAL(Run(mp, 1010, GetOpen, rec, &eff), "OK");
    BOOST_CHECK_EQUAL(eff.mapIssued.size(), 1U);
    BOOST_CHECK_EQUAL(eff.mapSpent.size(), 1U);
    BOOST_CHECK_EQUAL(Run(mp, f.E, f.Get(), rec), "bad-token-post-house-status");
    // an amount the keyset has no key for, and a signature by another key
    NoteTokenPost p2 = post;
    p2.vIssued = {TokenIssued(V(t.B), 4)};
    CMutableTransaction mp2 = NoteOpTx(NOTE_OP_TOKEN_POST);
    BOOST_REQUIRE(keyPost.Sign(TokenPostSigHash(C1With(mp2, &CMutableTransaction::vchNotePayload, p2)), p2.vchSig));
    SetPayload(mp2, p2);
    BOOST_CHECK_EQUAL(Run(mp2, 1010, GetOpen, rec), "bad-token-post-amount");
    BOOST_REQUIRE(f.keyPartner.Sign(TokenPostSigHash(C1With(mp, &CMutableTransaction::vchNotePayload, post)), post.vchSig));
    SetPayload(mp, post);
    BOOST_CHECK_EQUAL(Run(mp, 1010, GetOpen, rec), "bad-token-post-sig");
}

BOOST_AUTO_TEST_CASE(token_collect_pays_a_notes_share)
{
    // After the window: claims 131072 + 65536 + 131072 = 327680 against backing 299000, a materialized pot of 10 ECX
    // over 1,000,000 units (above par, so each unit is paid at par: the note's share).
    FailedHouse f;
    const uint32_t W = Params().GetConsensus().nTokenClaimWindow;
    f.house.status = HOUSE_STATUS_INSOLVENT;
    f.house.nInsolventHeight = f.E;
    f.house.nInsolventUnits = 1000000;
    f.house.amountInsolventPot = 10 * COIN;
    f.house.nInsolventSatsPerGram = 1000;   // gram-notes release: the snapshot's price (1 mg = 1 sat)
    f.house.nTokenUnits = 299000;
    f.house.nTokenClaimed = 327680;
    f.house.nTokenClaims = 3;
    Records rec;
    const CScript payA = CScript() << OP_TRUE << OP_DROP << OP_1, payB = CScript() << OP_2, relay = CScript() << OP_3;
    uint256 y1 = uint256S("01"), y2 = uint256S("02"), y3 = uint256S("03");
    auto C = [](uint64_t a, const CScript& s, uint16_t bps, const CScript& r) {
        CTokenClaim c;
        c.nAmount = a;
        c.vchPayoutScript.assign(s.begin(), s.end());
        c.nFeeBps = bps;
        c.vchRelayerScript.assign(r.begin(), r.end());
        c.nHeight = 1;
        return c;
    };
    rec.claim[{5, y1}] = C(131072, payA, 0, CScript());
    rec.claim[{5, y2}] = C(65536, payA, 0, CScript());
    rec.claim[{5, y3}] = C(131072, payB, 100, relay);
    // one escrow coin of 1 ECX
    Coin escrow;
    escrow.out = CTxOut(COIN, HouseEscrowScript(f.house.houseID));
    escrow.SetHouseEscrow(5);
    const COutPoint outEscrow(uint256S("e5c0"), 0);
    auto fnGetCoin = [&](const COutPoint& o, Coin& c) { if (!(o == outEscrow)) return false; c = escrow; return true; };
    auto Collect = [&](const std::vector<CTxOut>& vPay, CAmount amountChange) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_TOKEN_COLLECT;
        mtx.vin.push_back(CTxIn(outEscrow));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("fee1"), 0)));
        NoteTokenCollect col;
        col.nHouseID = 5;
        col.fEscrowChange = 1;
        col.vY = {y1, y2, y3};
        mtx.vout.push_back(CTxOut(amountChange, HouseEscrowScript(f.house.houseID)));
        for (const CTxOut& o : vPay)
            mtx.vout.push_back(o);
        SetPayload(mtx, col);
        return mtx;
    };
    const std::vector<CTxOut> vPay = {CTxOut(119600, payA), CTxOut(59800, payA), CTxOut(118404, payB), CTxOut(1196, relay)};
    const CAmount due = 119600 + 59800 + 119600;
    TokenEffects eff;
    CHouse out;
    BOOST_CHECK_EQUAL(Run(Collect(vPay, COIN - due), f.E + W, f.Get(), rec, &eff, &out, fnGetCoin), "OK");
    BOOST_CHECK_EQUAL(out.nTokenUnits, 0U);              // 299000 paid exactly, nothing to write off
    BOOST_CHECK_EQUAL(out.nTokenPaid, 299000U);
    BOOST_CHECK_EQUAL(out.nMintedUnits, 701000U);
    BOOST_CHECK_EQUAL(out.nTokenWriteOffHeight, f.E + W); // the last claim was collected
    BOOST_CHECK_EQUAL(out.nTokenWriteOff, 0U);
    BOOST_CHECK_EQUAL(out.nTokenBase, 299000U);
    BOOST_CHECK_EQUAL(eff.mapClaim.size(), 3U);
    // the window must have ended; the payouts are exact; the escrow taken never exceeds what is due
    BOOST_CHECK_EQUAL(Run(Collect(vPay, COIN - due), f.E + W - 1, f.Get(), rec, nullptr, nullptr, fnGetCoin), "bad-token-collect-window-open");
    std::vector<CTxOut> vMore = vPay;
    vMore[0].nValue += 1;
    BOOST_CHECK_EQUAL(Run(Collect(vMore, COIN - due - 1), f.E + W, f.Get(), rec, nullptr, nullptr, fnGetCoin), "bad-token-collect-payout");
    BOOST_CHECK_EQUAL(Run(Collect(vPay, COIN - due - 1), f.E + W, f.Get(), rec, nullptr, nullptr, fnGetCoin), "bad-token-collect-over-entitlement");
    // Backing nobody claimed is not written off (Michael 2026-10-08): with T = 196608 < B = 299000 every claim is paid
    // in full and the rest of the backing stays, like an unclaimed note.
    {
        Records r3;
        r3.claim[{5, y1}] = rec.claim[{5, y1}];
        r3.claim[{5, y2}] = rec.claim[{5, y2}];
        FailedHouse g = f;
        g.house.nTokenClaimed = 196608;
        g.house.nTokenClaims = 2;
        CMutableTransaction m3 = Collect({CTxOut(131072, payA), CTxOut(65536, payA)}, COIN - 196608);
        NoteTokenCollect c3;
        c3.nHouseID = 5;
        c3.fEscrowChange = 1;
        c3.vY = {y1, y2};
        SetPayload(m3, c3);
        CHouse o3;
        BOOST_CHECK_EQUAL(Run(m3, f.E + W, g.Get(), r3, nullptr, &o3, fnGetCoin), "OK");
        BOOST_CHECK_EQUAL(o3.nTokenUnits, 299000U - 196608U);
        BOOST_CHECK_EQUAL(o3.nTokenWriteOffHeight, 0U);
        BOOST_CHECK_EQUAL(o3.nMintedUnits, 1000000U - 196608U);
    }
    // a collected claim can't be collected again
    Records r2 = rec;
    r2.claim[{5, y1}].nCollectHeight = 7;
    BOOST_CHECK_EQUAL(Run(Collect(vPay, COIN - due), f.E + W, f.Get(), r2, nullptr, nullptr, fnGetCoin), "bad-token-collect-collected");
}

BOOST_AUTO_TEST_CASE(escrow_change_undo_leaves_the_till_alone)
{
    // Review H1: an escrow-spending op (note CLAIM, deposit CLAIM, token COLLECT) spends a change coin C and the DEFER
    // till L, and leaves change at vout[0]. Its undo must give back exactly the list before it: C, not L (L lives in
    // vOutReserveLock; listing it twice made a reorged node's pot count it twice).
    CHouse house;
    HousePartner p;
    p.vOutPledge = {COutPoint(uint256S("aa"), 0)};
    house.vPartner.push_back(p);
    const COutPoint C(uint256S("cc"), 1), L(uint256S("11"), 0), other(uint256S("dd"), 2);
    house.vOutReserveLock = {L};
    CMutableTransaction mtx;
    mtx.vin = {CTxIn(C), CTxIn(L), CTxIn(COutPoint(uint256S("fee"), 0))};
    mtx.vout = {CTxOut(1000, CScript() << OP_TRUE), CTxOut(5, CScript() << OP_TRUE)};
    const CTransaction tx(mtx);
    house.vOutEscrowChange = {COutPoint(tx.GetHash(), 0), other};   // the list after the op
    CTxUndo undo;
    for (int i = 0; i < 3; i++) {
        Coin c;
        c.out = CTxOut(100, CScript() << OP_TRUE);
        if (i < 2)
            c.SetHouseEscrow(7);
        undo.vprevout.push_back(c);
    }
    std::vector<COutPoint> vExpect = {C, other};
    std::sort(vExpect.begin(), vExpect.end());
    BOOST_CHECK(EscrowChangeBeforeOp(house, tx, &undo, 0) == vExpect);
}

// S4X-1 (external review of s4, Qwen 3.8 flash #1, 2026-11-23; security High). A token CLAIM is
// bounded against the house's CONFIRMED claim total only (validation.cpp, NOTE_OP_TOKEN_CLAIM). ConnectBlock adds the
// block's claims to the house at the flush and, past UINT64_MAX / 2, stops with state.Error("Token claim totals
// overflow!"): no invalid mark (retried for ever), and TestBlockValidity returns under fJustCheck before the flush, so
// every template carries the claims again. The code relies on "a block's staged claims are bounded by its weight, far
// below the headroom". Issuance records are uncapped (a TOKEN_POST takes 2,000 entries of up to 2^50, no check against
// nTokenUnits), so a house running its own mint can feed claims. This builds a real full claim (64 tokens of 2^50,
// the smallest the shape allows: 1-byte secrets, a 1-byte payout script), finds the highest confirmed total at which
// CheckTokenOperation still accepts it (so it follows whatever bound the fix sets), and checks that a maximum-weight
// block of such claims stays under the flush limit (security 11-23: pin it).
BOOST_AUTO_TEST_CASE(s4x_1_a_blocks_token_claims_stay_under_the_flush_headroom)
{
    FailedHouse f;
    TestMint mint;
    mint.k[MAX_TOKEN_AMOUNT_EXP] = RandScalar();
    const std::vector<TokenKey> vKey = mint.Keys();
    const uint64_t id = TokenKeysetID(vKey);
    Records rec;
    CTokenKeyset ks;
    ks.nHeight = 150;
    ks.vKey = vKey;
    rec.keyset[{f.house.nHouseID, id}] = ks;
    const CScript pay = CScript() << OP_TRUE;
    NoteTokenClaim claim;
    claim.nHouseID = f.house.nHouseID;
    for (size_t i = 0; i < MAX_TOKEN_CLAIM_ENTRIES; i++) {
        const TestMint::Token t = mint.Issue(MAX_TOKEN_AMOUNT_EXP, std::string(1, (char)(i + 1)));
        CTokenMark m;
        m.nHeight = 180;
        m.nKeysetID = id;
        m.nAmount = t.amount;
        rec.issued[{f.house.nHouseID, V(t.B)}] = m;
        claim.vEntry.push_back(Entry(f.house.nHouseID, id, t, pay));
    }
    CMutableTransaction mtx = NoteOpTx(NOTE_OP_TOKEN_CLAIM);
    SetPayload(mtx, claim);
    const uint64_t nSum = (uint64_t)MAX_TOKEN_CLAIM_ENTRIES << MAX_TOKEN_AMOUNT_EXP;
    const int nH = f.E + 1;

    auto fnAt = [&](uint64_t nConfirmed) {
        FailedHouse g = f;
        g.house.nTokenClaimed = nConfirmed;
        return Run(mtx, nH, g.Get(), rec);
    };
    BOOST_REQUIRE_EQUAL(fnAt(0), "OK");
    BOOST_REQUIRE(fnAt(std::numeric_limits<uint64_t>::max()) != "OK");
    // The highest confirmed total the full claim still passes at.
    uint64_t lo = 0, hi = std::numeric_limits<uint64_t>::max();
    while (hi - lo > 1) {
        const uint64_t mid = lo + (hi - lo) / 2;
        if (fnAt(mid) == "OK") lo = mid; else hi = mid;
    }
    const uint64_t nConfirmedMax = lo;
    // The rule exactly (S4X-1, token.h): a full claim passes up to MAX_TOKEN_CLAIM_CONFIRMED_TOTAL - its sum.
    BOOST_CHECK_EQUAL(nConfirmedMax, MAX_TOKEN_CLAIM_CONFIRMED_TOTAL - nSum);
    const uint64_t nFlushLimit = TOKEN_CLAIM_FLUSH_MAX;   // ConnectBlock's claim-total flush

    // On the wire: one P2WPKH fee input and a change output, as a wallet would send it.
    CMutableTransaction wire = mtx;
    wire.vin[0].scriptWitness.stack = {std::vector<unsigned char>(72, 0x30), std::vector<unsigned char>(33, 0x02)};
    wire.vout[0] = CTxOut(1000, CScript() << OP_0 << std::vector<unsigned char>(20, 0x11));
    const int64_t nWeight = GetTransactionWeight(CTransaction(wire));
    const int64_t nFit = ((int64_t)MAX_BLOCK_WEIGHT - 4000) / nWeight;   // 4,000 WU for the header and the coinbase
    const unsigned __int128 nStaged = (unsigned __int128)nFit * nSum;
    const unsigned __int128 nHeadroom = (unsigned __int128)nFlushLimit - nConfirmedMax;
    BOOST_TEST_MESSAGE("S4X-1: payload " << mtx.vchNotePayload.size() << " bytes, " << nWeight << " WU a full claim; "
                       << nFit << " fit in a block; a full claim passes up to a confirmed total of 2^62 x "
                       << (double)nConfirmedMax / (double)((uint64_t)1 << 62) << "; headroom to the flush "
                       << (double)nHeadroom / (double)nSum << " full claims");
    BOOST_CHECK_MESSAGE(nStaged <= nHeadroom,
                        "S4X-1: " << nFit << " full claims of one house fit in a block, past the flush headroom of "
                        << (double)nHeadroom / (double)nSum << ": the block fails every node's connect with state.Error "
                        "and every template carries the claims again");
}

// S4X-1 (security's pin): the gap between the per-claim bound and the flush limit must exceed what a maximum-weight
// block of the SMALLEST claim entries could add, so a later payload change that shrinks entries fails here instead of
// silently reopening the halt. The smallest entry: a 1-byte secret, a 1-byte payout script, no relayer, and a 64-byte
// signature (a real strict-DER one is ~70-72 bytes; shorter takes grinding r and s). Its weight is measured as the
// marginal weight of one more entry in a claim, so no per-tx overhead is counted.
BOOST_AUTO_TEST_CASE(s4x_1_claim_gap_exceeds_a_block_of_the_smallest_entries)
{
    auto weightOf = [](size_t nEntries) {
        NoteTokenClaim claim;
        claim.nHouseID = 1;
        for (size_t i = 0; i < nEntries; i++) {
            TokenClaimEntry e;
            e.nKeysetID = std::numeric_limits<uint64_t>::max();
            e.nAmount = (uint64_t)1 << MAX_TOKEN_AMOUNT_EXP;
            e.vchSecret = std::vector<unsigned char>(1, (unsigned char)(i + 1));
            e.vchB = std::vector<unsigned char>(33, 0x02);
            e.vchC = std::vector<unsigned char>(33, 0x02);
            e.vchE = std::vector<unsigned char>(32, 0x01);
            e.vchS = std::vector<unsigned char>(32, 0x01);
            e.vchPayoutScript = std::vector<unsigned char>(1, OP_TRUE);
            e.nFeeBps = 0;
            e.vchSig = std::vector<unsigned char>(64, 0x30);
            claim.vEntry.push_back(e);
        }
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_TOKEN_CLAIM;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << claim;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
        return GetTransactionWeight(CTransaction(mtx));
    };
    const int64_t nEntryWeight = (weightOf(MAX_TOKEN_CLAIM_ENTRIES) - weightOf(1)) / (int64_t)(MAX_TOKEN_CLAIM_ENTRIES - 1);
    BOOST_REQUIRE(nEntryWeight > 0);
    const unsigned __int128 nPerBlock = (unsigned __int128)(MAX_BLOCK_WEIGHT / nEntryWeight) << MAX_TOKEN_AMOUNT_EXP;
    const unsigned __int128 nGap = (unsigned __int128)TOKEN_CLAIM_FLUSH_MAX - MAX_TOKEN_CLAIM_CONFIRMED_TOTAL;
    BOOST_TEST_MESSAGE("S4X-1: smallest claim entry " << nEntryWeight << " WU; a block of them adds "
                       << (double)nPerBlock / (double)((unsigned __int128)1 << 56) << " x 2^56; the gap is "
                       << (double)nGap / (double)((unsigned __int128)1 << 56) << " x 2^56");
    BOOST_CHECK_MESSAGE(nPerBlock < nGap, "S4X-1: a block of the smallest claim entries (" << nEntryWeight
                        << " WU each) could reach the flush limit: the halt is open again");
}

// #include lines to add at the top of token_tests.cpp:
//   #include <houserate.h>   // CChainClock, CSwapRecord, SwapOpen (S1X-5)
//   #include <issued.h>      // UnitsCheckScope (S1X-5)
//   #include <units.h>       // CUnitsView (S1X-5)

// ---------------------------------------------------------------------------
// S1X-5, token COLLECT (validation.cpp ~6568; security 2026-11-23: Medium). See the note_tests case
// for the gate. COLLECT waits for the token claim window (nTokenClaimWindow, ~4 weeks), far past E + the swap deadline,
// so the gate can't bind here. PINNED (passes on master 71b3558): the window outlasts the deadline, and at the window's
// end a swap still pending does not hold the COLLECT. The house is FailedHouse, never materialized (status Open), so
// this COLLECT would take the snapshot itself.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(s1x_5_token_collect_is_never_held_by_a_swap_past_the_deadline)
{
    BOOST_REQUIRE(g_fClockIsHeightForTests);
    FailedHouse f;
    BOOST_REQUIRE(f.E > 20);
    BOOST_REQUIRE_EQUAL(f.house.status, HOUSE_STATUS_OPEN);
    f.house.nTokenUnits = 299000;
    f.house.nTokenClaimed = 327680;
    f.house.nTokenClaims = 3;
    const uint32_t W = Params().GetConsensus().nTokenClaimWindow;
    const uint32_t D = Params().GetConsensus().GramAt((int)f.E).nSwapDeadlineSecs;
    const uint32_t nWait = (D + 599) / 600;
    const int64_t nDeadline = (int64_t)(f.E - 10) * 600 + D + 234;
    const uint32_t h1 = (uint32_t)((nDeadline - 1) / 600);
    BOOST_REQUIRE_MESSAGE(W > nWait + 1, "S1X-5: the token claim window (" << W << " blocks) no longer outlasts the swap "
                          "deadline (" << nWait << " clock blocks)");

    Records rec;
    const CScript payA = CScript() << OP_TRUE << OP_DROP << OP_1;
    const uint256 y1 = uint256S("01");
    CTokenClaim c;
    c.nAmount = 131072;
    c.vchPayoutScript.assign(payA.begin(), payA.end());
    c.nFeeBps = 0;
    c.nHeight = 1;
    rec.claim[{5, y1}] = c;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_TOKEN_COLLECT;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("fee1"), 0)));
    NoteTokenCollect col;
    col.nHouseID = 5;
    col.fEscrowChange = 0;
    col.vY = {y1};
    mtx.vout.push_back(CTxOut(131072, payA));
    SetPayload(mtx, col);

    auto verdict = [&](int h, bool fSwap) {
        CUnitsView units(nullptr);
        CChainClock clock;
        clock.nHeight = (uint32_t)(h - 1);
        clock.nMonoTime = clock.nActiveTime = (int64_t)h * 600;
        units.Put(ChainClockKey(), clock);
        if (fSwap) {
            CSwapRecord r;
            r.nHouseID = 5;
            r.nUnits = 20000;
            r.nBid0 = 1000;
            r.nDemandHeight = f.E - 10;
            r.nDeadlineActive = nDeadline;
            r.vchPayoutScript = ParseHex("76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac");
            SwapOpen(units, uint256S("5150"), r);
        }
        UnitsCheckScope scope(&units);
        return Run(mtx, h, f.Get(), rec);
    };
    BOOST_CHECK_EQUAL(verdict((int)h1, true), "bad-token-collect-window-open");
    const std::string strControl = verdict((int)(f.E + W), false);
    BOOST_REQUIRE_MESSAGE(strControl != "bad-token-collect-window-open" && strControl != "bad-token-collect-not-insolvent",
                          "S1X-5 setup: the COLLECT stopped before the snapshot site: " + strControl);
    const std::string s = verdict((int)(f.E + W), true);
    BOOST_CHECK_MESSAGE(s.find("-swaps-pending") == std::string::npos, "S1X-5 token COLLECT: a swap still pending "
                        "weeks after the failure held the COLLECT (" + s + ")");
    BOOST_CHECK_EQUAL(s, strControl);
}

// ---------------------------------------------------------------------------
// S1X-27's TOKEN_CLAIM sibling (security 2026-11-25, Medium under S1X-27): a token CLAIM's admission hashes every entry
// of every pooled same-house CLAIM to the curve (PooledTokenClaimSharesY) before the fee check. A probe is refused DoS 0
// and never pays: a copy of a pooled claim's payload on the prober's own fee coin (the entry signatures bind no input),
// or one fresh token. So each probe costs the node the whole pool. Security asked for the time per probe at 1k and 10k
// pooled entries on one insolvent house; the times print with --log_level=message. The regression: a probe's cost must
// not grow with the pool.
// ---------------------------------------------------------------------------

namespace {

struct TokenPoolSetup : public TestChain100Setup {
    sidechain_test::SideDBScope sideDBs;   // ATMP's contextual checks read the house DB (TestingSetup makes none)
    int nNext = 0;
    CKey keyAny;
    std::vector<unsigned char> vchPoint;   // a valid point for the shape check's B_ and C_ (the probes never reach the DLEQ)

    TokenPoolSetup()
    {
        keyAny.MakeNewKey(true);
        vchPoint = V(keyAny.GetPubKey());
    }
    COutPoint TipFee()
    {
        const COutPoint o(uint256S(strprintf("%x", 0xd0000 + ++nNext)), 0);
        const CScript spk = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x0e) << OP_EQUALVERIFY << OP_CHECKSIG;
        pcoinsTip->AddCoin(o, Coin(CTxOut(COIN, spk), chainActive.Height(), false, false, false, uint256()), false);
        return o;
    }
    /** Stage 0 rule A (60e409d): relay checks a claim's house and window first, then hashes its secrets within entries + 32
     *  tries in all. For S1X-27's probes to reach the pool's identity index again, the pooled claims name a live insolvent
     *  house (SeedInsolventHouse5) and their secrets map in one try each (a copied 64-entry claim then fits the budget). */
    bool fOneTrySecrets = false;
    static bool MapsInOneTry(const std::string& str)
    {
        CPubKey Y;
        uint32_t nTries = 1;
        return CashuHashToCurveBudget(std::vector<unsigned char>(str.begin(), str.end()), Y, nTries);
    }
    CHouse SeedInsolventHouse5()
    {
        CHouse house;
        house.nHouseID = 5;
        house.houseID = uint256S("f00d");
        house.nTier = HOUSE_TIER_MULTI_PARTNER;
        house.nThresholdM = 1;
        house.strClassID = "mint";
        house.nDenomMgGold = 1000;
        house.status = HOUSE_STATUS_INSOLVENT;
        house.nNoCureHeight = 1;
        house.nRegisteredHeight = 1;
        HousePartner partner;
        partner.vchPubKey = vchPoint;
        partner.amountPledge = COIN;
        house.vPartner.push_back(partner);
        BOOST_REQUIRE(phousetree->WriteHouse(house));
        BOOST_REQUIRE_MESSAGE(HouseInsolventSince(house, chainActive.Height() + 1) != 0, "S1X-27 setup: house 5 is not insolvent");
        return house;
    }
    /** A shape-valid entry: a 64-character secret like a wallet's (hex of 32 random bytes). */
    TokenClaimEntry Entry64()
    {
        TokenClaimEntry e;
        e.nKeysetID = 1;
        e.nAmount = 1;
        std::string s = HexStr(GetRandHash());
        while (fOneTrySecrets && !MapsInOneTry(s))
            s = HexStr(GetRandHash());
        e.vchSecret.assign(s.begin(), s.end());
        e.vchB = vchPoint;
        e.vchC = vchPoint;
        e.vchE.assign(32, 1);
        e.vchS.assign(32, 2);
        const CScript pay = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 7) << OP_EQUALVERIFY << OP_CHECKSIG;
        e.vchPayoutScript.assign(pay.begin(), pay.end());
        e.vchSig.assign(70, 0x30);
        return e;
    }
    CMutableTransaction ClaimTx(const std::vector<TokenClaimEntry>& v, uint32_t nLockTime)
    {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_TOKEN_CLAIM;
        mtx.nLockTime = nLockTime;
        mtx.vin.push_back(CTxIn(TipFee()));
        mtx.vout.push_back(CTxOut(10000, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 8) << OP_EQUALVERIFY << OP_CHECKSIG));
        NoteTokenClaim c;
        c.nHouseID = 5;
        c.vEntry = v;
        SetPayload(mtx, c);
        return mtx;
    }
    /** Pool claims of 32 entries (security's relay cap, ffe871c: a copied claim must be one relay takes) at house 5 until
     *  the pool holds nEntries; returns them. */
    std::vector<CMutableTransaction> FillPool(size_t nEntries)
    {
        std::vector<CMutableTransaction> v;
        TestMemPoolEntryHelper entry;
        for (size_t n = 0; n < nEntries; n += MAX_TOKEN_CLAIM_ENTRIES_RELAY) {
            std::vector<TokenClaimEntry> ve;
            for (size_t i = 0; i < MAX_TOKEN_CLAIM_ENTRIES_RELAY && n + i < nEntries; i++)
                ve.push_back(Entry64());
            v.push_back(ClaimTx(ve, 0));
            mempool.addUnchecked(v.back().GetHash(), entry.FromTx(v.back()));
        }
        return v;
    }
    /** The median wall time (µs) of nRuns ATMP calls; each probe's verdict goes to *pReason (they must all agree). */
    int64_t MedianProbe(const std::function<CMutableTransaction(int)>& fnProbe, int nRuns, std::string& strReason, int& nDoS)
    {
        std::vector<int64_t> v;
        for (int i = 0; i < nRuns; i++) {
            const CTransactionRef ptx = MakeTransactionRef(fnProbe(i));
            CValidationState state;
            const int64_t t0 = GetTimeMicros();
            const bool fOk = AcceptToMemoryPool(mempool, state, ptx, nullptr, nullptr, true, 0);
            v.push_back(GetTimeMicros() - t0);
            BOOST_REQUIRE_MESSAGE(!fOk, "a probe was accepted");
            state.IsInvalid(nDoS);
            strReason = state.GetRejectReason();
        }
        std::sort(v.begin(), v.end());
        return v[v.size() / 2];
    }
};

} // namespace

BOOST_FIXTURE_TEST_CASE(s1x_27_token_claim_probe_cost_does_not_grow_with_the_pool, TokenPoolSetup)
{
    LOCK(cs_main);
    // One hash to the curve, for scale.
    std::vector<TokenClaimEntry> vRef;
    for (int i = 0; i < 2000; i++)
        vRef.push_back(Entry64());
    const int64_t tHash0 = GetTimeMicros();
    for (const TokenClaimEntry& e : vRef) {
        CPubKey Y;
        BOOST_REQUIRE(CashuHashToCurve(e.vchSecret, Y));
    }
    const double dHash = double(GetTimeMicros() - tHash0) / vRef.size();
    BOOST_TEST_MESSAGE(strprintf("S1X-27 token: one hash to the curve %.1f us", dHash));
    // Stage 0 rule A: a live insolvent house 5 and one-try secrets, so the probes pass the house, window and try-budget
    // checks and reach the pool's identity index (with house 5 unknown they stopped at the house, and this test no
    // longer saw the index at all).
    SeedInsolventHouse5();
    fOneTrySecrets = true;

    const int RUNS = 9;
    std::string strReason;
    int nDoS = -1;
    uint32_t nLock = 1;
    // Probe B: one fresh token. It shares nothing, so the scan visits every pooled claim before the token checks (the
    // keyset is unknown, so those fail at once: the time is the scan).
    auto fnFresh = [&](int) { return ClaimTx({Entry64()}, nLock++); };
    const int64_t tFresh0 = MedianProbe(fnFresh, RUNS, strReason, nDoS);
    BOOST_TEST_MESSAGE(strprintf("S1X-27 token: fresh-token probe, empty pool: %d us (%s, DoS %d)", tFresh0, strReason, nDoS));

    size_t nPooled = 0;
    std::vector<CMutableTransaction> vPooled;
    int64_t tFresh10k = 0;
    for (const size_t nTarget : {size_t(1024), size_t(10048)}) {
        const std::vector<CMutableTransaction> vMore = FillPool(nTarget - nPooled);
        vPooled.insert(vPooled.end(), vMore.begin(), vMore.end());
        nPooled = nTarget;
        const int64_t tFresh = MedianProbe(fnFresh, RUNS, strReason, nDoS);
        BOOST_TEST_MESSAGE(strprintf("S1X-27 token: %u pooled entries (%u claims): fresh-token probe %d us (%s, DoS %d)",
                                     nPooled, vPooled.size(), tFresh, strReason, nDoS));
        // Probe A: a pooled claim's payload on the prober's own coin with a fresh nLockTime (where the scan stops depends
        // on where the copied claim sits in the pool).
        auto fnCopy = [&](int i) {
            CMutableTransaction m = vPooled[(i * 7919) % vPooled.size()];
            m.vin[0] = CTxIn(TipFee());
            m.nLockTime = nLock++;
            return m;
        };
        const int64_t tCopy = MedianProbe(fnCopy, RUNS, strReason, nDoS);
        BOOST_TEST_MESSAGE(strprintf("S1X-27 token: %u pooled entries: copy probe %d us (%s, DoS %d)", nPooled, tCopy,
                                     strReason, nDoS));
        BOOST_CHECK_EQUAL(strReason, "token-claim-pending");
        BOOST_CHECK_EQUAL(nDoS, 0);
        if (nTarget == 10048)
            tFresh10k = tFresh;
    }
    // The fix (security: the pool's identity index) makes a probe one lookup per entry it carries. Allow it 5% of what
    // hashing the pool costs on this machine, on top of the empty-pool probe.
    const double dPoolHash = 10048 * dHash;
    BOOST_CHECK_MESSAGE(tFresh10k - tFresh0 < 0.05 * dPoolHash,
            strprintf("S1X-27 token: a free probe at 10,048 pooled entries costs %d us more than at none (hashing the "
                      "pool: %.0f us); the scan grows with the pool", tFresh10k - tFresh0, dPoolHash));
}

// ===========================================================================
// testing (2026-11-26, Stage 0 family A, after security's TOKEN_CLAIM relay ruling in ffe871c): the costliest refused
// claim a token HOLDER can send. A holder of 32 real tokens of an insolvent house (in its claim window) signs every entry
// under P = B_ - Y, and gives the last entry a wrong DLEQ proof. Relay hashes the 32 secrets (one-try here; up to 96 tries
// in all), reads four records an entry, and CheckTokenOperation verifies 32 holder signatures and 31 DLEQs before the
// 32nd DLEQ fails (bad-token-claim-dleq, DoS 100 in the code, re-scored 0 on the mempool path by MempoolRefusalScoresZero
// unless marked state-independent). The DLEQ cache keeps successes across calls, so the FIRST probe pays the 31 DLEQs and
// each repeat with a fresh payout script (new holder sighashes, re-signed by the holder) pays the 32 signatures again.
// Security ruled 11-26 (appended to its family-rules note): a token holder's signature has no standing, and
// bad-token-claim-sig, -dleq and -proof score DoSStateIndependent(100) - each is pure in the tx and the keyset its id
// names - so a probe costs its sender the connection. Checked here: the refusal scores 100 (FAILS until that lands).
// The cost is reported. The control: the same claim with the right proof is accepted.
// ===========================================================================
BOOST_FIXTURE_TEST_CASE(family_a_cost_token_claim_holder_last_dleq_wrong, TokenPoolSetup)
{
    LOCK(cs_main);
    CHouse house = SeedInsolventHouse5();
    TestMint mint;
    mint.k[0] = RandScalar();   // amount 1
    const std::vector<TokenKey> vKey = mint.Keys();
    const uint64_t id = TokenKeysetID(vKey);
    CTokenKeyset ks;
    ks.nHeight = 0;
    ks.vchPostingPubKey = vchPoint;
    ks.vKey = vKey;
    TokenEffects eff;
    eff.mapKeyset[std::make_pair((uint32_t)5, id)] = ks;
    std::vector<TestMint::Token> vTok;
    while (vTok.size() < MAX_TOKEN_CLAIM_ENTRIES_RELAY) {
        const std::string str = HexStr(GetRandHash());
        if (!MapsInOneTry(str))
            continue;
        vTok.push_back(mint.Issue(0, str));
        CTokenMark m;
        m.nHeight = 0;
        m.nKeysetID = id;
        m.nAmount = vTok.back().amount;
        eff.mapIssued[std::make_pair((uint32_t)5, V(vTok.back().B))] = m;
    }
    BOOST_REQUIRE(phousetree->WriteBlockEffects({house}, nullptr, chainActive.Tip()->GetBlockHash(), nullptr, &eff, nullptr));

    CKey keyFund;
    keyFund.MakeNewKey(true);
    CBasicKeyStore ksFund;
    ksFund.AddKey(keyFund);
    const CScript spkFund = GetScriptForDestination(keyFund.GetPubKey().GetID());
    auto fnFund = [&]() {
        const COutPoint o(uint256S(strprintf("%x", 0xdd0000 + ++nNext)), 0);
        pcoinsTip->AddCoin(o, Coin(CTxOut(COIN, spkFund), chainActive.Height(), false, false, false, uint256()), false);
        return o;
    };
    auto fnProbe = [&](bool fBadLast) {
        const uint256 r = GetRandHash();
        const CScript pay = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(r.begin(), r.begin() + 20)
                                      << OP_EQUALVERIFY << OP_CHECKSIG;   // fresh: every holder sighash is new
        std::vector<TokenClaimEntry> v;
        for (const TestMint::Token& t : vTok)
            v.push_back(Entry(5, id, t, pay));
        if (fBadLast)
            v.back().vchS[31] ^= 1;   // the proof's s: the holder's signature doesn't cover it
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_TOKEN_CLAIM;
        mtx.vin.push_back(CTxIn(fnFund()));
        mtx.vout.push_back(CTxOut(10000, pay));
        NoteTokenClaim c;
        c.nHouseID = 5;
        c.vEntry = v;
        SetPayload(mtx, c);
        BOOST_REQUIRE(SignSignature(ksFund, spkFund, mtx, 0, COIN, SIGHASH_ALL));
        return mtx;
    };
    std::vector<int64_t> vT;
    std::string strReason;
    int nDoS = -1;
    size_t nBytes = 0;
    for (int i = 0; i < 8; i++) {
        const CTransactionRef ptx = MakeTransactionRef(fnProbe(true));
        nBytes = ::GetSerializeSize(*ptx, SER_NETWORK, PROTOCOL_VERSION);
        CValidationState state;
        const int64_t t0 = GetTimeMicros();
        const bool fOk = AcceptToMemoryPool(mempool, state, ptx, nullptr, nullptr, false, 0);
        vT.push_back(GetTimeMicros() - t0);
        BOOST_REQUIRE_MESSAGE(!fOk, "the holder probe was accepted");
        strReason = state.GetRejectReason();
        nDoS = 0;
        state.IsInvalid(nDoS);
        BOOST_CHECK_EQUAL(strReason, "bad-token-claim-dleq");
    }
    BOOST_CHECK_MESSAGE(nDoS == 100, strprintf("family A (security 11-26): a holder's claim refused at %s scored DoS %d, "
                                               "not 100; the refusal is state-independent and must ban", strReason, nDoS));
    const int64_t tCold = vT[0];
    std::vector<int64_t> vWarm(vT.begin() + 1, vT.end());
    std::sort(vWarm.begin(), vWarm.end());
    // The plain baseline of the same size and shape: an owned signed fund, then an unowned coin, refused at the second
    // input's script (family_a_cost_tests' PlainMin).
    std::vector<int64_t> vPlain;
    for (int i = 0; i < 7; i++) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.push_back(CTxIn(fnFund()));
        mtx.vin.push_back(CTxIn(TipFee()));
        const size_t nOut = std::max<size_t>(1, nBytes / 34);
        for (size_t j = 0; j < nOut; j++)
            mtx.vout.emplace_back(COIN / 2 / nOut, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x0b)
                                                             << OP_EQUALVERIFY << OP_CHECKSIG);
        BOOST_REQUIRE(SignSignature(ksFund, spkFund, mtx, 0, COIN, SIGHASH_ALL));
        CValidationState state;
        const CTransactionRef ptx = MakeTransactionRef(std::move(mtx));
        const int64_t t0 = GetTimeMicros();
        AcceptToMemoryPool(mempool, state, ptx, nullptr, nullptr, false, 0);
        vPlain.push_back(GetTimeMicros() - t0);
    }
    const int64_t tPlain = *std::min_element(vPlain.begin(), vPlain.end());
    BOOST_TEST_MESSAGE(strprintf("family A cost: note TOKEN_CLAIM, a holder's 32 real tokens, the last DLEQ wrong (%u bytes): "
                                 "first probe %d us (%d over plain), repeats with a fresh payout %d us min, %d us median (%d "
                                 "over plain); plain %d us; refused %s, DoS %d (no standing: must score 100)", (unsigned)nBytes, tCold, tCold - tPlain, vWarm.front(),
                                 vWarm[vWarm.size() / 2], vWarm.front() - tPlain, tPlain, strReason, nDoS));
    // The control: the same claim with every proof right is accepted (so the probe was valid up to the last DLEQ).
    {
        CValidationState state;
        const bool fOk = AcceptToMemoryPool(mempool, state, MakeTransactionRef(fnProbe(false)), nullptr, nullptr, false, 0);
        BOOST_CHECK_MESSAGE(fOk, "holder probe control: the claim with the right proofs was refused: " + state.GetRejectReason());
    }
    mempool.clear();
}

// Security's second question (not rated): a zero-fee CLAIM of 64 real tokens runs the token checks (DLEQ, signatures)
// before ATMP's fee check refuses it, DoS 0. The cost per probe is flat; this measures it.
BOOST_AUTO_TEST_CASE(s1x_27_token_claim_dleq_cost_of_a_64_token_claim)
{
    FailedHouse f;
    TestMint mint;
    mint.k[16] = RandScalar();
    const std::vector<TokenKey> vKey = mint.Keys();
    const uint64_t id = TokenKeysetID(vKey);
    Records rec;
    CTokenKeyset ks;
    ks.nHeight = 150;
    ks.vKey = vKey;
    rec.keyset[{f.house.nHouseID, id}] = ks;
    const CScript pay = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 7) << OP_EQUALVERIFY << OP_CHECKSIG;
    std::vector<TokenClaimEntry> v;
    for (size_t i = 0; i < MAX_TOKEN_CLAIM_ENTRIES; i++) {
        const TestMint::Token t = mint.Issue(16, HexStr(GetRandHash()));
        CTokenMark m;
        m.nHeight = 180;
        m.nKeysetID = id;
        m.nAmount = t.amount;
        rec.issued[{f.house.nHouseID, V(t.B)}] = m;
        v.push_back(Entry(f.house.nHouseID, id, t, pay));
    }
    CMutableTransaction mtx = NoteOpTx(NOTE_OP_TOKEN_CLAIM);
    NoteTokenClaim c;
    c.nHouseID = f.house.nHouseID;
    c.vEntry = v;
    SetPayload(mtx, c);
    const CTransaction tx(mtx);
    std::vector<int64_t> vT;
    for (int i = 0; i < 7; i++) {
        CValidationState state;
        TokenEffects eff;
        CHouse out;
        bool fChanged = false;
        const int64_t t0 = GetTimeMicros();
        const bool fOk = CheckTokenOperation(tx, state, f.E + 1, f.Get(), [](const COutPoint&, Coin&) { return false; },
                                             rec.View(), eff, out, fChanged, true);
        vT.push_back(GetTimeMicros() - t0);
        BOOST_REQUIRE_MESSAGE(fOk, "the 64-token claim must pass the token checks: " + state.GetRejectReason());
    }
    std::sort(vT.begin(), vT.end());
    BOOST_TEST_MESSAGE(strprintf("S1X-27 token: CheckTokenOperation on a 64-token claim: median %d us (%.1f us a token)",
                                 vT[vT.size() / 2], double(vT[vT.size() / 2]) / MAX_TOKEN_CLAIM_ENTRIES));
}

// S1X-27 (security's sibling, Medium): a pooled token CLAIM is keyed per token by (house, Y id), computed once at add, so
// the claim guard is one lookup per token instead of a decode and up to 64 hash-to-curve per pooled claim per arrival.
BOOST_AUTO_TEST_CASE(s1x_27_token_claim_identity_keys)
{
    auto fnClaim = [](uint32_t nHouseID, const std::vector<std::string>& vSecret, uint32_t nLockTime) {
        NoteTokenClaim claim;
        claim.nHouseID = nHouseID;
        for (const std::string& str : vSecret) {
            TokenClaimEntry e;
            e.vchSecret = std::vector<unsigned char>(str.begin(), str.end());
            claim.vEntry.push_back(e);
        }
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_TOKEN_CLAIM;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << claim;
        mtx.vchNotePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("07"), 0)));
        mtx.nLockTime = nLockTime;
        return CTransaction(mtx);
    };
    const CTransaction txA = fnClaim(3, {"secret-a", "secret-b"}, 0);
    const CTransaction txCopy = fnClaim(3, {"secret-b"}, 5);          // shares secret-b at the same house
    const CTransaction txOtherHouse = fnClaim(4, {"secret-b"}, 0);    // the same token at another house
    const CTransaction txFresh = fnClaim(3, {"secret-c"}, 0);
    std::vector<uint256> vA, vCopy, vOther, vFresh;
    PooledIdentityKeys(txA, vA);
    PooledIdentityKeys(txCopy, vCopy);
    PooledIdentityKeys(txOtherHouse, vOther);
    PooledIdentityKeys(txFresh, vFresh);
    BOOST_REQUIRE_EQUAL(vA.size(), 2u);
    BOOST_REQUIRE_EQUAL(vCopy.size(), 1u);
    BOOST_CHECK(std::find(vA.begin(), vA.end(), vCopy[0]) != vA.end());

    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    {
        LOCK(pool.cs);
        pool.addUnchecked(txA.GetHash(), entry.FromTx(txA));
    }
    BOOST_CHECK(pool.HaveIdentityKey(vCopy));     // token-claim-pending
    BOOST_CHECK(!pool.HaveIdentityKey(vOther));   // another house's claim of that Y is not a conflict here
    BOOST_CHECK(!pool.HaveIdentityKey(vFresh));
    std::set<uint256> setY;
    uint32_t nHouse = 0;
    BOOST_REQUIRE(TokenClaimYs(txCopy, nHouse, setY));
    BOOST_CHECK(pool.HaveIdentityKey({TokenClaimIdentityKey(nHouse, *setY.begin())}));
    pool.removeRecursive(txA);
    BOOST_CHECK(!pool.HaveIdentityKey(vCopy));
}


// Security 11-25 (the DLEQ-before-fee Medium): FbVerifyDLEQ is CashuVerifyDLEQ outside an FbSigCacheScope, and inside
// one it remembers only DLEQs that verified: a valid one passes twice, a forged one fails every time (never cached).
BOOST_AUTO_TEST_CASE(dleq_cache_remembers_only_valid_checks)
{
    TestMint mint;
    mint.k[0] = RandScalar();
    const TestMint::Token t = mint.Issue(0, "dleq-cache-secret");
    const CPubKey A = MulG(mint.k[0]);
    CashuScalar sBad = t.s;
    sBad[31] ^= 1;
    BOOST_CHECK(!FbSigCacheScopeOpen());
    BOOST_CHECK(FbVerifyDLEQ(A, t.B, t.C_, t.e, t.s));
    BOOST_CHECK(!FbVerifyDLEQ(A, t.B, t.C_, t.e, sBad));
    {
        FbSigCacheScope scope;
        BOOST_CHECK(FbVerifyDLEQ(A, t.B, t.C_, t.e, t.s));      // verified, then remembered
        BOOST_CHECK(FbVerifyDLEQ(A, t.B, t.C_, t.e, t.s));      // from the cache
        BOOST_CHECK(!FbVerifyDLEQ(A, t.B, t.C_, t.e, sBad));    // a forgery is never remembered
        BOOST_CHECK(!FbVerifyDLEQ(A, t.B, t.C_, t.e, sBad));
        BOOST_CHECK(!FbVerifyDLEQ(A, t.C_, t.B, t.e, t.s));     // the key binds the points' roles
    }
    BOOST_CHECK(!FbVerifyDLEQ(A, t.B, t.C_, t.e, sBad));         // and outside the scope: the plain check
}

// S1X-36 (testing 2026-11-26; Claude max run 4 #6; security 11-26: Medium, Low if well under 1 ms a probe). The cost of
// the context-free TOKEN_POST shape check a peer makes a node pay before any input, fee or standardness check: every
// vIssued key is parsed in full (IsFullyValid). Measures CheckTransaction on a valid-shape post with
// MAX_TOKEN_POST_ENTRIES distinct keys. A measurement, not a pass/fail gate: it prints the median.
BOOST_AUTO_TEST_CASE(s1x_36_token_post_shape_parse_cost)
{
    NoteTokenPost post;
    post.nHouseID = 1;
    post.nKeysetID = 1;
    for (size_t i = 0; i < MAX_TOKEN_POST_ENTRIES; i++) {
        CKey k;
        k.MakeNewKey(true);
        const CPubKey pub = k.GetPubKey();
        post.vIssued.emplace_back(std::vector<unsigned char>(pub.begin(), pub.end()), 1);
    }
    post.vchSig.assign(70, 0x30);
    CMutableTransaction mtx = NoteOpTx(NOTE_OP_TOKEN_POST);
    SetPayload(mtx, post);
    const CTransaction tx(mtx);
    std::vector<int64_t> vT;
    std::string strReason;
    for (int i = 0; i < 9; i++) {
        CValidationState state;
        const int64_t t0 = GetTimeMicros();
        const bool fOk = CheckTransaction(tx, state);
        vT.push_back(GetTimeMicros() - t0);
        strReason = fOk ? "passes" : state.GetRejectReason();
    }
    std::sort(vT.begin(), vT.end());
    BOOST_TEST_MESSAGE(strprintf("S1X-36 TOKEN_POST: CheckTransaction on %u keys (%u bytes, %s): median %d us (%.2f us a key)",
                                 (unsigned)MAX_TOKEN_POST_ENTRIES, (unsigned)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION),
                                 strReason, vT[vT.size() / 2], double(vT[vT.size() / 2]) / MAX_TOKEN_POST_ENTRIES));
    BOOST_CHECK_EQUAL(strReason, "passes");
}

// ===========================================================================
// testing (2026-11-26): S1X-37 (Claude max run 4 #7; security 11-26 Medium, policy; fix 2db1f65 on mb/s1x-33, freebankd's
// suggested test). A settle NET has no house cap, and ATMP read every named house's record, rates and par eligibility
// before the first approver check and before any fee floor, refusing at DoS 0, so a zero-fee round could be re-sent
// with a new nLockTime for ever. The fix: a NET naming more than 100 houses is refused nonstandard before any house is
// read, and a settle tx meets the S1X-30 early fee floor first. Probes are NET rings (house i presents house i+1, the
// last the first) of real note coins on the presenters' keys, so they pass CheckTransaction and the NET input layer;
// the houses don't exist, so anything that reads one refuses with a house reason.
// FAILS on master 7f65d2e (both probes reach the house reads); passes on mb/s1x-33 2db1f65.
// ===========================================================================
namespace {
CMutableTransaction Run4NetRing(TokenPoolSetup& s, size_t H, CAmount nFee)
{
    SettleNet n;
    std::vector<std::vector<unsigned char>> vKey;
    CBasicKeyStore keystore;   // Stage 0 rule A step 2: the first note input is signed (below)
    for (size_t i = 0; i < H; i++) {
        CKey k;
        k.MakeNewKey(true);
        keystore.AddKey(k);
        vKey.push_back(V(k.GetPubKey()));
        n.vHouseID.push_back((uint32_t)(i + 900001));
        n.vReceive.push_back(0);
        n.vPrevMintedUnits.push_back(1000000);
        n.vPrevLastSettleHeight.push_back(0);
        n.vPresentKey.push_back(vKey.back());
        n.vPresentSig.push_back(std::vector<unsigned char>(70, 0x30));
        n.vApproverIndex.push_back({0});
        n.vApproverSig.push_back({std::vector<unsigned char>(70, 0x30)});
    }
    for (size_t i = 0; i < H; i++) {
        SettleNetBundle b;
        b.nPresenter = (uint32_t)(i + 900001);
        b.nIssuer = (uint32_t)((i + 1) % H + 900001);
        b.nUnits = 1000;
        b.nCount = 1;
        n.vBundle.push_back(b);
    }
    std::sort(n.vBundle.begin(), n.vBundle.end(), [](const SettleNetBundle& a, const SettleNetBundle& b) {
        return a.nPresenter != b.nPresenter ? a.nPresenter < b.nPresenter : a.nIssuer < b.nIssuer;
    });
    n.nExpiryHeight = 0;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_SETTLE_VERSION;
    mtx.nSettleOp = SETTLE_OP_NET;
    CAmount nIn = 0;
    std::vector<CScript> vInScript;
    for (const SettleNetBundle& b : n.vBundle) {
        const COutPoint o(uint256S(strprintf("%x", 0x37000000 + ++s.nNext)), 0);
        vInScript.push_back(NoteScriptForPubKey(vKey[b.nPresenter - 900001]));
        Coin coin(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vKey[b.nPresenter - 900001])), chainActive.Height(), false,
                  false, false, uint256());
        coin.SetNote(b.nIssuer, b.nUnits);
        pcoinsTip->AddCoin(o, std::move(coin), false);
        mtx.vin.push_back(CTxIn(o));
        nIn += NOTE_DUST_VALUE;
    }
    mtx.vin.push_back(CTxIn(s.TipFee()));   // plain funding after the bundles: 1 coin
    nIn += COIN;
    mtx.vout.emplace_back(nIn - nFee, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x37)
                                                << OP_EQUALVERIFY << OP_CHECKSIG);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << n;
    mtx.vchSettlePayload.assign(ss.begin(), ss.end());
    // Stage 0 rule A step 2 (60e409d): after the floor ATMP verifies the first signature-bearing input's script before
    // any FreeBank check. The prober owns its coins, so that input is signed (the rest stay unsigned: refused last), and
    // the probe reaches the settle checks S1X-37 is about.
    BOOST_REQUIRE(SignSignature(keystore, vInScript[0], mtx, 0, NOTE_DUST_VALUE, SIGHASH_ALL));
    return mtx;
}

std::string Run4Atmp(const CMutableTransaction& mtx, int& nDoS)
{
    CValidationState state;
    const bool fOk = AcceptToMemoryPool(mempool, state, MakeTransactionRef(mtx), nullptr, nullptr, false, 0);
    nDoS = -1;
    state.IsInvalid(nDoS);
    return fOk ? std::string("ACCEPTED") : state.GetRejectReason();
}
} // namespace

BOOST_FIXTURE_TEST_CASE(s1x_37_settle_net_probes_are_refused_before_any_house_is_read, TokenPoolSetup)
{
    LOCK(cs_main);
    int nDoS = -1;
    // Controls: the probes are well formed up to the house reads.
    {
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(CheckTransaction(CTransaction(Run4NetRing(*this, 101, 20000)), state),
                              "S1X-37 setup: the 101-house NET ring fails CheckTransaction: " + state.GetRejectReason());
    }
    // A NET naming 101 houses, paying a normal fee: refused nonstandard, before any house is read.
    std::string r = Run4Atmp(Run4NetRing(*this, 101, 20000), nDoS);
    BOOST_CHECK_MESSAGE(r == "settle-net-too-many-houses",
                        "S1X-37: a NET naming 101 houses was refused \"" + r + "\" (DoS " + std::to_string(nDoS) +
                        "), not as too many houses before the house reads");
    // A zero-fee NET of three houses: refused at the fee floor, before any house is read.
    r = Run4Atmp(Run4NetRing(*this, 3, 0), nDoS);
    BOOST_CHECK_MESSAGE(r == "min relay fee not met" || r == "mempool min fee not met",
                        "S1X-37: a zero-fee NET was refused \"" + r + "\" (DoS " + std::to_string(nDoS) +
                        "), not at the fee floor before the house reads");
    // And a 100-house NET with a fee is not refused for its size (it reaches the house reads, past the early script check).
    r = Run4Atmp(Run4NetRing(*this, 100, 20000), nDoS);
    BOOST_CHECK_MESSAGE(r != "settle-net-too-many-houses" && r.find("mandatory-script-verify-flag-failed") != 0,
                        "S1X-37 control: a 100-house NET was refused \"" + r + "\", not at the house reads");
}

// ===========================================================================
// testing (2026-11-26): family A, Stage 0 (Michael 11-26 via the telegram session: a testing regime with a defined end,
// one daemon-wide rule per bug family; freebankd takes the fix, security's wording in note
// 2026-11-26-from-security-family-rules: "until the fee floor is met and the authorizing signature verifies, the node
// does byte-shape work only"). The bypass test: a zero-fee op of each FreeBank tx family, well-formed up to its contextual
// checks (shape-valid, inputs that pass the input layer, records that don't exist), must be refused AT THE FEE FLOOR,
// before any contextual read. S1X-30 and S1X-37 did this for TOKEN_CLAIM and settle only; ATMP runs the bill, house, note,
// deposit and pool checks (validation.cpp ~2419-2715) before the normal fee checks (~2857). FAILS on master for every family
// not yet covered; passes once freebankd's one early floor covers every FreeBank op version.
// ===========================================================================
namespace {
std::string Run4FeeProbe(TokenPoolSetup& s, CMutableTransaction mtx, const std::vector<std::pair<COutPoint, Coin>>& vCoin)
{
    CAmount nIn = 0;
    for (const auto& c : vCoin) {
        pcoinsTip->AddCoin(c.first, Coin(c.second), true);
        mtx.vin.push_back(CTxIn(c.first));
        nIn += c.second.out.nValue;
    }
    const COutPoint fee = s.TipFee();
    mtx.vin.push_back(CTxIn(fee));
    nIn += COIN;
    CAmount nOut = 0;
    for (const CTxOut& o : mtx.vout)
        nOut += o.nValue;
    mtx.vout.emplace_back(nIn - nOut, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xa0)
                                                << OP_EQUALVERIFY << OP_CHECKSIG);   // zero fee: everything back
    int nDoS = -1;
    return Run4Atmp(mtx, nDoS);
}
template <typename T>
std::vector<unsigned char> Run4Ser(const T& x)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << x;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}
COutPoint Run4Out(TokenPoolSetup& s) { return COutPoint(uint256S(strprintf("%x", 0xa1000000 + ++s.nNext)), 0); }
bool Run4IsFeeFloor(const std::string& r) { return r == "min relay fee not met" || r == "mempool min fee not met"; }
} // namespace

BOOST_FIXTURE_TEST_CASE(family_a_zero_fee_ops_are_refused_at_the_fee_floor_first, TokenPoolSetup)
{
    LOCK(cs_main);
    CKey key;
    key.MakeNewKey(true);
    const std::vector<unsigned char> vchKey = V(key.GetPubKey());
    std::vector<std::pair<std::string, std::string>> vResult;

    // note: a TRANSFER of 1,000 units of house 900099 (no such house).
    {
        NoteTransfer t;
        t.nHouseID = 900099;
        t.vUnits = {1000};
        t.nDemandHeight = 0;
        t.vchSenderPubKey = vchKey;
        t.vchSenderSig.assign(70, 0x30);
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_TRANSFER;
        mtx.vchNotePayload = Run4Ser(t);
        mtx.vout.emplace_back(NOTE_DUST_VALUE, NoteScriptForPubKey(vchKey));
        Coin c(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchKey)), chainActive.Height(), false, false, false, uint256());
        c.SetNote(900099, 1000);
        vResult.emplace_back("note TRANSFER", Run4FeeProbe(*this, mtx, {{Run4Out(*this), c}}));
    }
    // house: a rate POST by house 900099.
    {
        HouseRate r;
        r.nHouseID = 900099;
        r.nKind = HOUSE_RATE_POST;
        r.nBid = 100000;
        r.nAsk = 100000;
        r.vchRateSig.assign(70, 0x30);
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_RATE;
        mtx.vchHousePayload = Run4Ser(r);
        vResult.emplace_back("house rate POST", Run4FeeProbe(*this, mtx, {}));
    }
    // bill: a RETIRE of bill 900099 (no such bill), spending a bill-escrow coin of that id.
    {
        BillRetire r;
        r.nBillID = 900099;
        r.vchAcceptorSig.assign(70, 0x30);
        r.nRateNamed = 1000;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_RETIRE;
        mtx.vchBillPayload = Run4Ser(r);
        mtx.vout.emplace_back(10000, BillScriptForPubKey(vchKey));
        Coin c(CTxOut(20000, BillEscrowScript(uint256S("b9"))), chainActive.Height(), false, false, false, uint256());
        c.SetBill(true, 900099);
        vResult.emplace_back("bill RETIRE", Run4FeeProbe(*this, mtx, {{Run4Out(*this), c}}));
    }

    // deposit: a WITHDRAW of a 50,000-unit receipt of house 900099 (no such house).
    {
        DepositWithdraw w;
        w.nHouseID = 900099;
        w.vchHolderPubKey = vchKey;
        w.vchHolderSig.assign(70, 0x30);
        w.nRateNamed = 1000;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_DEPOSIT_VERSION;
        mtx.nDepositOp = DEPOSIT_OP_WITHDRAW;
        mtx.vchDepositPayload = Run4Ser(w);
        Coin c(CTxOut(NOTE_DUST_VALUE, DepositScriptForPubKey(vchKey)), chainActive.Height(), false, false, false, uint256());
        c.SetDeposit(900099, 50000, 500, (uint32_t)chainActive.Height(), 1);
        vResult.emplace_back("deposit WITHDRAW", Run4FeeProbe(*this, mtx, {{Run4Out(*this), c}}));
    }

    for (const auto& r : vResult) {
        BOOST_TEST_MESSAGE("family A probe: zero-fee " + r.first + " -> " + r.second);
        BOOST_CHECK_MESSAGE(Run4IsFeeFloor(r.second), "family A: a zero-fee " + r.first + " was refused \"" + r.second +
                                                      "\", not at the fee floor before its contextual checks");
    }
}

BOOST_AUTO_TEST_SUITE_END()
