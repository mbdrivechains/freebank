// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ===========================================================================
// testing (2026-11-26): family A cost measurement, Stage 0 (D-2026-11-26-1). Security's test for rule A (note
// 2026-11-26-from-security-family-rules): "for each op type, the costliest refused tx of maximum standard size costs
// under 1 ms of node time, measured". freebankd asked for it on mb/stage0-a (A part 2): the op types that are over.
//
// How the probes are built (testing's cost map, gateway docs/testing/families/A-cost-map-2026-11-26.md):
//  - The fee floor is met by input VALUES (CheckTxInputs); input scripts are verified last (CheckInputs, after every
//    FreeBank check), so the floor proves nothing (security agreed 11-26 and added an early check: the first non-family
//    input's script right after the floor). Each probe's funding coin is the test's own, signed last by Time(), so it
//    passes that check and reaches the FreeBank work; a probe that is otherwise valid also carries an unowned coin with an
//    empty scriptSig, so it is refused last, at CheckInputs.
//  - Security's rulings 11-26: the line is the cost above a plain tx of the same size; work after a signature with
//    standing (a registered house's key or approvers) doesn't count, but a refusal there that doesn't depend on chain
//    state must score DoS 100; REGISTER counts; TOKEN_CLAIM relay spends a budget of entries + 32 hash-to-curve tries.
//  - Input-script ECDSA grows with the input count on every version (Bitcoin's own cost, scored DoS 100), so probes
//    carry one funding input and max the payload, except where the FreeBank work itself grows with the inputs.
//  - Every timed run is a first submission: fresh coins and fresh payload signatures, so no signature cache helps.
//  - Each probe reports min and median microseconds over its runs. The 1 ms line is checked on the min (the least
//    noisy on a shared machine) LESS a plain v2 tx of the same size (one funding coin, P2PKH outputs, refused at its
//    input script): a plain 100,000-byte tx alone costs ~0.85 ms here, so the line is read as the FreeBank work.
//    Probes whose cost grows with inputs subtract a plain tx with the same inputs instead.
// The side DBs are in memory here (SideDBScope), so DB-read costs are a floor: a real node reads LevelDB.
// ===========================================================================

#include <bill.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <house.h>
#include <issued.h>
#include <key.h>
#include <script/standard.h>
#include <script/sign.h>
#include <keystore.h>
#include <note.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <random.h>
#include <settle.h>
#include <test/sidechain_test_util.h>
#include <test/test_bitcoin.h>
#include <token.h>
#include <txdb.h>
#include <txmempool.h>
#include <util.h>
#include <utilstrencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <map>
#include <string>
#include <vector>

/** Timing is reported unless FAMILY_A_COST_ENFORCE=1 (testing 11-26, on freebankd's v1.2.7 strict-suite failure under
 *  build load): the 1 ms line is a measurement for security, made on a quiet machine with ENFORCE=1; the shared DEV suite
 *  and GitHub's runners only report it. Refusal reasons and DoS scores stay hard assertions everywhere. */
static bool FamilyACostEnforced()
{
    const char* p = getenv("FAMILY_A_COST_ENFORCE");
    return p && *p && std::string(p) != "0" && !getenv("FAMILY_A_COST_REPORT_ONLY");
}


namespace {

std::vector<unsigned char> FaV(const CPubKey& p) { return std::vector<unsigned char>(p.begin(), p.end()); }

template <typename T>
std::vector<unsigned char> FaSer(const T& x)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << x;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CScript FaP2PKH(unsigned char c) { return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, c) << OP_EQUALVERIFY << OP_CHECKSIG; }

/** How many hash-to-curve tries CashuHashToCurve (cashu.cpp) makes for msg: the same loop, counted. */
int FaHashToCurveTries(const std::vector<unsigned char>& msg)
{
    static const std::string DOMAIN_SEPARATOR = "Secp256k1_HashToCurve_Cashu_";
    unsigned char msgHash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write((const unsigned char*)DOMAIN_SEPARATOR.data(), DOMAIN_SEPARATOR.size()).Write(msg.data(), msg.size()).Finalize(msgHash);
    for (uint32_t counter = 0; counter < 65536; counter++) {
        unsigned char ctr[4] = {(unsigned char)(counter & 0xff), (unsigned char)((counter >> 8) & 0xff),
                                (unsigned char)((counter >> 16) & 0xff), (unsigned char)((counter >> 24) & 0xff)};
        unsigned char cand[33];
        cand[0] = 0x02;
        CSHA256().Write(msgHash, sizeof(msgHash)).Write(ctr, sizeof(ctr)).Finalize(cand + 1);
        if (CPubKey(cand, cand + sizeof(cand)).IsFullyValid())
            return (int)counter + 1;
    }
    return 65537;
}

struct FaResult {
    std::string strName;
    int64_t nMin;
    int64_t nMedian;
    size_t nBytes;
    std::string strReason;
    bool fCounts;        // checked against the 1 ms line
    int nDoS = 0;        // the refusal\'s DoS score
    int64_t nBase = 0;   // the plain baseline of the same size subtracted before the check (0: none)
};

struct FamilyACostSetup : public TestChain100Setup {
    sidechain_test::SideDBScope sideDBs;   // ATMP's contextual checks read the side DBs (TestingSetup makes none)
    int nNext = 0;
    std::vector<FaResult> vResult;

    /** The test's own funding key: Time() signs every input spending one of its coins, last, with SIGHASH_ALL. */
    struct FaFundKey {
        CKey key;
        CBasicKeyStore keystore;
        CScript script;
        FaFundKey()
        {
            key.MakeNewKey(true);
            keystore.AddKey(key);
            script = GetScriptForDestination(key.GetPubKey().GetID());
        }
    } fundKey;
    std::map<COutPoint, CTxOut> mapOwned;
    /** A confirmed P2PKH coin of the test's own key, signed by Time(): a probe passes any early input-script check
     *  (security's rule A amendment, 11-26: the first non-family input's script right after the fee floor) and reaches
     *  the FreeBank checks. */
    COutPoint Fund(CAmount nValue = COIN)
    {
        const COutPoint o(uint256S(strprintf("%x", 0xfa000000 + ++nNext)), 0);
        pcoinsTip->AddCoin(o, Coin(CTxOut(nValue, fundKey.script), 1, false, false, false, uint256()), false);
        mapOwned[o] = CTxOut(nValue, fundKey.script);
        return o;
    }
    /** A confirmed P2PKH coin nobody here can sign for, spent with an empty scriptSig: refused at its input script. A
     *  probe that is otherwise valid carries one after its owned fund, so it is refused last (CheckInputs). */
    COutPoint Unowned(CAmount nValue = COIN)
    {
        const COutPoint o(uint256S(strprintf("%x", 0xfa000000 + ++nNext)), 0);
        pcoinsTip->AddCoin(o, Coin(CTxOut(nValue, FaP2PKH(0xfa)), 1, false, false, false, uint256()), false);
        return o;
    }
    void SignOwned(CMutableTransaction& mtx)
    {
        for (unsigned int i = 0; i < mtx.vin.size(); i++) {
            const auto it = mapOwned.find(mtx.vin[i].prevout);
            if (it != mapOwned.end())
                BOOST_REQUIRE(SignSignature(fundKey.keystore, it->second.scriptPubKey, mtx, i, it->second.nValue, SIGHASH_ALL));
        }
    }
    std::map<size_t, int64_t> mapPlain;
    /** The min ATMP time of a plain v2 tx of about nBytes (P2PKH outputs): what any tx of that size costs. Since security's
     *  rule A step 2 (11-26) every probe carries one owned, signed funding input (verified early: one sighash over the
     *  whole tx and one ECDSA verify) and is refused after it, so the baseline has the same shape: an owned signed fund,
     *  then an unowned coin with an empty scriptSig, refused at that second input. (Before 2026-11-26 evening the baseline
     *  had only the unowned coin, refused before any sighash, and charged the funding signature to FreeBank.) Cached per
     *  kilobyte. */
    int64_t PlainMin(size_t nBytes)
    {
        const size_t nKey = (nBytes + 500) / 1000;
        auto it = mapPlain.find(nKey);
        if (it != mapPlain.end())
            return it->second;
        std::vector<int64_t> v;
        for (int i = 0; i < 7; i++) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.vin.push_back(CTxIn(Fund()));
            mtx.vin.push_back(CTxIn(Unowned()));
            const size_t nOut = std::max<size_t>(1, nBytes / 34);
            for (size_t j = 0; j < nOut; j++)
                mtx.vout.emplace_back(COIN / 2 / nOut, FaP2PKH(0x0b));
            SignOwned(mtx);
            CValidationState state;
            const CTransactionRef ptx = MakeTransactionRef(std::move(mtx));
            const int64_t t0 = GetTimeMicros();
            AcceptToMemoryPool(mempool, state, ptx, nullptr, nullptr, false, 0);
            v.push_back(GetTimeMicros() - t0);
        }
        const int64_t n = *std::min_element(v.begin(), v.end());
        mapPlain[nKey] = n;
        return n;
    }
    /** Times ATMP on nRuns fresh probes. Each must be refused. */
    FaResult Time(const std::string& strName, const std::function<CMutableTransaction(int)>& fnBuild, int nRuns, bool fCounts = true)
    {
        std::vector<int64_t> v;
        FaResult r;
        r.strName = strName;
        r.fCounts = fCounts;
        for (int i = 0; i < nRuns; i++) {
            CMutableTransaction mtxProbe = fnBuild(i);
            SignOwned(mtxProbe);
            const CTransactionRef ptx = MakeTransactionRef(std::move(mtxProbe));
            r.nBytes = ::GetSerializeSize(*ptx, SER_NETWORK, PROTOCOL_VERSION);
            CValidationState state;
            const int64_t t0 = GetTimeMicros();
            const bool fOk = AcceptToMemoryPool(mempool, state, ptx, nullptr, nullptr, false, 0);
            v.push_back(GetTimeMicros() - t0);
            BOOST_REQUIRE_MESSAGE(!fOk, "family A cost: a probe was accepted (" + strName + ")");
            r.strReason = state.GetRejectReason();
            int nDoS = 0;
            state.IsInvalid(nDoS);
            r.nDoS = nDoS;
        }
        std::sort(v.begin(), v.end());
        r.nMin = v.front();
        r.nMedian = v[v.size() / 2];
        if (fCounts)
            r.nBase = PlainMin(r.nBytes);
        BOOST_TEST_MESSAGE(strprintf("family A cost: %-60s %7d us min, %7d us median, %6u bytes; over plain %6d us; refused %s",
                                     strName, r.nMin, r.nMedian, (unsigned)r.nBytes, r.nMin - r.nBase, r.strReason));
        vResult.push_back(r);
        return r;
    }
    /** The plain baseline: a v2 tx of about nBytes (P2PKH outputs), an owned signed fund then an unowned coin, refused at
     *  the second input's script (the probes' shape; see PlainMin). */
    FaResult Baseline(size_t nBytes)
    {
        return Time(strprintf("baseline: plain v2, ~%u bytes", (unsigned)nBytes), [&](int) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.vin.push_back(CTxIn(Fund()));
            mtx.vin.push_back(CTxIn(Unowned()));
            const size_t nOut = std::max<size_t>(1, nBytes / 34);
            for (size_t i = 0; i < nOut; i++)
                mtx.vout.emplace_back(COIN / 2 / nOut, FaP2PKH(0x0b));
            return mtx;
        }, 7, false);
    }
    /** Security 11-26 (rule A): a refusal after a signature with standing that doesn't depend on chain state scores 100,
     *  even on the mempool path (a UF4-1 carve-out). */
    void ExpectDoS100(const FaResult& r)
    {
        BOOST_CHECK_MESSAGE(r.nDoS == 100, strprintf("family A: %s was refused (%s) at DoS %d, not 100: a refusal after a "
                                                     "signature with standing that doesn't depend on chain state must score 100",
                                                     r.strName, r.strReason, r.nDoS));
    }
    void Check()
    {
        for (const FaResult& r : vResult) {
            // Timing only reports unless FAMILY_A_COST_ENFORCE=1 (a loaded machine inflates every time).
            if (!r.fCounts || !FamilyACostEnforced())
                continue;
            BOOST_CHECK_MESSAGE(r.nMin - r.nBase < 1000,
                                strprintf("family A: %s costs %d us over a plain tx of its size (min %d us, median %d us, "
                                          "plain %d us) before it is refused (%s): over the 1 ms line",
                                          r.strName, r.nMin - r.nBase, r.nMin, r.nMedian, r.nBase, r.strReason));
        }
    }
};

/** A shape-valid TOKEN_CLAIM entry of house nHouse with the given secret (the probes never reach the DLEQ). */
TokenClaimEntry FaClaimEntry(const std::vector<unsigned char>& vchSecret, const std::vector<unsigned char>& vchPoint)
{
    TokenClaimEntry e;
    e.nKeysetID = 1;
    e.nAmount = 1;
    e.vchSecret = vchSecret;
    e.vchB = vchPoint;
    e.vchC = vchPoint;
    e.vchE.assign(32, 1);
    e.vchS.assign(32, 2);
    const CScript pay = FaP2PKH(7);
    e.vchPayoutScript.assign(pay.begin(), pay.end());
    e.vchSig.assign(70, 0x30);
    return e;
}


/** An Open house record (tier multi-partner, M = 1), registered at block 1, written to the house DB. */
CHouse FaWriteOpenHouse(uint32_t nHouseID, const std::vector<unsigned char>& vchApprover)
{
    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = ArithToUint256(arith_uint256(0xfa0000 + nHouseID));
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = strprintf("fa%u", nHouseID);
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1;
    HousePartner partner;
    partner.vchPubKey = vchApprover;
    partner.amountPledge = COIN;
    house.vPartner.push_back(partner);
    BOOST_REQUIRE(phousetree->WriteHouse(house));
    return house;
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

BOOST_FIXTURE_TEST_SUITE(family_a_cost_tests, FamilyACostSetup)

// ---------------------------------------------------------------------------
// TOKEN_CLAIM, no key. ATMP runs TokenClaimYs (one hash-to-curve per entry: CashuHashToCurve tries up to 65,536
// counters, each a SHA256 and a point parse) before the house is read or any signature checked, and nothing refuses a
// repeated secret first. A secret ground offline to need k tries can fill all 64 entries: about 2^(k-1) candidates find
// one, so k = 30 is hours on one core. The probe: 64 copies of a ground secret, a house that doesn't exist.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_token_claim_ground_secret)
{
    LOCK(cs_main);
    CKey k;
    k.MakeNewKey(true);
    const std::vector<unsigned char> vchPoint = FaV(k.GetPubKey());
    // Grind a 64-character secret needing at least 17 tries (2^16 candidates on average; well under a second).
    const int nWant = 17;
    std::vector<unsigned char> vchGround;
    int nTries = 0;
    int64_t nCandidates = 0;
    const int64_t tGrind = GetTimeMicros();
    while (nTries < nWant) {
        const std::string s = HexStr(GetRandHash());
        vchGround.assign(s.begin(), s.end());
        nTries = FaHashToCurveTries(vchGround);
        nCandidates++;
    }
    BOOST_TEST_MESSAGE(strprintf("family A cost: ground a secret needing %d hash-to-curve tries in %d candidates (%d ms)",
                                 nTries, nCandidates, (GetTimeMicros() - tGrind) / 1000));
    auto fnClaim = [&](bool fGround) {
        return [&, fGround](int) {
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_NOTE_VERSION;
            mtx.nNoteOp = NOTE_OP_TOKEN_CLAIM;
            mtx.vin.push_back(CTxIn(Fund()));
            mtx.vout.emplace_back(COIN - 100000, FaP2PKH(8));
            NoteTokenClaim c;
            c.nHouseID = 900005;   // no such house
            for (size_t i = 0; i < MAX_TOKEN_CLAIM_ENTRIES; i++) {
                std::vector<unsigned char> vchRandom;
                if (!fGround) {
                    const std::string s = HexStr(GetRandHash());
                    vchRandom.assign(s.begin(), s.end());
                }
                c.vEntry.push_back(FaClaimEntry(fGround ? vchGround : vchRandom, vchPoint));
            }
            mtx.vchNotePayload = FaSer(c);
            return mtx;
        };
    };
    const FaResult rRandom = Time("note TOKEN_CLAIM, 64 random secrets, no house", fnClaim(false), 7);
    const FaResult rGround = Time(strprintf("note TOKEN_CLAIM, 64 x a secret ground to %d tries, no house", nTries), fnClaim(true), 7);
    // Per try, and what a 30-try secret (hours of grinding on one core) costs.
    const double dPerTry = double(rGround.nMin - rRandom.nMin) / (64.0 * (nTries - 2));
    BOOST_TEST_MESSAGE(strprintf("family A cost: TOKEN_CLAIM hash-to-curve ~%.2f us a try; 64 x a 30-try secret ~%d us, "
                                 "64 x a 40-try secret ~%d us", dPerTry, rRandom.nMin + (int64_t)(dPerTry * 64 * 28),
                                 rRandom.nMin + (int64_t)(dPerTry * 64 * 38)));
    Baseline(rGround.nBytes);
    Check();
}

// ---------------------------------------------------------------------------
// TOKEN_CLAIM at an insolvent house inside its claim window, no key. The cheap checks pass (the house exists and is
// insolvent, the window is open), so each entry's secret goes through hash-to-curve twice (ATMP's TokenClaimYs, then
// the record loop) with four record reads, before the first holder signature fails. 64 DISTINCT secrets, each ground to
// need at least 10 tries (about 640 tries a claim), all naming one public issued B. Security's relay budget (11-26):
// entries + 32 = 96 tries a tx, spent and then refused at DoS 0.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_token_claim_insolvent_house)
{
    LOCK(cs_main);
    CKey keyHouse, keyMint, keyB;
    keyHouse.MakeNewKey(true);
    keyMint.MakeNewKey(true);
    keyB.MakeNewKey(true);
    CHouse house = FaWriteOpenHouse(62, FaV(keyHouse.GetPubKey()));
    house.status = HOUSE_STATUS_INSOLVENT;
    house.nNoCureHeight = 1;
    CTokenKeyset ks;
    ks.nHeight = 0;
    ks.vchPostingPubKey = FaV(keyHouse.GetPubKey());
    ks.vKey.emplace_back(0, FaV(keyMint.GetPubKey()));   // amount 1
    const std::vector<unsigned char> vchB = FaV(keyB.GetPubKey());
    CTokenMark issued;
    issued.nHeight = 0;
    issued.nKeysetID = 1;
    issued.nAmount = 1;
    TokenEffects eff;
    eff.mapKeyset[std::make_pair((uint32_t)62, (uint64_t)1)] = ks;
    eff.mapIssued[std::make_pair((uint32_t)62, vchB)] = issued;
    BOOST_REQUIRE(phousetree->WriteBlockEffects({house}, nullptr, chainActive.Tip()->GetBlockHash(), nullptr, &eff, nullptr));
    // Security's relay ruling (11-26, freebankd ffe871c): at most 32 entries, hashed within 2 x entries + 32 = 96 tries in
    // all. The costliest claim relay still takes spends the whole budget and goes on to the reads and the signature: 32
    // distinct secrets of exactly 3 tries each (96). The over-budget case (secrets of 4 or more tries) stops at the budget.
    std::vector<std::vector<unsigned char>> vSecret, vOver;
    int nTotal = 0;
    while (vSecret.size() < MAX_TOKEN_CLAIM_ENTRIES_RELAY || vOver.size() < MAX_TOKEN_CLAIM_ENTRIES_RELAY) {
        const std::string str = HexStr(GetRandHash());
        const std::vector<unsigned char> v(str.begin(), str.end());
        const int n = FaHashToCurveTries(v);
        if (n == 3 && vSecret.size() < MAX_TOKEN_CLAIM_ENTRIES_RELAY) {
            vSecret.push_back(v);
            nTotal += n;
        } else if (n >= 4 && vOver.size() < MAX_TOKEN_CLAIM_ENTRIES_RELAY) {
            vOver.push_back(v);
        }
    }
    BOOST_REQUIRE_EQUAL(nTotal, (int)TokenClaimRelayTryBudget(MAX_TOKEN_CLAIM_ENTRIES_RELAY));
    auto fnClaim = [&](int nKind) {   // 0 random, 1 the 96-try set, 2 over budget
        const bool fGround = nKind != 0;
        return [&, fGround, nKind](int) {
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_NOTE_VERSION;
            mtx.nNoteOp = NOTE_OP_TOKEN_CLAIM;
            mtx.vin.push_back(CTxIn(Fund()));
            mtx.vout.emplace_back(COIN - 100000, FaP2PKH(8));
            NoteTokenClaim c;
            c.nHouseID = 62;
            for (size_t i = 0; i < MAX_TOKEN_CLAIM_ENTRIES_RELAY; i++) {
                std::vector<unsigned char> v = nKind == 2 ? vOver[i] : vSecret[i];
                if (!fGround) {
                    const std::string str = HexStr(GetRandHash());
                    v.assign(str.begin(), str.end());
                }
                c.vEntry.push_back(FaClaimEntry(v, vchB));
            }
            mtx.vchNotePayload = FaSer(c);
            return mtx;
        };
    };
    Time("note TOKEN_CLAIM at an insolvent house, 32 random secrets, signature wrong", fnClaim(0), 7);
    Time("note TOKEN_CLAIM at an insolvent house, 32 secrets of 4+ tries (over the budget)", fnClaim(2), 7);
    const FaResult r = Time(strprintf("note TOKEN_CLAIM at an insolvent house, 32 secrets of 3 tries (%d: the whole budget), signature wrong", nTotal),
                            fnClaim(1), 7);
    BOOST_CHECK_MESSAGE(r.strReason == "bad-token-claim-sig", "family A: the 96-try claim was refused at " + r.strReason +
                        ", not at the holder signature after the reads (so the probe no longer measures that path)");
    // Security 11-26: a token holder's signature has no standing; bad-token-claim-sig, -dleq and -proof are pure in the
    // tx and the keyset its id names, so they score DoSStateIndependent(100) (freebankd 4358e5d, v1.2.7).
    ExpectDoS100(r);
    const FaResult rProof = Time("note TOKEN_CLAIM at an insolvent house, 32 random secrets, the first C not a point", [&](int i) {
        CMutableTransaction mtx = fnClaim(0)(i);
        NoteTokenClaim c;
        BOOST_REQUIRE(DecodeNotePayload(mtx.vchNotePayload, c));
        c.vEntry[0].vchC.assign(33, 0xff);
        c.vEntry[0].vchC[0] = 0x02;   // 0x02 || ff..ff: x above the field prime, not a point
        mtx.vchNotePayload = FaSer(c);
        return mtx;
    }, 7);
    BOOST_CHECK_MESSAGE(rProof.strReason == "bad-token-claim-proof", "family A: the bad-C claim was refused at " + rProof.strReason);
    ExpectDoS100(rProof);
    Baseline(r.nBytes);
    Check();
}

// ---------------------------------------------------------------------------
// Pooled parents, no key, any version, before the fee floor. Each input that spends a POOLED FreeBank tx's output makes
// CCoinsViewMemPool::GetCoin decode the parent's payload (the payload-pure taggers, no cache): once at the input fetch
// and again in SpendsPooledCreditOutput. Inputs need not be owned (scripts are checked last), so a child can spend the
// outputs of anyone's pooled txs. Parents here are pooled with addUnchecked (shape-valid payloads, not validated):
//  (1) note TRANSFERs of 256 outputs (any noteholder can pool one), a child spending ~2,400 of their outputs;
//  (2) note MINTs of 256 outputs with 64 reserve proofs and 24 approver signatures (a house's own), the same child;
//  (3), (4) the same parents, 2,400 of them, one input off each (what a per-call decode cache still pays).
// The child is a zero-fee plain v2 tx: refused (at the latest) in CheckTxInputs, after every decode.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_pooled_parent_decodes)
{
    LOCK(cs_main);
    CKey k;
    k.MakeNewKey(true);
    const std::vector<unsigned char> vchKey = FaV(k.GetPubKey());
    TestMemPoolEntryHelper entry;
    const size_t nOutputs = MAX_STANDARD_FREEBANK_OUTPUTS;   // 256
    auto fnPool = [&](bool fMint, size_t nParents) {
        std::vector<uint256> v;
        for (size_t p = 0; p < nParents; p++) {
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_NOTE_VERSION;
            mtx.vin.push_back(CTxIn(Fund()));
            for (size_t i = 0; i < nOutputs; i++)
                mtx.vout.emplace_back(NOTE_DUST_VALUE, NoteScriptForPubKey(vchKey));
            if (fMint) {
                NoteMint m;
                m.nHouseID = 7;
                m.vUnits.assign(nOutputs, 1000);
                m.nAsOfHeight = 99;
                for (size_t i = 0; i < MAX_ATTEST_PROOFS; i++) {
                    AttestProof pr;
                    pr.outpoint = COutPoint(GetRandHash(), (uint32_t)i);
                    pr.vchPubKey = vchKey;
                    pr.vchSig.assign(72, 0x30);
                    m.vReserveProofs.push_back(pr);
                }
                for (uint32_t i = 0; i < 24; i++) {
                    m.vApproverIndex.push_back(i);
                    m.vApproverSig.push_back(std::vector<unsigned char>(72, 0x30));
                }
                mtx.nNoteOp = NOTE_OP_MINT;
                mtx.vchNotePayload = FaSer(m);
            } else {
                NoteTransfer t;
                t.nHouseID = 7;
                t.vUnits.assign(nOutputs, 1000);
                t.nDemandHeight = 0;
                t.vchSenderPubKey = vchKey;
                t.vchSenderSig.assign(72, 0x30);
                mtx.nNoteOp = NOTE_OP_TRANSFER;
                mtx.vchNotePayload = FaSer(t);
            }
            const CTransaction tx(mtx);
            mempool.addUnchecked(tx.GetHash(), entry.Fee(100000).FromTx(tx));
            v.push_back(tx.GetHash());
        }
        return v;
    };
    // ~2,400 inputs fill 100,000 bytes (41 bytes an input with an empty scriptSig).
    const size_t nInputs = 2400;
    const size_t nParents = (nInputs + nOutputs - 1) / nOutputs;
    auto fnChild = [&](const std::vector<uint256>& vParent) {
        return [&, vParent](int i) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.nLockTime = (uint32_t)i;
            for (size_t n = 0; n < nInputs; n++)
                mtx.vin.push_back(CTxIn(COutPoint(vParent[n / nOutputs], (uint32_t)(n % nOutputs))));
            mtx.vout.emplace_back((CAmount)nInputs * NOTE_DUST_VALUE, FaP2PKH(9));   // zero fee
            return mtx;
        };
    };
    // The same child shape off confirmed note coins first: the input fetch with no decode (Bitcoin's own cost).
    std::vector<COutPoint> vConfirmed;
    for (size_t n = 0; n < nInputs; n++) {
        const COutPoint o(uint256S(strprintf("%x", 0xfb000000 + ++nNext)), 0);
        Coin c(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vchKey)), 1, false, false, false, uint256());
        c.SetNote(7, 1000);
        pcoinsTip->AddCoin(o, std::move(c), false);
        vConfirmed.push_back(o);
    }
    const FaResult rBase = Time(strprintf("baseline: %u inputs off confirmed note coins", (unsigned)nInputs), [&](int i) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.nLockTime = (uint32_t)i;
        for (const COutPoint& o : vConfirmed)
            mtx.vin.push_back(CTxIn(o));
        mtx.vout.emplace_back((CAmount)nInputs * NOTE_DUST_VALUE, FaP2PKH(9));
        return mtx;
    }, 5, false);
    // The pooled children; what counts is the excess over the confirmed-coin child.
    const std::vector<uint256> vTransfer = fnPool(false, nParents);
    const FaResult rT = Time(strprintf("pooled parents: %u inputs off pooled 256-output TRANSFERs", (unsigned)nInputs), fnChild(vTransfer), 5, false);
    mempool.clear();
    const std::vector<uint256> vMint = fnPool(true, nParents);
    const FaResult rM = Time(strprintf("pooled parents: %u inputs off pooled 256-output MINTs (64 proofs)", (unsigned)nInputs), fnChild(vMint), 5, false);
    mempool.clear();
    // One input off each of 2,400 DISTINCT pooled parents: a decode cache per ATMP call still decodes every parent once;
    // tags kept on the mempool entry at admission decode none (security's rule A amendment, 11-26).
    auto fnChildDistinct = [&](const std::vector<uint256>& vParent) {
        return [&, vParent](int i) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.nLockTime = (uint32_t)i;
            for (size_t n = 0; n < nInputs; n++)
                mtx.vin.push_back(CTxIn(COutPoint(vParent[n], 0)));
            mtx.vout.emplace_back((CAmount)nInputs * NOTE_DUST_VALUE, FaP2PKH(9));   // zero fee
            return mtx;
        };
    };
    const std::vector<uint256> vTransferD = fnPool(false, nInputs);
    const FaResult rTD = Time(strprintf("pooled parents: 1 input off each of %u pooled 256-output TRANSFERs", (unsigned)nInputs), fnChildDistinct(vTransferD), 5, false);
    mempool.clear();
    const std::vector<uint256> vMintD = fnPool(true, nInputs);
    const FaResult rMD = Time(strprintf("pooled parents: 1 input off each of %u pooled 256-output MINTs", (unsigned)nInputs), fnChildDistinct(vMintD), 5, false);
    mempool.clear();
    // Security's "same inputs" baseline (11-26), read exactly: the same child off pooled PLAIN v2 parents (256 P2PKH
    // outputs each), zero fee. It pays Bitcoin's own cost of spending pooled parents (the pool lookups, the sequence
    // locks, and standardness of the inputs) and is refused at the relay fee, DoS 0, so anyone can repeat it for free.
    // What counts is a FreeBank child's excess over that (freebankd 60e409d: the residual is the per-parent cold lookups).
    auto fnPoolPlain = [&](size_t nParents) {
        std::vector<uint256> v;
        for (size_t p = 0; p < nParents; p++) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.vin.push_back(CTxIn(Fund()));
            for (size_t i = 0; i < nOutputs; i++)
                mtx.vout.emplace_back(NOTE_DUST_VALUE, FaP2PKH(7));
            const CTransaction tx(mtx);
            mempool.addUnchecked(tx.GetHash(), entry.Fee(100000).FromTx(tx));
            v.push_back(tx.GetHash());
        }
        return v;
    };
    const std::vector<uint256> vPlain = fnPoolPlain(nParents);
    const FaResult rPT = Time(strprintf("baseline: %u inputs off pooled 256-output plain v2 parents", (unsigned)nInputs), fnChild(vPlain), 5, false);
    mempool.clear();
    const std::vector<uint256> vPlainD = fnPoolPlain(nInputs);
    const FaResult rPD = Time(strprintf("baseline: 1 input off each of %u pooled plain v2 parents", (unsigned)nInputs), fnChildDistinct(vPlainD), 5, false);
    mempool.clear();
    auto fnExcess = [&](const FaResult& r, const FaResult& base, const std::string& strOver, bool fCounts) {
        FaResult x = r;
        x.strName = "excess over " + strOver + ": " + r.strName;
        x.nMin = r.nMin - base.nMin;
        x.nMedian = r.nMedian - base.nMedian;
        x.fCounts = fCounts;
        BOOST_TEST_MESSAGE(strprintf("family A cost: %-60s %7d us min, %7d us median%s", x.strName, x.nMin, x.nMedian,
                                     fCounts ? "" : " (reported, not counted)"));
        vResult.push_back(x);
    };
    for (const FaResult* p : {&rT, &rM, &rTD, &rMD})   // the old reading, for comparison with the 11-26 table
        fnExcess(*p, rBase, "confirmed inputs", false);
    fnExcess(rT, rPT, "the same inputs off plain pooled parents", true);
    fnExcess(rM, rPT, "the same inputs off plain pooled parents", true);
    fnExcess(rTD, rPD, "the same inputs off plain pooled parents", true);
    fnExcess(rMD, rPD, "the same inputs off plain pooled parents", true);
    Check();
}

// ---------------------------------------------------------------------------
// TOKEN_POST, the posting-key holder (a mint). After its one signature the POST parses every issued B and reads a
// record for each B and y: up to MAX_TOKEN_POST_ENTRIES = 2,000. The order meets the rule (signature first), but the
// cost line is per op type. The probe: 2,000 fresh issued Bs, a valid posting signature (a fresh funding coin each run,
// so the digest is new), refused at its empty scriptSig.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_token_post_key_holder)
{
    LOCK(cs_main);
    CKey keyHouse, keyPost, keyMint;
    keyHouse.MakeNewKey(true);
    keyPost.MakeNewKey(true);
    keyMint.MakeNewKey(true);
    const CHouse house = FaWriteOpenHouse(61, FaV(keyHouse.GetPubKey()));
    CTokenKeyset ks;
    ks.nHeight = 1;
    ks.vchPostingPubKey = FaV(keyPost.GetPubKey());
    ks.vKey.emplace_back(0, FaV(keyMint.GetPubKey()));   // amount 1
    TokenEffects eff;
    eff.mapKeyset[std::make_pair((uint32_t)61, (uint64_t)1)] = ks;
    BOOST_REQUIRE(phousetree->WriteBlockEffects({house}, nullptr, chainActive.Tip()->GetBlockHash(), nullptr, &eff, nullptr));
    std::vector<TokenIssued> vIssued;
    for (size_t i = 0; i < MAX_TOKEN_POST_ENTRIES; i++) {
        CKey k;
        k.MakeNewKey(true);
        vIssued.emplace_back(FaV(k.GetPubKey()), 1);
    }
    auto fnPost = [&](size_t nEntries, bool fGoodSig) {
        return [&, nEntries, fGoodSig](int) {
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_NOTE_VERSION;
            mtx.nNoteOp = NOTE_OP_TOKEN_POST;
            mtx.vin.push_back(CTxIn(Fund()));
            if (fGoodSig)
                mtx.vin.push_back(CTxIn(Unowned()));   // otherwise valid: refused last, at this input's script
            mtx.vout.emplace_back(COIN - 2000000, FaP2PKH(8));
            NoteTokenPost post;
            post.nHouseID = 61;
            post.nKeysetID = 1;
            post.vIssued.assign(vIssued.begin(), vIssued.begin() + nEntries);
            if (fGoodSig)
                BOOST_REQUIRE(keyPost.Sign(TokenPostSigHash(C1With(mtx, &CMutableTransaction::vchNotePayload, post)), post.vchSig));
            else
                post.vchSig.assign(70, 0x30);
            mtx.vchNotePayload = FaSer(post);
            return mtx;
        };
    };
    Time("note TOKEN_POST, 2,000 issued Bs, bad posting signature", fnPost(MAX_TOKEN_POST_ENTRIES, false), 5);
    // The posting key is standing (security 11-26): measured for the record, not counted.
    Time("note TOKEN_POST, 1 issued B, posting-key holder (standing: not counted)", fnPost(1, true), 5, false);
    const FaResult r = Time("note TOKEN_POST, 2,000 issued Bs, posting-key holder (standing: not counted)",
                            fnPost(MAX_TOKEN_POST_ENTRIES, true), 5, false);
    // A refusal after the posting signature that doesn't depend on chain state (an issued B that isn't a point) must
    // score 100 even on the mempool path.
    {
        std::vector<unsigned char> vchNotPoint(33, 0xff);
        vchNotPoint[0] = 0x02;   // x = 2^256 - 1 > p: the right shape, no point
        const TokenIssued good = vIssued[0];
        vIssued[0] = TokenIssued(vchNotPoint, 1);
        const FaResult rBad = Time("note TOKEN_POST, posting-key holder, one issued B not a point (DoS checked)", fnPost(1, true), 3, false);
        vIssued[0] = good;
        BOOST_CHECK_EQUAL(rBad.strReason, "bad-token-post-issued");
        ExpectDoS100(rBad);
    }
    Baseline(r.nBytes);
    Check();
}

// freebankd 11-26 (v1.2.7, the quiet-box ENFORCE run): the mempool's token-slot check (Stage 0 rule B2) built a POST's
// keys, one hash per issued B and spent Y, before the posting signature: 2,056 us over plain for a 2,000-B POST with a bad
// signature. The keys are now checked after the signature (rule A). A POST sharing a pooled POST's B is refused
// token-slot-pending with a good signature, and at the signature with a bad one.
BOOST_AUTO_TEST_CASE(family_a_token_post_slot_after_signature)
{
    LOCK(cs_main);
    CKey keyHouse, keyPost, keyMint;
    keyHouse.MakeNewKey(true);
    keyPost.MakeNewKey(true);
    keyMint.MakeNewKey(true);
    const CHouse house = FaWriteOpenHouse(62, FaV(keyHouse.GetPubKey()));
    CTokenKeyset ks;
    ks.nHeight = 1;
    ks.vchPostingPubKey = FaV(keyPost.GetPubKey());
    ks.vKey.emplace_back(0, FaV(keyMint.GetPubKey()));   // amount 1
    TokenEffects eff;
    eff.mapKeyset[std::make_pair((uint32_t)62, (uint64_t)1)] = ks;
    BOOST_REQUIRE(phousetree->WriteBlockEffects({house}, nullptr, chainActive.Tip()->GetBlockHash(), nullptr, &eff, nullptr));
    std::vector<TokenIssued> vB;
    for (int i = 0; i < 3; i++) {
        CKey k;
        k.MakeNewKey(true);
        vB.emplace_back(FaV(k.GetPubKey()), 1);
    }
    auto fnPost = [&](const std::vector<TokenIssued>& vIssued, bool fGoodSig) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_NOTE_VERSION;
        mtx.nNoteOp = NOTE_OP_TOKEN_POST;
        mtx.vin.push_back(CTxIn(Fund()));
        mtx.vout.emplace_back(COIN - 2000000, FaP2PKH(8));
        NoteTokenPost post;
        post.nHouseID = 62;
        post.nKeysetID = 1;
        post.vIssued = vIssued;
        if (fGoodSig)
            BOOST_REQUIRE(keyPost.Sign(TokenPostSigHash(C1With(mtx, &CMutableTransaction::vchNotePayload, post)), post.vchSig));
        else
            post.vchSig.assign(70, 0x30);
        mtx.vchNotePayload = FaSer(post);
        SignOwned(mtx);
        return MakeTransactionRef(std::move(mtx));
    };
    CValidationState s1;
    BOOST_REQUIRE_MESSAGE(AcceptToMemoryPool(mempool, s1, fnPost({vB[0], vB[1]}, true), nullptr, nullptr, false, 0),
                          FormatStateMessage(s1));
    CValidationState s2;
    BOOST_CHECK(!AcceptToMemoryPool(mempool, s2, fnPost({vB[1], vB[2]}, true), nullptr, nullptr, false, 0));
    BOOST_CHECK_EQUAL(s2.GetRejectReason(), "token-slot-pending");
    CValidationState s3;
    BOOST_CHECK(!AcceptToMemoryPool(mempool, s3, fnPost({vB[1], vB[2]}, false), nullptr, nullptr, false, 0));
    BOOST_CHECK_EQUAL(s3.GetRejectReason(), "bad-token-post-sig");
    CValidationState s4;
    BOOST_CHECK_MESSAGE(AcceptToMemoryPool(mempool, s4, fnPost({vB[2]}, true), nullptr, nullptr, false, 0),
                        FormatStateMessage(s4));
}

// ---------------------------------------------------------------------------
// Settle NET, no key: 100 existing houses (the S1X-37 cap), each record read before the first approver signature
// (validation.cpp CheckSettleTx, the S1X-37 order). A ring of note bundles on the presenters' keys passes the input
// layer; the approver signatures are junk, so the round is refused at the first one.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_settle_net_existing_houses)
{
    LOCK(cs_main);
    const size_t H = 100;
    CKey keyApprover;
    keyApprover.MakeNewKey(true);
    std::vector<std::vector<unsigned char>> vKey;
    for (size_t i = 0; i < H; i++) {
        CKey k;
        k.MakeNewKey(true);
        vKey.push_back(FaV(k.GetPubKey()));
    }
    auto fnNet = [&](int) {
        SettleNet n;
        for (size_t i = 0; i < H; i++) {
            n.vHouseID.push_back((uint32_t)(i + 900001));
            n.vReceive.push_back(0);
            n.vPrevMintedUnits.push_back(1000000);
            n.vPrevLastSettleHeight.push_back(0);
            n.vPresentKey.push_back(vKey[i]);
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
        for (const SettleNetBundle& b : n.vBundle) {
            const COutPoint o(uint256S(strprintf("%x", 0xfc000000 + ++nNext)), 0);
            Coin coin(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(vKey[b.nPresenter - 900001])), 1, false, false, false, uint256());
            coin.SetNote(b.nIssuer, b.nUnits);
            pcoinsTip->AddCoin(o, std::move(coin), false);
            mtx.vin.push_back(CTxIn(o));
            nIn += NOTE_DUST_VALUE;
        }
        mtx.vin.push_back(CTxIn(Fund()));
        nIn += COIN;
        mtx.vout.emplace_back(nIn - 100000, FaP2PKH(0x37));
        mtx.vchSettlePayload = FaSer(n);
        return mtx;
    };
    Time("settle NET, 100 houses that don't exist (control)", fnNet, 5, false);
    for (size_t i = 0; i < H; i++)
        FaWriteOpenHouse((uint32_t)(i + 900001), FaV(keyApprover.GetPubKey()));
    const FaResult r = Time("settle NET, 100 existing houses, junk approver signatures", fnNet, 5);
    Baseline(r.nBytes);
    Check();
}

// ---------------------------------------------------------------------------
// Issued TRANSFER, no payload authorizer (the holders' input scripts, checked last). ConnectIssuedTx reads one units
// record (IssuedFrozenKey) per issued input before anything else, on the mempool path too. About 2,400 issued inputs
// fit 100,000 bytes; the annex conserves them. Inputs need not be owned.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_issued_transfer_inputs)
{
    LOCK(cs_main);
    const size_t nInputs = 2400;
    const uint256 token = ArithToUint256(arith_uint256(0xfa7e));
    std::vector<COutPoint> vIssued, vPlain;
    for (size_t n = 0; n < nInputs; n++) {
        const COutPoint o(uint256S(strprintf("%x", 0xfd000000 + ++nNext)), 0);
        Coin c(CTxOut(ISSUED_COIN_VALUE, FaP2PKH(0x15)), 1, false, false, false, uint256());
        c.SetIssued(token, 1, 0);
        pcoinsTip->AddCoin(o, std::move(c), false);
        vIssued.push_back(o);
        const COutPoint q(uint256S(strprintf("%x", 0xfe000000 + ++nNext)), 0);
        pcoinsTip->AddCoin(q, Coin(CTxOut(ISSUED_COIN_VALUE, FaP2PKH(0x15)), 1, false, false, false, uint256()), false);
        vPlain.push_back(q);
    }
    const FaResult rBase = Time(strprintf("baseline: plain v2, %u plain inputs", (unsigned)nInputs), [&](int i) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.nLockTime = (uint32_t)i;
        for (const COutPoint& o : vPlain)
            mtx.vin.push_back(CTxIn(o));
        mtx.vout.emplace_back(ISSUED_COIN_VALUE, FaP2PKH(0x16));
        return mtx;
    }, 5, false);
    const FaResult r = Time(strprintf("issued TRANSFER, %u issued inputs", (unsigned)nInputs), [&](int i) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_TOKEN_VERSION;
        mtx.nIssuedOp = ISSUED_OP_TRANSFER;
        mtx.nLockTime = (uint32_t)i;
        for (const COutPoint& o : vIssued)
            mtx.vin.push_back(CTxIn(o));
        mtx.vout.emplace_back(ISSUED_COIN_VALUE, FaP2PKH(0x16));
        CIssuedOut out;
        out.nOut = 0;
        out.tokenID = token;
        out.nUnits = nInputs;
        out.nFrozen = 0;
        mtx.vIssuedOut.push_back(out);
        return mtx;
    }, 5, false);
    FaResult x = r;
    x.strName = "excess over plain inputs: " + r.strName;
    x.nMin = r.nMin - rBase.nMin;
    x.nMedian = r.nMedian - rBase.nMedian;
    x.fCounts = true;
    BOOST_TEST_MESSAGE(strprintf("family A cost: %-60s %7d us min, %7d us median", x.strName, x.nMin, x.nMedian));
    vResult.push_back(x);
    Check();
}

// ---------------------------------------------------------------------------
// Issued FREEZE, before the fee floor: ATMP fetches every named outpoint (up to MAX_ISSUED_FREEZE_OUTPOINTS = 64) into
// the view before CheckTxInputs. Zero fee, 64 outpoints not in the coins cache: refused at the floor after the reads.
// In memory here; a real node reads LevelDB, possibly from disk.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_issued_freeze_prefetch)
{
    LOCK(cs_main);
    const FaResult r = Time("issued FREEZE, 64 uncached outpoints, zero fee", [&](int) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_TOKEN_VERSION;
        mtx.nIssuedOp = ISSUED_OP_FREEZE;
        const COutPoint fund = Fund();
        mtx.vin.push_back(CTxIn(fund));
        mtx.vout.emplace_back(COIN, FaP2PKH(0x17));   // zero fee
        IssuedFreeze fz;
        fz.tokenID = ArithToUint256(arith_uint256(0xfa7f));
        for (size_t i = 0; i < MAX_ISSUED_FREEZE_OUTPOINTS; i++) {
            fz.vOutpoint.emplace_back(GetRandHash(), (uint32_t)i);
            fz.vFrozen.push_back(1);
        }
        fz.vchFreezeSig.assign(70, 0x30);
        mtx.vchIssuedPayload = FaSer(fz);
        return mtx;
    }, 7);
    Baseline(r.nBytes);
    Check();
}

BOOST_AUTO_TEST_SUITE_END()
