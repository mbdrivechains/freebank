// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ===========================================================================
// testing (2026-11-26): family A cost measurement, HOUSE family (Stage 0, D-2026-11-26-1). Security's test for rule A
// (note 2026-11-26-from-security-family-rules): "for each op type, the costliest refused tx of maximum standard size
// costs under 1 ms of node time, measured". The method is family_a_cost_tests.cpp's: a funding coin of the test's own key
// (signed, so it passes security's early input-script check), plus an unowned coin with an empty scriptSig where a probe
// would otherwise be valid (refused last, at CheckInputs); fresh coins, keys or digests every run, so no signature cache
// helps; min and median over the runs, the 1 ms line checked on the min. The side DBs are in memory (SideDBScope).
// The probes, from testing's cost map (house section):
//  - ATTEST, third party: 64 reserve proofs with valid proof signatures (not authorizers) checked before the approvers;
//  - REGISTER: 64 founding partners, the last signature wrong; unowned pledge funding counts, and with owned funding the
//    refusal must score 100 (security 11-26);
//  - EXIT, third party: the capital check (CapitalCapUnits: rate-day reads, a partner x tranche loop with clock reads)
//    runs before the signature; a normal house and one built to 64 partners x 64 tranches, on the real clock;
//  - MEMBER_ADD, insider: 24 approvers, 256 entries, the last prior wrong (reads after the signatures; standing, so not
//    counted against the line: security's ruling 11-26);
//  - the universal slot guard, which walks the whole mempool for every slot-taking incomer: 0 / 10k / 50k entries.
// ===========================================================================

#include <bill.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <house.h>
#include <houserate.h>
#include <issued.h>
#include <key.h>
#include <script/sign.h>
#include <keystore.h>
#include <miner.h>
#include <note.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <random.h>
#include <script/standard.h>
#include <test/sidechain_test_util.h>
#include <test/test_bitcoin.h>
#include <txdb.h>
#include <txmempool.h>
#include <units.h>
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

/** A validly encoded signature that doesn't verify (key over a random hash): the refusal pays a full ECDSA verify. */
std::vector<unsigned char> FaWrongSig(const CKey& key)
{
    std::vector<unsigned char> v;
    BOOST_REQUIRE(key.Sign(GetRandHash(), v));
    return v;
}
std::vector<unsigned char> FaSign(const CKey& key, const uint256& hash)
{
    std::vector<unsigned char> v;
    BOOST_REQUIRE(key.Sign(hash, v));
    return v;
}

// Stage 0 C1: the ATTEST and MEMBER approvers sign the whole transaction (HouseAttestSigHash / HouseMemberSigHash(tx, id)).

struct FaResult {
    std::string strName;
    int64_t nMin;
    int64_t nMedian;
    size_t nBytes;
    std::string strReason;
    bool fCounts;   // checked against the 1 ms line
    int nDoS = 0;        // the refusal\'s DoS score
};

/** The real capital check, rates and clock for one case (unit tests emulate the pre-gram caps, override every rate to
 *  1,000 sats a gram and count windows in blocks: test_bitcoin.cpp). */
struct FaRealScope {
    std::function<void(const CHouse&, int, CHouseCapital&)> fnCap;
    uint64_t nRate;
    bool fClock;
    bool fParamsClock;
    FaRealScope() : fnCap(g_fnCapitalForChecksTestOverride), nRate(g_nHouseRateTestOverride), fClock(g_fClockIsHeightForTests),
                    fParamsClock(Params().GetConsensus().fClockIsHeight)
    {
        g_fnCapitalForChecksTestOverride = nullptr;
        g_nHouseRateTestOverride = 0;
        g_fClockIsHeightForTests = false;
        UpdateClockIsHeight(false);   // TestChain100Setup runs on regtest params, whose windows count blocks
    }
    ~FaRealScope()
    {
        g_fnCapitalForChecksTestOverride = fnCap;
        g_nHouseRateTestOverride = nRate;
        g_fClockIsHeightForTests = fClock;
        UpdateClockIsHeight(fParamsClock);
    }
};

struct FamilyACostHouseSetup : public TestChain100Setup {
    sidechain_test::RegtestFamilyScope family;
    sidechain_test::SideDBScope sideDBs;   // ATMP's contextual checks read the side DBs (TestingSetup makes none)
    int nNext = 0;
    std::vector<FaResult> vResult;

    /** The unit chain starts at block 0 here; ATTEST needs an as-of height above the last attestation and below the
     *  next block, so mine three empty blocks (the BMM path the order harness uses; each connect also writes the chain
     *  clock records). */
    FamilyACostHouseSetup()
    {
        for (int i = 0; i < 3; i++) {
            CBlock block;
            std::string strError;
            BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
                std::vector<CMutableTransaction>(), uint256(), CScript() << OP_TRUE), strError);
            int nBefore = 0;
            {
                LOCK(cs_main);
                block.nTime = chainActive.Tip()->GetMedianTimePast() + 1;
                nBefore = chainActive.Height();
            }
            block.hashMerkleRoot = BlockMerkleRoot(block);
            sidechain_test::ProcessBlockWithoutMainchain(std::make_shared<const CBlock>(block));
            LOCK(cs_main);
            BOOST_REQUIRE_MESSAGE(chainActive.Height() == nBefore + 1, "setup: an empty block didn't connect");
        }
    }

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
        const COutPoint o(uint256S(strprintf("%x", 0xfc000000 + ++nNext)), 0);
        pcoinsTip->AddCoin(o, Coin(CTxOut(nValue, fundKey.script), 1, false, false, false, uint256()), false);
        mapOwned[o] = CTxOut(nValue, fundKey.script);
        return o;
    }
    /** A confirmed P2PKH coin nobody here can sign for, spent with an empty scriptSig: refused at its input script. A
     *  probe that is otherwise valid carries one after its owned fund, so it is refused last (CheckInputs). */
    COutPoint Unowned(CAmount nValue = COIN)
    {
        const COutPoint o(uint256S(strprintf("%x", 0xfc000000 + ++nNext)), 0);
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
    COutPoint FreshOut() { return COutPoint(uint256S(strprintf("%x", 0xfd000000 + ++nNext)), 0); }
    std::vector<CKey> Keys(size_t n)
    {
        std::vector<CKey> v(n);
        for (CKey& k : v)
            k.MakeNewKey(true);
        return v;
    }
    /** An Open house in the DB: one partner per key (tier 3 when there are several), nPledges pledge outpoints and ramp
     *  tranches per partner (HOUSE_MIN_PLEDGE each), registered at block 1, attested at block nLastAttest. */
    CHouse SeedHouse(uint32_t nID, const std::string& strClass, const std::vector<CKey>& vKey, uint32_t nM, size_t nPledges,
                     uint8_t nFlags = 0, uint32_t nLastAttest = 1)
    {
        CHouse h;
        h.nHouseID = nID;
        h.houseID = Hash(strClass.begin(), strClass.end());
        h.nTier = vKey.size() > 1 ? HOUSE_TIER_MULTI_PARTNER : HOUSE_TIER_BONDED_SOLO;
        h.nThresholdM = nM;
        h.strClassID = strClass;
        h.nDenomMgGold = 1000;
        h.vchRedemptionDestPK = FaV(vKey[0].GetPubKey());
        h.nFlags = nFlags;
        h.status = HOUSE_STATUS_OPEN;
        h.nRegisteredHeight = 1;
        h.nLastAttestHeight = nLastAttest;
        for (size_t i = 0; i < vKey.size(); i++) {
            HousePartner p;
            p.vchPubKey = FaV(vKey[i].GetPubKey());
            p.status = HOUSE_PARTNER_ACTIVE;
            for (size_t j = 0; j < nPledges; j++) {
                p.vOutPledge.push_back(FreshOut());
                p.amountPledge += HOUSE_MIN_PLEDGE;
                h.vEscrowTranche.emplace_back((uint32_t)i, HOUSE_MIN_PLEDGE, 1u);
            }
            h.vPartner.push_back(p);
        }
        BOOST_REQUIRE(phousetree->WriteHouse(h));
        return h;
    }
    /** One rate post per house at the tip (in effect from the next block) on the chain clock the connected blocks wrote
     *  (or a fresh one), written to the units DB as a connected block leaves them. */
    void SeedRealClockAndRates(const std::vector<uint32_t>& vHouse)
    {
        static const int64_t DAY = 86400;
        const Consensus::GramParams& gp = Params().GetConsensus().GramAt(1);
        CUnitsView v(punitsdb.get());
        const uint32_t nTip = (uint32_t)chainActive.Height();
        CChainClock clock;
        if (!GetChainClock(v, clock)) {
            for (uint32_t h = 1; h <= nTip; h++)
                AdvanceChainClock(v, h, 300 * DAY + (int64_t)h * 600, gp);
            BOOST_REQUIRE(GetChainClock(v, clock));
        }
        for (uint32_t nHouse : vHouse) {
            std::string strReject;
            BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(v, nHouse, 100000, 101000, nTip, clock.nMonoTime, gp, strReject),
                                  "setup: rate post refused: " + strReject);
        }
        std::map<UnitsKey, UnitsSlot> mapChange, mapBefore;
        v.GetChanges(mapChange, mapBefore);
        BOOST_REQUIRE(punitsdb->WriteBlock(mapChange, mapBefore, chainActive.Tip()->GetBlockHash()));
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
        BOOST_TEST_MESSAGE(strprintf("family A cost: %-64s %7d us min, %7d us median, %6u bytes, refused %s",
                                     strName, r.nMin, r.nMedian, (unsigned)r.nBytes, r.strReason));
        vResult.push_back(r);
        return r;
    }
    /** The plain baseline: a v2 tx of about nBytes (P2PKH outputs), an owned signed fund then an unowned coin, refused at
     *  the second input's script (the probes' shape: each carries one owned,
     *  signed fund since security's rule A step 2, so the baseline pays the same sighash and verify). */
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
            BOOST_CHECK_MESSAGE(r.nMin < 1000, strprintf("family A: %s costs %d us (min; median %d us) before it is refused "
                                                         "(%s), over the 1 ms line", r.strName, r.nMin, r.nMedian, r.strReason));
        }
    }
    /** A zero-reserve ATTEST of house h at as-of the tip with valid approver signatures (indices 0..M-1), from a fresh fund
     *  coin and an unowned coin, change value varied by nSalt so every run has a fresh digest. Refused only at the unowned
     *  coin's empty scriptSig, last. */
    CMutableTransaction ValidZeroAttest(const CHouse& h, const std::vector<CKey>& vKey, int nSalt)
    {
        HouseAttest att;
        att.nHouseID = h.nHouseID;
        att.nSchemaVersion = 1;
        att.nAsOfHeight = (uint32_t)chainActive.Height();
        att.nPrevLastAttestHeight = h.nLastAttestHeight;
        att.nPrevStressSince = h.nStressSinceHeight;
        att.amountPrevReserves = h.amountLastAttestReserves;
        att.nPrevDeferInvokedHeight = h.nDeferInvokedHeight;
        att.nPrevDeferRenewals = h.nDeferRenewals;
        att.nPrevDeferCumBlocks = h.nDeferCumBlocks;
        att.nPrevDeferEndedHeight = h.nDeferEndedHeight;
        att.nPrevCureLeft = h.nCureLeft;
        att.nPrevEpisodeDeferBlocks = h.nEpisodeDeferBlocks;
        att.nPrevEpisodeFloorUsed = h.fEpisodeFloorUsed;
        att.nPrevDeferInEpisode = h.fDeferInEpisode;
        att.amountReserves = 0;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_ATTEST;
        mtx.vin.push_back(CTxIn(Fund()));
        mtx.vin.push_back(CTxIn(Unowned()));   // otherwise valid: refused last, at this input's script
        mtx.vout.emplace_back(2 * COIN - 100000 - nSalt, FaP2PKH(0x5a));
        { CDataStream s0(SER_NETWORK, PROTOCOL_VERSION); s0 << att; mtx.vchHousePayload.assign(s0.begin(), s0.end()); }
        const uint256 sighash = HouseAttestSigHash(CTransaction(mtx), h.houseID);   // Stage 0 C1
        for (uint32_t i = 0; i < h.nThresholdM; i++) {
            att.vApproverIndex.push_back(i);
            att.vApproverSig.push_back(FaSign(vKey[i], sighash));
        }
        mtx.vchHousePayload = FaSer(att);
        return mtx;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(family_a_cost_house_tests, FamilyACostHouseSetup)

// ---------------------------------------------------------------------------
// ATTEST, third party. VerifyReserveProofs (validation.cpp ~596-659) runs before the approvers: per proof a coin read
// and one ECDSA verify by the proof key, which is not an authorizer of the op. Anyone can prove 64 coins of their own
// against any live house (the challenge binds house, as-of and outpoint, so a fresh as-of or house gives fresh work);
// the approver signature is then wrong. The shape check also parses the 64 proof keys before the fee floor.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_house_attest_third_party)
{
    LOCK(cs_main);
    const std::vector<CKey> vApprover = Keys(3);
    const uint32_t nAsOf = (uint32_t)chainActive.Height();
    const CHouse h = SeedHouse(901, "costattest", vApprover, 2, 1, 0, 0);   // last attested at 0: as-of the tip is fresh
    const std::vector<CKey> vProofKey = Keys(MAX_ATTEST_PROOFS);
    const uint256 hashAsOf = chainActive[nAsOf]->GetBlockHash();
    auto fnAttest = [&](size_t nProofs, bool fZeroFee = false) {
        return [&, nProofs, fZeroFee](int i) {
            HouseAttest att;
            att.nHouseID = h.nHouseID;
            att.nSchemaVersion = 1;
            att.nAsOfHeight = nAsOf;
            att.nPrevLastAttestHeight = h.nLastAttestHeight;   // the priors are public (the house record)
            att.nPrevStressSince = h.nStressSinceHeight;
            att.amountPrevReserves = h.amountLastAttestReserves;
            att.nPrevDeferInvokedHeight = h.nDeferInvokedHeight;
            att.nPrevDeferRenewals = h.nDeferRenewals;
            att.nPrevDeferCumBlocks = h.nDeferCumBlocks;
            att.nPrevDeferEndedHeight = h.nDeferEndedHeight;
            att.nPrevCureLeft = h.nCureLeft;
            att.nPrevEpisodeDeferBlocks = h.nEpisodeDeferBlocks;
            att.nPrevEpisodeFloorUsed = h.fEpisodeFloorUsed;
            att.nPrevDeferInEpisode = h.fDeferInEpisode;
            for (size_t n = 0; n < nProofs; n++) {
                // fresh coins each run: fresh challenges, so no signature cache helps
                const COutPoint o = FreshOut();
                const CPubKey pub = vProofKey[n].GetPubKey();
                pcoinsTip->AddCoin(o, Coin(CTxOut(COIN, GetScriptForDestination(pub.GetID())), nAsOf, false, false, false, uint256()), false);
                AttestProof p;
                p.outpoint = o;
                p.vchPubKey = FaV(pub);
                p.vchSig = FaSign(vProofKey[n], HouseAttestChallenge(h.houseID, nAsOf, hashAsOf, o));
                att.vProofs.push_back(p);
                att.amountReserves += COIN;
            }
            att.vApproverIndex = {0, 1};
            att.vApproverSig = {FaWrongSig(vApprover[0]), FaWrongSig(vApprover[1])};   // the third party can't sign
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_HOUSE_VERSION;
            mtx.nHouseOp = HOUSE_OP_ATTEST;
            mtx.nLockTime = (uint32_t)i;
            mtx.vin.push_back(CTxIn(Fund()));
            mtx.vout.emplace_back(fZeroFee ? COIN : COIN - 100000, FaP2PKH(0xa7));
            mtx.vchHousePayload = FaSer(att);
            return mtx;
        };
    };
    // Before the fee floor: the shape check's 64 proof-key parses, refused at the floor (what a zero-fee copy costs).
    Time("house ATTEST, 64 proofs, zero fee (pre-floor shape work only)", fnAttest(MAX_ATTEST_PROOFS, true), 7);
    Time("house ATTEST, third party, 1 proof, approvers wrong", fnAttest(1), 7);
    const FaResult r = Time("house ATTEST, third party, 64 proofs, approvers wrong", fnAttest(MAX_ATTEST_PROOFS), 7);
    Baseline(r.nBytes);
    Check();
}

// ---------------------------------------------------------------------------
// REGISTER. Every founding partner signs (the attacker's own keys: these ARE the op's authorizers, so the order is the
// rule's; the question is only the cost). 64 partners, signatures 1-63 valid, 64 wrong; the shape check parses 65 keys
// (64 partners and the redemption key) before the fee floor. A fresh class id each run gives a fresh declaration digest.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_house_register_64_partners)
{
    LOCK(cs_main);
    const std::vector<CKey> vKey = Keys(MAX_HOUSE_PARTNERS);
    auto fnRegister = [&](bool fZeroFee, bool fOwnedPledge) {
        return [&, fZeroFee, fOwnedPledge](int i) {
        HouseRegister reg;
        reg.nTier = HOUSE_TIER_MULTI_PARTNER;
        reg.nThresholdM = 2;
        reg.strClassID = strprintf("costreg%d%d", i, nNext++);
        reg.nDenomMgGold = 1000;
        reg.vchRedemptionDestPK = FaV(vKey[0].GetPubKey());
        for (const CKey& k : vKey) {
            reg.vPartnerPubKey.push_back(FaV(k.GetPubKey()));
            reg.vPledgeAmount.push_back(HOUSE_MIN_PLEDGE);
        }
        const uint256 declDigest = HouseDeclarationDigest(reg, 0);
        for (size_t n = 0; n < vKey.size(); n++)
            reg.vPartnerSig.push_back(n + 1 < vKey.size() ? FaSign(vKey[n], HouseRegisterSigHash(declDigest, (uint32_t)n, HOUSE_MIN_PLEDGE))
                                                          : FaWrongSig(vKey[n]));
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_REGISTER;
        mtx.vin.push_back(CTxIn(fOwnedPledge ? Fund(10 * COIN) : Unowned(10 * COIN)));
        const CScript escrow = HouseEscrowScript(HouseIDFromDeclaration(reg, 0));
        for (size_t n = 0; n < vKey.size(); n++)
            mtx.vout.emplace_back(HOUSE_MIN_PLEDGE, escrow);
        mtx.vout.emplace_back(10 * COIN - (CAmount)vKey.size() * HOUSE_MIN_PLEDGE - (fZeroFee ? 0 : 100000), FaP2PKH(0x7e));
        mtx.vchHousePayload = FaSer(reg);
        return mtx;
        };
    };
    Time("house REGISTER, 64 partners, zero fee (pre-floor shape work only)", fnRegister(true, false), 7);
    // Security 11-26: self-made partner keys are no standing, so REGISTER counts; the fix verifies every pledge input's
    // script before the partner signatures. Unowned pledge funding: must be refused cheaply then.
    const FaResult r = Time("house REGISTER, 64 partners, unowned pledge input, the last signature wrong", fnRegister(false, false), 7);
    // Owned pledge funding: the partner signatures run, and the failing one must score 100 (not counted for time).
    const FaResult rOwned = Time("house REGISTER, 64 partners, owned pledge input, the last signature wrong (DoS checked)",
                                 fnRegister(false, true), 5, false);
    ExpectDoS100(rOwned);
    Baseline(r.nBytes);
    Check();
}

// ---------------------------------------------------------------------------
// EXIT, third party, on the real clock and rates. The capital check (CapitalCapUnits -> HouseCapitalForChecks:
// the 30-day rate-day reads, then for every active partner a pass over every tranche, two clock reads per counted
// tranche, then the owed reads) runs before the partner's or approvers' signature. A normal house (3 partners, 1
// tranche each) and one built to the caps (64 partners x 64 pledge outpoints = 4,096 tranches; one TOPUP per block).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_house_exit_capital_before_signature)
{
    LOCK(cs_main);
    FaRealScope real;
    const std::vector<CKey> vSmall = Keys(3);
    const std::vector<CKey> vBig = Keys(MAX_HOUSE_PARTNERS);
    const CHouse hSmall = SeedHouse(911, "costexitsmall", vSmall, 2, 1);
    const CHouse hBig = SeedHouse(912, "costexitbig", vBig, 2, MAX_HOUSE_PLEDGE_OUTPOINTS);
    SeedRealClockAndRates({911, 912});
    auto fnExit = [&](const CHouse& h, const std::vector<CKey>& vKey) {
        return [&](int i) {
            HouseExit ex;
            ex.nHouseID = h.nHouseID;
            ex.nPartnerIndex = 1;
            ex.vchPartnerSig = FaWrongSig(vKey[1]);   // the third party can't sign
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_HOUSE_VERSION;
            mtx.nHouseOp = HOUSE_OP_EXIT;
            mtx.nLockTime = (uint32_t)i;
            mtx.vin.push_back(CTxIn(Fund()));
            mtx.vout.emplace_back(COIN - 100000, FaP2PKH(0xe1));
            mtx.vchHousePayload = FaSer(ex);
            return mtx;
        };
    };
    Time("house EXIT, third party, 3 partners x 1 tranche (real clock)", fnExit(hSmall, vSmall), 7);
    const FaResult r = Time("house EXIT, third party, 64 partners x 64 tranches (real clock)", fnExit(hBig, vBig), 7);
    // The same big house with the unit tests' block clock: the clock reads are what the default hides.
    {
        g_fClockIsHeightForTests = true;
        UpdateClockIsHeight(true);
        Time("house EXIT, third party, 64 x 64 tranches (block clock, for scale)", fnExit(hBig, vBig), 7, false);
        g_fClockIsHeightForTests = false;
        UpdateClockIsHeight(false);
    }
    Baseline(r.nBytes);
    Check();
}

// ---------------------------------------------------------------------------
// MEMBER_ADD, insider (the house's own 24 approvers: the reads come after the signatures, so the order is the rule's;
// the question is the cost). A members-only house with 24 partners and M = 24; 256 new keyids; the last prior claims a
// record that isn't there, so every member read runs and the op is refused at the last.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_house_member_add_insider)
{
    LOCK(cs_main);
    const std::vector<CKey> vKey = Keys(MAX_HOUSE_THRESHOLD);
    const CHouse h = SeedHouse(921, "costmember", vKey, MAX_HOUSE_THRESHOLD, 1, HOUSE_FLAG_MEMBERS_ONLY);
    // Security 11-26: work after a signature with standing (the house's approvers) doesn't count against the line; the
    // wrong-prior refusal depends on chain state, so it may stay at DoS 0. Measured for the record.
    const FaResult r = Time("house MEMBER_ADD, insider, 24 approvers, 256 entries, last prior wrong (standing: not counted)", [&](int i) {
        HouseMemberOp op;
        op.nHouseID = h.nHouseID;
        for (size_t n = 0; n < MAX_HOUSE_MEMBER_BATCH; n++) {
            const uint256 r256 = GetRandHash();
            op.vKeyID.push_back(uint160(std::vector<unsigned char>(r256.begin(), r256.begin() + 20)));
            HouseMemberPrior prior;
            if (n + 1 == MAX_HOUSE_MEMBER_BATCH) {
                prior.fPresent = 1;   // wrong: no such record
                prior.rec.nAddHeight = 5;
            }
            op.vPrior.push_back(prior);
        }
        op.nPrevCount = 0;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_MEMBER_ADD;
        mtx.nLockTime = (uint32_t)i;
        mtx.vin.push_back(CTxIn(Fund()));
        mtx.vout.emplace_back(COIN - 100000, FaP2PKH(0x3e));
        { CDataStream s0(SER_NETWORK, PROTOCOL_VERSION); s0 << op; mtx.vchHousePayload.assign(s0.begin(), s0.end()); }
        const uint256 sighash = HouseMemberSigHash(CTransaction(mtx), h.houseID);   // Stage 0 C1
        for (uint32_t n = 0; n < MAX_HOUSE_THRESHOLD; n++) {
            op.vApproverIndex.push_back(n);
            op.vApproverSig.push_back(FaSign(vKey[n], sighash));
        }
        mtx.vchHousePayload = FaSer(op);
        return mtx;
    }, 7, false);
    Baseline(r.nBytes);
    Check();
}

// ---------------------------------------------------------------------------
// The universal slot guard (validation.cpp ~2822-2840) walks the whole mempool (GetHouseStateKeys per pooled tx) for
// every slot-taking or status-reading incomer, after its family check. Not payload growth: pool growth. The incomer is
// a valid zero-reserve ATTEST by a house whose keys the test holds (refused only at its empty scriptSig); the pool is
// filled with addUnchecked: plain txs, then slot-taking ATTESTs of other houses.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_house_slot_guard_scans_the_pool)
{
    LOCK(cs_main);
    const std::vector<CKey> vKey = Keys(3);
    const CHouse h = SeedHouse(931, "costslot", vKey, 2, 1, 0, 0);
    TestMemPoolEntryHelper entry;
    auto fnFillPlain = [&](size_t nTo) {
        while (mempool.size() < nTo) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.vin.push_back(CTxIn(FreshOut()));
            mtx.vout.emplace_back(10000, FaP2PKH(0x91));
            const CTransaction tx(mtx);
            mempool.addUnchecked(tx.GetHash(), entry.Fee(1000).FromTx(tx));
        }
    };
    auto fnFillSlotTakers = [&](size_t nTo) {
        uint32_t nOther = 2000;
        while (mempool.size() < nTo) {
            HouseAttest att;
            att.nHouseID = nOther++;   // other houses: a slot each, never this one
            att.nSchemaVersion = 1;
            att.nAsOfHeight = 1;
            att.vApproverIndex = {0, 1};
            att.vApproverSig = {std::vector<unsigned char>(71, 0x30), std::vector<unsigned char>(71, 0x30)};
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_HOUSE_VERSION;
            mtx.nHouseOp = HOUSE_OP_ATTEST;
            mtx.vin.push_back(CTxIn(FreshOut()));
            mtx.vout.emplace_back(10000, FaP2PKH(0x92));
            mtx.vchHousePayload = FaSer(att);
            const CTransaction tx(mtx);
            mempool.addUnchecked(tx.GetHash(), entry.Fee(1000).FromTx(tx));
        }
    };
    auto fnProbe = [&](int i) { return ValidZeroAttest(h, vKey, i + 10 * (nNext % 1000)); };
    // Control at the same pool size: a plain v2 tx of the same size meets no FreeBank scan.
    auto fnPlain = [&](int i) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.nLockTime = (uint32_t)i;
        mtx.vin.push_back(CTxIn(Fund()));
        mtx.vin.push_back(CTxIn(Unowned()));   // refused last, like the ATTEST probe
        mtx.vout.emplace_back(2 * COIN - 100000, FaP2PKH(0x5b));
        mtx.vout.emplace_back(1000, FaP2PKH(0x5c));
        return mtx;
    };
    Time("slot guard: valid ATTEST, empty pool", fnProbe, 7);
    fnFillPlain(10000);
    Time("slot guard: valid ATTEST, 10,000 plain txs pooled", fnProbe, 7);
    fnFillPlain(50000);
    Time("slot guard: valid ATTEST, 50,000 plain txs pooled", fnProbe, 7);
    Time("control: plain v2 incomer, 50,000 plain txs pooled", fnPlain, 7, false);
    mempool.clear();
    fnFillSlotTakers(50000);
    Time("slot guard: valid ATTEST, 50,000 other houses' ATTESTs pooled", fnProbe, 7);
    mempool.clear();
    Check();
}

BOOST_AUTO_TEST_SUITE_END()
