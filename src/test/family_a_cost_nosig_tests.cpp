// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ===========================================================================
// testing (2026-11-26): family A cost, Stage 0 (D-2026-11-26-1), the "no signature-bearing input" shape. Security's
// ask in its review of mb/stage0-bc (relayed by freebankd 11-26): rule A's step 2 (after the fee floor, ATMP verifies the
// first input whose coin carries a signature: CheckInputScriptEarly, validation.cpp ~1898, InputCarriesSignature ~1930)
// is skipped when no input carries one, e.g. an escrow-funded CLAIM. So such a tx reaches the FreeBank checks with no
// proof that its sender owns anything: the family custody scripts (<push> OP_DROP [<push> OP_DROP] OP_TRUE) are
// anyone-can-spend, restricted only by tags. Each probe here spends ONLY such coins, and they pay the fee.
//
// Which ops can take that shape (checked on testing/stage0-bc 3d2bd6e = mb/stage0-bc 7fd6254 + testing):
//  - bill CLAIM (op 4): exactly one bill escrow coin (tx_verify ~866) plus OPTIONAL plain fee coins, and the holder
//    chooses the outputs, so the escrow can pay the fee. Probed.
//  - note REDEEM, pre-auth DISCHARGE: inputs are the demand's custody coins (NoteDemandCustodyScript), each worth
//    NOTE_DUST_VALUE, which can pay the fee; the pre-auth signature is public in the DEMAND payload. Probed.
//  - NOT this shape (their outputs are pinned to at least the escrow they spend, so the fee needs a plain coin, which
//    carries a signature, so step 2 runs): token COLLECT (payouts exact, escrow out <= entitlement, validation.cpp
//    ~7259-7300), house CLOSE (shares + fund == the live escrow exactly, ~5281-5310), house ESCROW_MERGE (vout[0] == the
//    merged sum, ~5878), bill HCLAIM_ESCROW (vout[0] >= the bond, ~4527). House txs may spend no other family's
//    custody coin (tx_verify ~612-637), so none of those can be funded from custody alone.
//
// Method as family_a_cost_tests (security's 11-26 rulings): min over fresh runs, less a plain v2 tx of the same size in
// the probes' matched shape (one owned signed fund, then an unowned empty-scriptSig coin, refused at the second input),
// or of the same inputs where the work grows with the inputs. Timing reports unless FAMILY_A_COST_ENFORCE=1.
// ===========================================================================

#include <arith_uint256.h>
#include <bill.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <house.h>
#include <houserate.h>
#include <issued.h>
#include <key.h>
#include <keystore.h>
#include <note.h>
#include <policy/policy.h>
#include <random.h>
#include <script/sign.h>
#include <script/standard.h>
#include <test/sidechain_test_util.h>
#include <test/test_bitcoin.h>
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

std::vector<unsigned char> NsV(const CPubKey& p) { return std::vector<unsigned char>(p.begin(), p.end()); }

template <typename T>
std::vector<unsigned char> NsSer(const T& x)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << x;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CScript NsP2PKH(unsigned char c) { return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, c) << OP_EQUALVERIFY << OP_CHECKSIG; }

struct NsResult {
    std::string strName;
    int64_t nMin = 0;
    int64_t nMedian = 0;
    size_t nBytes = 0;
    std::string strReason;
    int nDoS = 0;
    int64_t nBase = 0;
    bool fCounts = true;
};

struct FamilyACostNoSigSetup : public TestChain100Setup {
    sidechain_test::SideDBScope sideDBs;
    int nNext = 0;
    std::vector<NsResult> vResult;
    CKey keyFund;
    CBasicKeyStore keystore;
    CScript scriptFund;
    std::map<COutPoint, CTxOut> mapOwned;

    FamilyACostNoSigSetup()
    {
        keyFund.MakeNewKey(true);
        keystore.AddKey(keyFund);
        scriptFund = GetScriptForDestination(keyFund.GetPubKey().GetID());
    }
    COutPoint NewOutPoint() { return COutPoint(uint256S(strprintf("%x", 0xf5000000 + ++nNext)), 0); }
    COutPoint Fund(CAmount nValue = COIN)
    {
        const COutPoint o = NewOutPoint();
        pcoinsTip->AddCoin(o, Coin(CTxOut(nValue, scriptFund), 1, false, false, false, uint256()), false);
        mapOwned[o] = CTxOut(nValue, scriptFund);
        return o;
    }
    COutPoint Unowned(CAmount nValue = COIN)
    {
        const COutPoint o = NewOutPoint();
        pcoinsTip->AddCoin(o, Coin(CTxOut(nValue, NsP2PKH(0xf5)), 1, false, false, false, uint256()), false);
        return o;
    }
    void SignOwned(CMutableTransaction& mtx)
    {
        for (unsigned int i = 0; i < mtx.vin.size(); i++) {
            const auto it = mapOwned.find(mtx.vin[i].prevout);
            if (it != mapOwned.end())
                BOOST_REQUIRE(SignSignature(keystore, it->second.scriptPubKey, mtx, i, it->second.nValue, SIGHASH_ALL));
        }
    }
    /** ATMP on nRuns fresh probes; each must be refused (the probe builder makes every run new). */
    NsResult Time(const std::string& strName, const std::function<CMutableTransaction(int)>& fnBuild, int nRuns)
    {
        NsResult r;
        r.strName = strName;
        std::vector<int64_t> v;
        for (int i = 0; i < nRuns; i++) {
            CMutableTransaction mtx = fnBuild(i);
            SignOwned(mtx);
            const CTransactionRef ptx = MakeTransactionRef(std::move(mtx));
            r.nBytes = ::GetSerializeSize(*ptx, SER_NETWORK, PROTOCOL_VERSION);
            CValidationState state;
            const int64_t t0 = GetTimeMicros();
            const bool fOk = AcceptToMemoryPool(mempool, state, ptx, nullptr, nullptr, false, 0);
            v.push_back(GetTimeMicros() - t0);
            BOOST_REQUIRE_MESSAGE(!fOk, "family A cost (no-sig): a probe was accepted (" + strName + ")");
            r.strReason = state.GetRejectReason();
            int nDoS = 0;
            state.IsInvalid(nDoS);
            r.nDoS = nDoS;
        }
        std::sort(v.begin(), v.end());
        r.nMin = v.front();
        r.nMedian = v[v.size() / 2];
        return r;
    }
    /** The matched plain baseline of about nBytes: an owned signed fund, an unowned coin, P2PKH outputs; refused at the
     *  second input's script. */
    int64_t PlainSameSize(size_t nBytes)
    {
        const NsResult r = Time(strprintf("baseline: plain v2, ~%u bytes", (unsigned)nBytes), [&](int) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.vin.push_back(CTxIn(Fund()));
            mtx.vin.push_back(CTxIn(Unowned()));
            const size_t nOut = std::max<size_t>(1, nBytes / 34);
            for (size_t j = 0; j < nOut; j++)
                mtx.vout.emplace_back(COIN / 2 / nOut, NsP2PKH(0x0b));
            return mtx;
        }, 7);
        Report(r, false);
        return r.nMin;
    }
    /** The same-inputs plain baseline: a v2 tx spending nInputs unowned P2PKH coins (refused at the first input's script,
     *  CheckInputs), for probes whose work grows with the inputs (security 11-26). */
    int64_t PlainSameInputs(size_t nInputs)
    {
        std::vector<COutPoint> vIn;
        for (size_t i = 0; i < nInputs; i++)
            vIn.push_back(Unowned(10000));
        const NsResult r = Time(strprintf("baseline: plain v2, %u unowned inputs", (unsigned)nInputs), [&](int i) {
            CMutableTransaction mtx;
            mtx.nVersion = 2;
            mtx.nLockTime = (uint32_t)i;
            for (const COutPoint& o : vIn)
                mtx.vin.push_back(CTxIn(o));
            mtx.vout.emplace_back((CAmount)nInputs * 10000 - 200000, NsP2PKH(0x0c));
            return mtx;
        }, 5);
        Report(r, false);
        return r.nMin;
    }
    void Report(NsResult r, bool fCounts, int64_t nBase = 0)
    {
        r.fCounts = fCounts;
        r.nBase = nBase;
        BOOST_TEST_MESSAGE(strprintf("family A cost (no-sig): %-72s %7d us min, %7d us median, %6u bytes; over plain %6d us; "
                                     "refused %s, DoS %d%s", r.strName, r.nMin, r.nMedian, (unsigned)r.nBytes,
                                     fCounts ? r.nMin - nBase : r.nMin, r.strReason, r.nDoS, fCounts ? "" : " (baseline)"));
        vResult.push_back(r);
    }
    void Check()
    {
        for (const NsResult& r : vResult) {
            if (!r.fCounts || !FamilyACostEnforced())
                continue;
            BOOST_CHECK_MESSAGE(r.nMin - r.nBase < 1000,
                                strprintf("family A (no-sig): %s costs %d us over plain (min %d us, plain %d us) before it is "
                                          "refused (%s): over the 1 ms line", r.strName, r.nMin - r.nBase, r.nMin, r.nBase,
                                          r.strReason));
        }
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(family_a_cost_nosig_tests, FamilyACostNoSigSetup)

// ---------------------------------------------------------------------------
// bill CLAIM (op 4) funded by the bill's escrow alone. A defaulted (past maturity + grace) holder-held bill's escrow is
// anyone-can-spend by script; the holder's payload signature is the authorizer (validation.cpp ~4283). Before it: the
// bill read, TermDeadlineHeight (clock reads; a binary search on the real clock), and the C1 digest over the whole tx.
// The probe: the escrow as the only input paying the fee, 256 outputs (MAX_STANDARD_FREEBANK_OUTPUTS) to fill the tx,
// a well-formed signature by the wrong key (a full ECDSA verify that fails), fresh nLockTime each run.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_nosig_bill_claim_escrow_only)
{
    LOCK(cs_main);
    CKey keyHolder, keyWrong;
    keyHolder.MakeNewKey(true);
    keyWrong.MakeNewKey(true);
    CBill bill;
    bill.nBillID = 1;
    bill.billID = uint256S("b111c1a1");
    bill.amount = 10000;
    bill.amountEscrow = COIN;
    bill.nIssuedHeight = 0;
    bill.nMaturityHeight = 0;
    bill.nGraceBlocks = 0;
    bill.vchDrawerPubKey = NsV(keyWrong.GetPubKey());
    bill.vchAcceptorPubKey = NsV(keyWrong.GetPubKey());
    bill.vchHolderPubKey = NsV(keyHolder.GetPubKey());
    bill.nRefHouseID = 5;
    bill.nOwnerHouseID = 0;
    bill.status = BILL_STATUS_ACTIVE;
    const COutPoint escrow = NewOutPoint();
    bill.outEscrow = escrow;
    bill.outTitle = NewOutPoint();
    BOOST_REQUIRE(pbilltree->WriteBills({bill}));
    BOOST_REQUIRE(pbilltree->WriteLastBillID(1));
    Coin c(CTxOut(bill.amountEscrow, BillEscrowScript(bill.billID)), 1, false, false, false, uint256());
    c.SetBill(true, bill.nBillID);
    pcoinsTip->AddCoin(escrow, std::move(c), false);

    auto fnProbe = [&](size_t nOut, bool fRightKey) {
        return [&, nOut, fRightKey](int i) {
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_BILL_VERSION;
            mtx.nBillOp = BILL_OP_CLAIM;
            mtx.nLockTime = (uint32_t)(i + 1 + nNext++);
            mtx.vin.push_back(CTxIn(escrow));
            const CAmount amountEach = (COIN - 500000) / (CAmount)nOut;
            for (size_t o = 0; o < nOut; o++)
                mtx.vout.emplace_back(amountEach, NsP2PKH((unsigned char)(o & 0xff)));
            BillClaim claim;
            claim.nBillID = bill.nBillID;
            mtx.vchBillPayload = NsSer(claim);   // C1: the digest strips the signature
            std::vector<unsigned char> vchSig;
            BOOST_REQUIRE((fRightKey ? keyHolder : keyWrong).Sign(BillClaimSigHash(CTransaction(mtx), bill.billID, false), vchSig));
            claim.vchHolderSig = vchSig;
            mtx.vchBillPayload = NsSer(claim);
            return mtx;
        };
    };
    // Control: the holder's own signature is accepted (so the probe was valid up to the signature), then evicted.
    {
        CMutableTransaction mtx = fnProbe(1, true)(0);
        CValidationState state;
        const bool fOk = AcceptToMemoryPool(mempool, state, MakeTransactionRef(mtx), nullptr, nullptr, false, 0);
        BOOST_CHECK_MESSAGE(fOk, "no-sig bill CLAIM control: the holder's own claim was refused: " + state.GetRejectReason());
        mempool.clear();
    }
    const NsResult r1 = Time("bill CLAIM, escrow the only input, 1 output, wrong-key signature", fnProbe(1, false), 7);
    const NsResult rMax = Time(strprintf("bill CLAIM, escrow the only input, %u outputs, wrong-key signature",
                                         (unsigned)MAX_STANDARD_FREEBANK_OUTPUTS), fnProbe(MAX_STANDARD_FREEBANK_OUTPUTS, false), 7);
    // Not on the real clock: TestChain100's blocks have no clock records, so TermDeadlineHeight never passes there and the
    // probe stops at bad-bill-claim-early (the gate's binary search is the map's ~22 reads, bounded by shape).
    for (const NsResult* p : std::vector<const NsResult*>{&r1, &rMax})
        BOOST_CHECK_MESSAGE(p->strReason == "bad-bill-claim-sig", "no-sig bill CLAIM: " + p->strName + " refused at " +
                            p->strReason + ", not at the holder signature");
    Report(r1, true, PlainSameSize(r1.nBytes));
    const int64_t nPlainMax = PlainSameSize(rMax.nBytes);
    Report(rMax, true, nPlainMax);
    Check();
}

// ---------------------------------------------------------------------------
// note REDEEM, pre-auth DISCHARGE, inputs only the demand's custody coins (NoteDemandCustodyScript: anyone-can-spend by
// script, pinned to the holder's keyid by tx_verify), their dust paying the fee. The pre-auth signature is the holder's
// standing authorisation, public in the DEMAND payload, so anyone can send this. Before the refusal
// (bad-note-redeem-interest-short, validation.cpp ~6492): the house read and status, an O(vin) TipCoin loop with the
// custody demand id (~6362), the pre-auth verify (cached after the first run: the digest never changes), the bound
// rate, the brassage, an O(vin) demand-tag loop (~6444), NoteDemandInterest, fnPaidMg over the outputs. Probed at one
// coin and at ~2,400 coins (one demand of 2,400 coins: the holder's own notes). Measured 11-26 on DEV (load ~6): 7.9 ms,
// 1.5 ms over a plain tx spending 2,400 unowned coins (6.4 ms) and 6.1 ms over a plain tx of the same size; refused at
// DoS 0, so it repeats for free with a new nLockTime. FAILS the 1 ms line until the per-input work is cut: the custody
// keyid hashed once per input (tx_verify.cpp ~735, NoteCustodyKeyIs) and CheckNoteOperation's O(vin) loops before the
// floor check (validation.cpp ~6362, ~6444).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(family_a_cost_nosig_preauth_discharge_custody_only)
{
    LOCK(cs_main);
    const uint32_t nHouseID = 77;
    CKey keyApprover, keyHolder;
    keyApprover.MakeNewKey(true);
    keyHolder.MakeNewKey(true);
    const std::vector<unsigned char> vchHolder = NsV(keyHolder.GetPubKey());
    const uint64_t nUnitsPerCoin = 1000000;   // 1 g a coin: the 1,000-sat payout is far short of the floor
    const size_t nMax = 2400;

    CHouse house;
    house.nHouseID = nHouseID;
    house.houseID = ArithToUint256(arith_uint256(0xf50000 + nHouseID));
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "ns77";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1;
    house.nMintedUnits = 10 * nMax * nUnitsPerCoin;
    house.nLastAttestHeight = (uint32_t)chainActive.Height();
    house.amountLastAttestReserves = 100 * COIN;
    HousePartner partner;
    partner.vchPubKey = NsV(keyApprover.GetPubKey());
    partner.amountPledge = COIN;
    partner.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(partner);
    BOOST_REQUIRE(phousetree->WriteHouse(house));

    const CScript scriptPayout = NsP2PKH(0x77);
    const std::vector<unsigned char> vchPayout(scriptPayout.begin(), scriptPayout.end());
    auto fnDemand = [&](size_t nCoins) {
        // One demand of nCoins custody coins (its id opaque here: what the coins carry is what the digest must name).
        const uint256 demandId = GetRandHash();
        const uint32_t nTag = NoteDemandTag(50, NOTE_DEMAND_MODE_PREAUTH);
        std::vector<COutPoint> vCoin;
        for (size_t i = 0; i < nCoins; i++) {
            const COutPoint o = NewOutPoint();
            Coin c(CTxOut(NOTE_DUST_VALUE, NoteDemandCustodyScript(vchHolder, demandId)), 50, false, false, false, uint256());
            c.SetNote(nHouseID, nUnitsPerCoin, nTag);
            pcoinsTip->AddCoin(o, std::move(c), false);
            vCoin.push_back(o);
        }
        NoteRedeem redeem;
        redeem.nHouseID = nHouseID;
        redeem.vchHolderPubKey = vchHolder;
        redeem.fPreAuthDischarge = 1;
        redeem.vPreAuthUnits.push_back(nCoins * nUnitsPerCoin);
        redeem.vchPayoutScript = vchPayout;
        BOOST_REQUIRE(keyHolder.Sign(NotePreAuthSigHash(nHouseID, redeem.vPreAuthUnits, redeem.vchPayoutScript, demandId),
                                     redeem.vchPreAuthSig));
        return std::make_pair(vCoin, redeem);
    };
    auto fnProbe = [&](const std::pair<std::vector<COutPoint>, NoteRedeem>& d) {
        return [&, d](int i) {
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_NOTE_VERSION;
            mtx.nNoteOp = NOTE_OP_REDEEM;
            mtx.nLockTime = (uint32_t)(i + 1 + nNext++);
            for (const COutPoint& o : d.first)
                mtx.vin.push_back(CTxIn(o));
            // The payout, short of the floor (units + interest); the custody dust pays the fee.
            mtx.vout.emplace_back(NOTE_DUST_VALUE, scriptPayout);
            mtx.vchNotePayload = NsSer(d.second);
            return mtx;
        };
    };
    const auto dMax = fnDemand(nMax);
    // The fee: one coin's dust (1,000 sats) less the 1,000-sat payout is zero, so a one-coin probe is refused at the
    // floor; the small probe has two coins.
    const auto d2 = fnDemand(2);
    const NsResult r2 = Time("note pre-auth DISCHARGE, 2 custody coins only, payout short", fnProbe(d2), 7);
    const NsResult rMax = Time(strprintf("note pre-auth DISCHARGE, %u custody coins only, payout short", (unsigned)nMax),
                               fnProbe(dMax), 5);
    for (const NsResult* p : std::vector<const NsResult*>{&r2, &rMax})
        BOOST_CHECK_MESSAGE(p->strReason == "bad-note-redeem-interest-short", "no-sig DISCHARGE: " + p->strName +
                            " refused at " + p->strReason + ", not at the payout floor (the late refusal)");
    Report(r2, true, PlainSameSize(r2.nBytes));
    const int64_t nPlainSize = PlainSameSize(rMax.nBytes);
    const int64_t nPlainInputs = PlainSameInputs(nMax);
    NsResult rSize = rMax;
    rSize.strName += " (vs same size)";
    Report(rSize, false, nPlainSize);
    BOOST_TEST_MESSAGE(strprintf("family A cost (no-sig): %u-coin DISCHARGE over the same-size plain: %d us (reported); over "
                                 "the same-inputs plain (security's baseline for work that grows with inputs): %d us",
                                 (unsigned)nMax, rMax.nMin - nPlainSize, rMax.nMin - nPlainInputs));
    Report(rMax, true, nPlainInputs);
    Check();
}

BOOST_AUTO_TEST_SUITE_END()
