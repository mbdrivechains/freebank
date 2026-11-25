// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <house.h>
#include <houserate.h>       // CShortfallLedger, ShortfallLedgerKey (S2X-6)
#include <issued.h>

#include <bill.h>            // MAX_BILL_TENOR_BLOCKS, LOAN_BOOK_MAX_FACE (B1)
#include <chainparams.h>     // SelectParams / CreateChainParams (v0.2.18 silence clock)
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deposit.h>         // MAX_DEPOSIT_TERM_BLOCKS (B1 max-magnitude vectors)
#include <key.h>
#include <note.h>
#include <token.h>           // TokenClaimSigHash (UR-ext-13)
#include <pool.h>            // Pool*SigHash (UR-ext-13 case 3)
#include <script/standard.h>
#include <settle.h>          // SettleExchange, MAX_SETTLE_PAYLOAD (UR1-3: the EXCHANGE carries both approver sets)
#include <streams.h>
#include <test/sidechain_test_util.h>   // SideDBScope (the equity proof reads the bill DB)
#include <test/test_bitcoin.h>
#include <txmempool.h>
#include <txdb.h>              // HouseDB (UR-ext-10)
#include <units.h>             // CUnitsView (S2X-6)
#include <policy/policy.h>     // IsStandardTx (MM-1)
#include <utilstrencodings.h>
#include <validation.h>        // HouseOverdueBills, pbilltree
#include <version.h>

#include <functional>

#include <boost/test/unit_test.hpp>

// Contextual house-op validator (validation.cpp, external linkage; not in a
// public header). Forward-declared here so the negative direction of every 3.5
// consensus guard - previously reachable only through the wallet, which never
// builds a rejectable tx - can be exercised directly (R-i6 test-quality fixes).
bool CheckHouseOperation(const CTransaction& tx, CValidationState& state, int nHeight,
                         const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                         const std::function<bool(const uint256&)>& fnHaveHouseHash,
                         const std::function<bool(const std::string&)>& fnHaveClassID,
                         const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                         const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                         CHouse& houseOut, bool fMempool = false);

BOOST_FIXTURE_TEST_SUITE(house_tests, BasicTestingSetup)

// Build a fully valid REGISTER tx for nPartners partners at the given tier
static CMutableTransaction MakeRegisterTx(HouseRegister& regOut, std::vector<CKey>& vKey,
                                          uint8_t nTier, uint32_t nThresholdM, size_t nPartners,
                                          const std::string& strClassID = "clyde")
{
    HouseRegister reg;
    reg.nTier = nTier;
    reg.nThresholdM = nThresholdM;
    reg.strClassID = strClassID;
    reg.nDenomMgGold = 1000;

    CKey keyRedemption;
    keyRedemption.MakeNewKey(true);
    CPubKey pubRedemption = keyRedemption.GetPubKey();
    reg.vchRedemptionDestPK = std::vector<unsigned char>(pubRedemption.begin(), pubRedemption.end());

    vKey.clear();
    for (size_t i = 0; i < nPartners; i++) {
        CKey key;
        key.MakeNewKey(true);
        CPubKey pub = key.GetPubKey();
        reg.vPartnerPubKey.push_back(std::vector<unsigned char>(pub.begin(), pub.end()));
        reg.vPledgeAmount.push_back(HOUSE_MIN_PLEDGE * (i + 1));
        vKey.push_back(key);
    }

    const uint256 declDigest = HouseDeclarationDigest(reg);
    for (size_t i = 0; i < nPartners; i++) {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(vKey[i].Sign(HouseRegisterSigHash(declDigest, i, reg.vPledgeAmount[i]), vchSig));
        reg.vPartnerSig.push_back(vchSig);
    }

    const uint256 houseID = HouseIDFromDeclaration(reg);

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_REGISTER;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << reg;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());

    // funding input placeholder (prevout must be non-null for CheckTransaction)
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));

    for (size_t i = 0; i < nPartners; i++)
        mtx.vout.push_back(CTxOut(reg.vPledgeAmount[i], HouseEscrowScript(houseID)));

    regOut = reg;
    return mtx;
}

BOOST_AUTO_TEST_CASE(house_id_derivation)
{
    // Content-derived, deterministic, and sensitive to every declaration field
    HouseRegister reg;
    std::vector<CKey> vKey;
    MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);

    const uint256 id1 = HouseIDFromDeclaration(reg);
    BOOST_CHECK(!id1.IsNull());
    BOOST_CHECK(HouseIDFromDeclaration(reg) == id1);

    HouseRegister reg2 = reg;
    reg2.strClassID = "other";
    BOOST_CHECK(HouseIDFromDeclaration(reg2) != id1);

    HouseRegister reg3 = reg;
    reg3.vPledgeAmount[0] += 1;
    BOOST_CHECK(HouseIDFromDeclaration(reg3) != id1);
}

BOOST_AUTO_TEST_CASE(house_sighash_domain_separation)
{
    // Every op sighash must differ for identical field values
    const uint256 h = uint256S("aa");
    std::vector<unsigned char> pk(33, 0x02);

    const uint256 outs = uint256S("cc");
    std::vector<uint256> v;
    v.push_back(HouseRegisterSigHash(h, 0, 1000));
    const uint256 ins = uint256S("bb");   // S1X-16: the four approval digests bind the inputs
    v.push_back(HouseTopupSigHash(h, 0, ins, h));
    v.push_back(HouseAdmitSigHash(h, pk, 1000, 500));
    v.push_back(HouseExitSigHash(h, 0, ins, outs));
    v.push_back(HouseWinddownSigHash(h, ins, outs));
    v.push_back(HouseReclaimSigHash(h, 0, ins, h));

    for (size_t i = 0; i < v.size(); i++) {
        for (size_t j = i + 1; j < v.size(); j++)
            BOOST_CHECK(v[i] != v[j]);
    }

    // And distinct from the bill domain (same-family escrow scripts)
    BOOST_CHECK(HouseWinddownSigHash(h, ins, outs) != HouseExitSigHash(h, 0, ins, outs));

    // Exit/winddown sighashes must actually vary with the output set (freshness)
    BOOST_CHECK(HouseExitSigHash(h, 0, ins, outs) != HouseExitSigHash(h, 0, ins, uint256S("dd")));
    BOOST_CHECK(HouseWinddownSigHash(h, ins, outs) != HouseWinddownSigHash(h, ins, uint256S("dd")));
    // S1X-16: and with the inputs (no replay by whoever funds the same outputs), and the admit with its expiry
    BOOST_CHECK(HouseExitSigHash(h, 0, ins, outs) != HouseExitSigHash(h, 0, uint256S("dd"), outs));
    BOOST_CHECK(HouseWinddownSigHash(h, ins, outs) != HouseWinddownSigHash(h, uint256S("dd"), outs));
    BOOST_CHECK(HouseTopupSigHash(h, 0, ins, outs) != HouseTopupSigHash(h, 0, uint256S("dd"), outs));
    BOOST_CHECK(HouseReclaimSigHash(h, 0, ins, outs) != HouseReclaimSigHash(h, 0, uint256S("dd"), outs));
    BOOST_CHECK(HouseAdmitSigHash(h, pk, 1000, 500) != HouseAdmitSigHash(h, pk, 1000, 501));
}

BOOST_AUTO_TEST_CASE(house_escrow_script)
{
    const uint256 houseID = uint256S("1234");
    const CScript script = HouseEscrowScript(houseID);
    BOOST_CHECK(IsHouseEscrowScript(script));
    BOOST_CHECK_EQUAL(script.size(), 35);

    BOOST_CHECK(!IsHouseEscrowScript(CScript()));
    BOOST_CHECK(!IsHouseEscrowScript(CScript() << OP_TRUE));
}

BOOST_AUTO_TEST_CASE(house_class_id_rules)
{
    BOOST_CHECK(IsValidHouseClassID("clyde"));
    BOOST_CHECK(IsValidHouseClassID("a"));
    BOOST_CHECK(IsValidHouseClassID("x123abc"));
    BOOST_CHECK(IsValidHouseClassID("0123456789abcdef"));   // 16 chars

    BOOST_CHECK(!IsValidHouseClassID(""));
    BOOST_CHECK(!IsValidHouseClassID("0123456789abcdefg"));  // 17
    BOOST_CHECK(!IsValidHouseClassID("Clyde"));              // uppercase
    BOOST_CHECK(!IsValidHouseClassID("cly de"));             // space
    BOOST_CHECK(!IsValidHouseClassID("cly-de"));             // punctuation
}

BOOST_AUTO_TEST_CASE(house_payload_roundtrip)
{
    HouseRegister reg;
    std::vector<CKey> vKey;
    MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 2, 3);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << reg;
    HouseRegister reg2;
    BOOST_REQUIRE(DecodeHousePayload(std::vector<unsigned char>(ss.begin(), ss.end()), reg2));
    BOOST_CHECK_EQUAL(reg2.nTier, reg.nTier);
    BOOST_CHECK_EQUAL(reg2.nThresholdM, reg.nThresholdM);
    BOOST_CHECK_EQUAL(reg2.strClassID, reg.strClassID);
    BOOST_CHECK(reg2.vPartnerPubKey == reg.vPartnerPubKey);
    BOOST_CHECK(reg2.vPledgeAmount == reg.vPledgeAmount);

    // Trailing bytes rejected
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << reg;
    ss2 << uint8_t(0xff);
    BOOST_CHECK(!DecodeHousePayload(std::vector<unsigned char>(ss2.begin(), ss2.end()), reg2));

    // The other payloads round-trip too
    HouseReclaim rec;
    rec.nHouseID = 7;
    rec.nPartnerIndex = 2;
    rec.vchSig = std::vector<unsigned char>(70, 0x30);
    CDataStream ss3(SER_NETWORK, PROTOCOL_VERSION);
    ss3 << rec;
    HouseReclaim rec2;
    BOOST_REQUIRE(DecodeHousePayload(std::vector<unsigned char>(ss3.begin(), ss3.end()), rec2));
    BOOST_CHECK_EQUAL(rec2.nHouseID, 7);
    BOOST_CHECK_EQUAL(rec2.nPartnerIndex, 2);
}

BOOST_AUTO_TEST_CASE(house_tx_serialization_roundtrip)
{
    HouseRegister reg;
    std::vector<CKey> vKey;
    CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mtx;
    CMutableTransaction mtx2;
    ss >> mtx2;
    BOOST_CHECK_EQUAL(mtx2.nVersion, TRANSACTION_HOUSE_VERSION);
    BOOST_CHECK_EQUAL(mtx2.nHouseOp, HOUSE_OP_REGISTER);
    BOOST_CHECK(mtx2.vchHousePayload == mtx.vchHousePayload);
    BOOST_CHECK(CTransaction(mtx2).GetHash() == CTransaction(mtx).GetHash());
}

BOOST_AUTO_TEST_CASE(house_register_shape_valid)
{
    // All four tiers pass the context-free shape checks
    CValidationState state;
    HouseRegister reg;
    std::vector<CKey> vKey;

    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1, "t0solo")), state));
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_ENCUMBERED_SOLO, 1, 1, "t1solo")), state));
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2, "t2multi")), state));
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 3, 5, "t3multi")), state));
}

BOOST_AUTO_TEST_CASE(house_register_shape_rejections)
{
    CValidationState state;
    HouseRegister reg;
    std::vector<CKey> vKey;

    // Solo with 2 partners
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 2);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Multi with 1 partner
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 1, 1);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Multi-partner tier with threshold M=1 (single-point control) rejected
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 1, 3);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 1, 2);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Threshold above the set size
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, 4, 3);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Bad class id
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1, "BADID");
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Pledge below floor: rebuild payload with a sub-minimum pledge
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);
        HouseRegister bad = reg;
        bad.vPledgeAmount[0] = HOUSE_MIN_PLEDGE - 1;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << bad;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vout[0].nValue = HOUSE_MIN_PLEDGE - 1;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Escrow output value mismatching the declared pledge
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);
        mtx.vout[0].nValue += 1;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Duplicate partner key
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2);
        HouseRegister bad = reg;
        bad.vPartnerPubKey[1] = bad.vPartnerPubKey[0];
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << bad;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        const uint256 houseID = HouseIDFromDeclaration(bad);
        mtx.vout[0].scriptPubKey = HouseEscrowScript(houseID);
        mtx.vout[1].scriptPubKey = HouseEscrowScript(houseID);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    // Zero denomination
    {
        CMutableTransaction mtx = MakeRegisterTx(reg, vKey, HOUSE_TIER_BONDED_SOLO, 1, 1);
        HouseRegister bad = reg;
        bad.nDenomMgGold = 0;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << bad;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        const uint256 houseID = HouseIDFromDeclaration(bad);
        mtx.vout[0].scriptPubKey = HouseEscrowScript(houseID);
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
    }
}

BOOST_AUTO_TEST_CASE(house_approver_shape_rules)
{
    // Exercised through the ADMIT shape path: duplicate / descending approver
    // indices and mismatched sig arrays must be rejected
    CValidationState state;

    HouseAdmit admit;
    admit.nHouseID = 1;
    CKey keyNew;
    keyNew.MakeNewKey(true);
    CPubKey pubNew = keyNew.GetPubKey();
    admit.vchNewPubKey = std::vector<unsigned char>(pubNew.begin(), pubNew.end());
    admit.vchNewSig = std::vector<unsigned char>(70, 0x30);
    admit.vApproverIndex = {0, 1};
    admit.vApproverSig = {std::vector<unsigned char>(70, 0x30), std::vector<unsigned char>(70, 0x30)};

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_ADMIT;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(HOUSE_MIN_PLEDGE, HouseEscrowScript(uint256S("aa"))));

    auto encode = [&](const HouseAdmit& a) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << a;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    };

    encode(admit);
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(mtx), state));

    // Duplicate index
    HouseAdmit bad = admit;
    bad.vApproverIndex = {1, 1};
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));

    // Descending order
    bad = admit;
    bad.vApproverIndex = {1, 0};
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));

    // Sig / index count mismatch
    bad = admit;
    bad.vApproverSig.pop_back();
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));

    // No approvers at all
    bad = admit;
    bad.vApproverIndex.clear();
    bad.vApproverSig.clear();
    encode(bad);
    BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
}

BOOST_AUTO_TEST_CASE(house_register_sig_binding)
{
    // A founding signature must break if the declaration or the signer's own
    // pledge amount changes (anti front-run binding)
    HouseRegister reg;
    std::vector<CKey> vKey;
    MakeRegisterTx(reg, vKey, HOUSE_TIER_RESTRICTED, 2, 2);

    const uint256 declDigest = HouseDeclarationDigest(reg);
    const uint256 sighash = HouseRegisterSigHash(declDigest, 0, reg.vPledgeAmount[0]);
    BOOST_CHECK(CPubKey(reg.vPartnerPubKey[0]).Verify(sighash, reg.vPartnerSig[0]));

    // Different pledge -> different sighash -> signature no longer verifies
    const uint256 sighashBad = HouseRegisterSigHash(declDigest, 0, reg.vPledgeAmount[0] + 1);
    BOOST_CHECK(!CPubKey(reg.vPartnerPubKey[0]).Verify(sighashBad, reg.vPartnerSig[0]));

    // Different partner index (same amount) also breaks
    const uint256 sighashIdx = HouseRegisterSigHash(declDigest, 1, reg.vPledgeAmount[0]);
    BOOST_CHECK(!CPubKey(reg.vPartnerPubKey[0]).Verify(sighashIdx, reg.vPartnerSig[0]));

    // Mutated declaration (class id) breaks every founding signature
    HouseRegister reg2 = reg;
    reg2.strClassID = "other";
    const uint256 declDigest2 = HouseDeclarationDigest(reg2);
    const uint256 sighash2 = HouseRegisterSigHash(declDigest2, 0, reg2.vPledgeAmount[0]);
    BOOST_CHECK(!CPubKey(reg.vPartnerPubKey[0]).Verify(sighash2, reg.vPartnerSig[0]));
}

BOOST_AUTO_TEST_CASE(house_record_serialization)
{
    CHouse house;
    house.nHouseID = 42;
    house.houseID = uint256S("beef");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 2;
    house.strClassID = "ayr";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 100;

    HousePartner p1;
    p1.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p1.amountPledge = HOUSE_MIN_PLEDGE;
    p1.vOutPledge.push_back(COutPoint(uint256S("aa"), 0));
    p1.status = HOUSE_PARTNER_ACTIVE;

    HousePartner p2 = p1;
    p2.status = HOUSE_PARTNER_TAIL;
    p2.nTailUnlockHeight = 158000;

    house.vPartner.push_back(p1);
    house.vPartner.push_back(p2);

    // Active-escrow counts ACTIVE pledges only (CM-2)
    BOOST_CHECK_EQUAL(house.ActiveEscrow(), HOUSE_MIN_PLEDGE);
    BOOST_CHECK_EQUAL(house.ActivePartnerCount(), 1);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    CHouse house2;
    ss >> house2;
    BOOST_CHECK_EQUAL(house2.nHouseID, 42);
    BOOST_CHECK_EQUAL(house2.strClassID, "ayr");
    BOOST_CHECK_EQUAL(house2.vPartner.size(), 2);
    BOOST_CHECK_EQUAL(house2.vPartner[1].status, HOUSE_PARTNER_TAIL);
    BOOST_CHECK_EQUAL(house2.vPartner[1].nTailUnlockHeight, 158000);
    BOOST_CHECK_EQUAL(house2.ActiveEscrow(), HOUSE_MIN_PLEDGE);
}

BOOST_AUTO_TEST_CASE(house_serialization_v2_attest_fields)
{
    // 3.4 fields round-trip; version byte guards the layout (D10)
    CHouse house;
    house.nHouseID = 7;
    house.strClassID = "paisley";
    {
        HousePartner p;
        p.vchPubKey = std::vector<unsigned char>(33, 0x02);
        p.amountPledge = HOUSE_MIN_PLEDGE;
        p.amountInsolventPledge = 12345;   // residual weight (review fix)
        house.vPartner.push_back(p);
    }
    house.nLastAttestHeight = 5000;
    house.amountLastAttestReserves = 123456789;
    house.nStressSinceHeight = 5100;
    house.nInsolventHeight = 6108;
    house.nInsolventUnits = 300000;
    house.amountInsolventPot = 100000000;
    house.vOutEscrowChange.push_back(COutPoint(uint256S("cc"), 1));

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    // First byte on the wire is the serialization version
    BOOST_CHECK_EQUAL((uint8_t)ss[0], HOUSE_SER_VERSION);

    CHouse h2;
    ss >> h2;
    BOOST_CHECK_EQUAL(h2.nLastAttestHeight, 5000);
    BOOST_CHECK_EQUAL(h2.amountLastAttestReserves, 123456789);
    BOOST_CHECK_EQUAL(h2.nStressSinceHeight, 5100);
    BOOST_CHECK_EQUAL(h2.nInsolventHeight, 6108);
    BOOST_CHECK_EQUAL(h2.nInsolventUnits, 300000);
    BOOST_CHECK_EQUAL(h2.amountInsolventPot, 100000000);
    BOOST_CHECK_EQUAL(h2.vOutEscrowChange.size(), 1);
    BOOST_CHECK(h2.vOutEscrowChange[0] == COutPoint(uint256S("cc"), 1));
    BOOST_REQUIRE_EQUAL(h2.vPartner.size(), 1);
    BOOST_CHECK_EQUAL(h2.vPartner[0].amountInsolventPledge, 12345);

    // An unknown (FUTURE) version byte is a hard read failure, never defaulted
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << house;
    ss2[0] = (char)(HOUSE_SER_VERSION + 1);
    CHouse h3;
    BOOST_CHECK_THROW(ss2 >> h3, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(house_serialization_v5_deposit_fields)
{
    // Phase 3.8 term-deposit accounting round-trips, including the 128-bit
    // weighted-maturity accumulator (which overflows u64: one term is
    // principal <= MAX_MONEY times a maturity height).
    CHouse house;
    house.nHouseID = 9;
    house.strClassID = "glasgow";
    house.nMintedUnits = 700000000;
    house.nDepositUnits = 250000000;
    house.nInsolventDepositPrincipal = 40000000;
    const unsigned __int128 wt =
        (unsigned __int128)2000000000000000ULL * (unsigned __int128)1500000ULL; // ~3e21 > 2^64
    house.SetDepositWtMaturity(wt);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    BOOST_CHECK_EQUAL((uint8_t)ss[0], HOUSE_SER_VERSION);   // 5

    CHouse h2;
    ss >> h2;
    BOOST_CHECK_EQUAL(h2.nMintedUnits, 700000000);
    BOOST_CHECK_EQUAL(h2.nDepositUnits, 250000000);
    BOOST_CHECK_EQUAL(h2.nInsolventDepositPrincipal, 40000000);
    BOOST_CHECK(h2.DepositWtMaturity() == wt);
    BOOST_CHECK_EQUAL(h2.nDepositWtMatHi, (uint64_t)(wt >> 64));
    BOOST_CHECK_EQUAL(h2.nDepositWtMatLo, (uint64_t)wt);
}

BOOST_AUTO_TEST_CASE(house_v4_to_v5_migration)
{
    // A pre-3.8 (v4) record - no deposit leg - must still read, with the deposit
    // fields defaulting to 0. We synthesise a v4 stream from a v5 one whose
    // deposit fields are 0: the trailing 32 bytes (four zeroed u64) are exactly
    // the v5 addendum, so dropping them + stamping version 4 yields a valid v4
    // record. (This is the no-wipe upgrade path for the live HouseDB.)
    CHouse house;
    house.nHouseID = 11;
    house.strClassID = "ayr2";
    house.nMintedUnits = 123456;
    house.nLastAttestHeight = 4321;
    house.amountLastAttestReserves = 99999999;
    house.vOutReserveLock.push_back(COutPoint(uint256S("ab"), 0));
    // deposit fields left at their constructor default of 0

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    std::vector<char> bytes(ss.begin(), ss.end());
    BOOST_REQUIRE_EQUAL((uint8_t)bytes[0], (uint8_t)HOUSE_SER_VERSION);
    bytes[0] = (char)4;                 // stamp as v4
    // Drop the v5 addendum (four zeroed u64 deposit fields, 32B), the v6
    // addendum (zeroed u32 nDeferEndedHeight, 4B), the v7 addendum (zeroed u32
    // nLastSettleHeight, 4B) AND the v8 addendum (three zeroed u64 loan-book
    // fields, 24B) - all post-date v4.
    bytes.resize(bytes.size() - 64);

    CDataStream ssV4(bytes, SER_NETWORK, PROTOCOL_VERSION);
    CHouse h2;
    ssV4 >> h2;                         // must not throw
    BOOST_CHECK_EQUAL(h2.nHouseID, 11);
    BOOST_CHECK_EQUAL(h2.strClassID, "ayr2");
    BOOST_CHECK_EQUAL(h2.nMintedUnits, 123456);
    BOOST_CHECK_EQUAL(h2.nLastAttestHeight, 4321);
    BOOST_CHECK_EQUAL(h2.amountLastAttestReserves, 99999999);
    BOOST_REQUIRE_EQUAL(h2.vOutReserveLock.size(), 1);
    // The migration's whole point: absent deposit leg defaults to 0.
    BOOST_CHECK_EQUAL(h2.nDepositUnits, 0);
    BOOST_CHECK_EQUAL(h2.nInsolventDepositPrincipal, 0);
    BOOST_CHECK(h2.DepositWtMaturity() == (unsigned __int128)0);
}

BOOST_AUTO_TEST_CASE(house_v5_to_v6_migration)
{
    // A pre-DR-2 (v5) record - no episode-end stamp - must still read, with
    // nDeferEndedHeight defaulting to 0 (= no episode has closed; a demanded
    // note on such a record keeps the uncapped accrual until the next recovery
    // stamps it). Same synthesis as v4->v5: a v6 record whose nDeferEndedHeight
    // is 0 ends in exactly the 4-byte v6 addendum, so dropping it + stamping
    // version 5 yields a valid v5 record.
    CHouse house;
    house.nHouseID = 12;
    house.strClassID = "ayr3";
    house.nMintedUnits = 654321;
    house.nDepositUnits = 777;                       // v5 leg must survive the round-trip
    house.nDeferCumBlocks = 42;
    // nDeferEndedHeight left at its constructor default of 0

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << house;
    std::vector<char> bytes(ss.begin(), ss.end());
    BOOST_REQUIRE_EQUAL((uint8_t)bytes[0], (uint8_t)HOUSE_SER_VERSION);
    bytes[0] = (char)5;                 // stamp as v5
    // Drop the zeroed u32 nDeferEndedHeight (v6), the zeroed u32
    // nLastSettleHeight (v7) and the three zeroed u64 loan-book fields (v8).
    bytes.resize(bytes.size() - 32);

    CDataStream ssV5(bytes, SER_NETWORK, PROTOCOL_VERSION);
    CHouse h2;
    ssV5 >> h2;                         // must not throw
    BOOST_CHECK_EQUAL(h2.nHouseID, 12);
    BOOST_CHECK_EQUAL(h2.strClassID, "ayr3");
    BOOST_CHECK_EQUAL(h2.nMintedUnits, 654321);
    BOOST_CHECK_EQUAL(h2.nDepositUnits, 777);
    BOOST_CHECK_EQUAL(h2.nDeferCumBlocks, 42);
    BOOST_CHECK_EQUAL(h2.nDeferEndedHeight, 0);
}

BOOST_AUTO_TEST_CASE(house_effective_status_derivation)
{
    // The full lazy-derivation matrix (D3). Registration at height 1000:
    // deadline = 1000 + MISS_N*CADENCE; grace holds through the deadline
    // block itself, lazy stress starts at deadline + 1.
    CHouse house;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    const uint32_t nDeadline = 1000 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE;

    // Healthy: before and AT the deadline
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1000), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nDeadline), HOUSE_STATUS_OPEN);

    // Gram-notes release: a missed cadence no longer stresses a house (stress starts only on unpaid demand); it
    // stays Open past the deadline, with nothing stored.
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nDeadline + 1), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nDeadline + 1 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(house.nStressSinceHeight, 0); // nothing stored
    const uint32_t nLazyOrigin = nDeadline + 1;

    // Ratio-breach stress (tx-written by ATTEST): stressed immediately, even
    // while the cadence clock is fresh
    CHouse hRatio = house;
    hRatio.nLastAttestHeight = 2000;   // fresh attestation...
    hRatio.nStressSinceHeight = 2000;  // ...that showed a sub-floor ratio (T2)
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRatio, 2000), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRatio, 2000 + HOUSE_STRESSED_WINDOW - 1), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRatio, 2000 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);

    // A stored origin alone drives the window clock (the missed-cadence origin is gone).
    CHouse hBoth = house;
    hBoth.nStressSinceHeight = nLazyOrigin + 500;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hBoth, nLazyOrigin + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hBoth, nLazyOrigin + 500 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);
    // ...and a stored origin EARLIER than the lazy one wins unchanged
    CHouse hEarly = house;
    hEarly.nStressSinceHeight = 1500;  // ratio breach well before the cadence deadline
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hEarly, 1500 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);

    // Recovery shape (T4 writes done by ATTEST connect): cleared stress +
    // fresh clock derives Open again
    CHouse hRec = hRatio;
    hRec.nStressSinceHeight = 0;
    hRec.nLastAttestHeight = 2500;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRec, 2500), HOUSE_STATUS_OPEN);

    // Stored terminal states short-circuit the derivation
    CHouse hIns = house;
    hIns.status = HOUSE_STATUS_INSOLVENT;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hIns, 1000), HOUSE_STATUS_INSOLVENT);
    CHouse hWound = house;
    hWound.status = HOUSE_STATUS_WOUNDDOWN;
    hWound.nLastAttestHeight = 0; // even with an ancient clock...
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hWound, 999999), HOUSE_STATUS_WOUNDDOWN);
}

BOOST_AUTO_TEST_CASE(house_attest_floor_logic)
{
    // HouseAttestNewStressOrigin: T2 below-floor / T4 recovery / in-band (D9).
    // rho = 10%, buffer = +5 -> recovery at 15%. Units are sats 1:1 (v1).
    CHouse house;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    house.nMintedUnits = 1000000;   // N: floor = 100k sats, buffer target = 150k

    // Healthy house, healthy report (>= 15%): stays clear
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 150000, 1100), 0);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 1000000, 1100), 0);

    // Below floor (< 10%): stress originates at this attest's height
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 99999, 1100), 1100);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 0, 1100), 1100);

    // Exactly at the floor (10.0%) is NOT below floor - in-band, healthy stays healthy
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 100000, 1100), 0);
    // Just under the buffer (14.9999%): in-band, healthy stays healthy
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(house, 149999, 1100), 0);

    // Stressed house (ratio origin 1050): in-band PRESERVES the origin...
    CHouse hStressed = house;
    hStressed.nStressSinceHeight = 1050;
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 120000, 1100), 1050);
    // ...below-floor keeps the ORIGINAL clock (no reset-by-re-breach)...
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 50000, 1100), 1050);
    // ...and only >= floor+buffer recovers
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 149999, 1100), 1050);
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hStressed, 150000, 1100), 0);

    // (Gram-notes release: no lazy missed-cadence origin to materialize any more; ATTEST connect no longer calls
    // this helper for an open house - validation.cpp's gold-till recovery test replaced it.)

    // Zero liabilities: any report (even 0 reserves) is a recovery - a house
    // with no notes outstanding cannot be liquidity-stressed
    CHouse hEmpty = house;
    hEmpty.nMintedUnits = 0;
    hEmpty.nStressSinceHeight = 1050;
    BOOST_CHECK_EQUAL(HouseAttestNewStressOrigin(hEmpty, 0, 1100), 0);
}

BOOST_AUTO_TEST_CASE(gold_brassage_schedule)
{
    // v1.1.0 (D-2026-11-05-1): an Open house redeems at par whatever its till (option A). A house that is not Open
    // (here Stressed) owes the spread on the counted gold till / notes against the 2% till floor - par at or above it,
    // the full 4% at a quarter of it, the same quadratic curve between. Nothing about the attested ECX reserves enters.
    uint64_t nTill = 0;
    g_fnCapitalForChecksTestOverride = [&nTill](const CHouse&, int, CHouseCapital& cap) { cap.nTillMg = nTill; };
    const int H = 100;
    CHouse house;
    house.nMintedUnits = 1000000000;           // 1 tonne of notes, in mg
    house.amountLastAttestReserves = 0;        // never attested: no longer the full spread
    CHouse hEmpty;
    BOOST_CHECK_EQUAL(GoldBrassageBps(hEmpty, H), 0u);
    // Open: par at any till, even none.
    house.status = HOUSE_STATUS_OPEN;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
    nTill = 0;
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), 0u);
    nTill = 10000000;                          // 1%: below the floor, still par while Open
    BOOST_CHECK_EQUAL(GoldTillRatioBps(house, H), 100u);
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), 0u);
    // Stressed: the curve.
    house.status = HOUSE_STATUS_STRESSED;
    house.nStressSinceHeight = (uint32_t)H - 1;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_STRESSED);
    nTill = 20000000;                          // 2% = the floor: par
    BOOST_CHECK_EQUAL(GoldTillRatioBps(house, H), 200u);
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), 0u);
    nTill = 900000000;                         // 90%: par
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), 0u);
    nTill = 12500000;                          // 1.25%, the midpoint of [0.5%, 2%]: a quarter of the full spread
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), HOUSE_BRASSAGE_MAX_BPS / 4);
    nTill = 5000000;                           // 0.5% = theta: the full spread
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), HOUSE_BRASSAGE_MAX_BPS);
    nTill = 0;
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), HOUSE_BRASSAGE_MAX_BPS);
    house.amountLastAttestReserves = 500000000;   // a big ECX attestation changes nothing
    BOOST_CHECK_EQUAL(GoldBrassageBps(house, H), HOUSE_BRASSAGE_MAX_BPS);
    nTill = 19900000;                          // a whisker under the floor: almost nothing
    BOOST_CHECK(GoldBrassageBps(house, H) < 5);
    g_fnCapitalForChecksTestOverride = nullptr;
}

BOOST_AUTO_TEST_CASE(house_brassage_schedule)
{
    // 3.5 D1/D8: the redemption spread as a function of the ATTESTED ratio.
    // rho = 1000 bps, theta = 250 bps, max = 300 bps, quadratic in proximity.
    CHouse house;
    house.nMintedUnits = 1000000000;   // N = 1e9 units

    // No liabilities -> ratio is 100% by definition, no spread
    CHouse hEmpty;
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(hEmpty), 10000);
    BOOST_CHECK_EQUAL(HouseBrassageBps(hEmpty), 0);

    // At and above the floor: EXACT PAR. This is the invariant that keeps 3.4's
    // "redemption at par" promise intact for an Open house - and an Open house
    // is always here, because a below-floor attestation is precisely what makes
    // a house Stressed.
    house.amountLastAttestReserves = 100000000;   // R = 1e8 -> rr = 10.00% = rho
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(house), 1000);
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), 0);
    house.amountLastAttestReserves = 500000000;   // rr = 50%
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), 0);

    // At and below theta: the full spread
    house.amountLastAttestReserves = 25000000;    // rr = 2.50% = theta
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(house), 250);
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), HOUSE_BRASSAGE_MAX_BPS);
    house.amountLastAttestReserves = 0;           // rr = 0
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), HOUSE_BRASSAGE_MAX_BPS);

    // Between: quadratic, so it opens GENTLY just under the floor rather than
    // with a cliff (the sim's prox^2).
    house.amountLastAttestReserves = 99000000;    // rr = 9.90%, a whisker below rho
    const uint32_t nJustUnder = HouseBrassageBps(house);
    BOOST_CHECK(nJustUnder < 5);                  // ~0.05 bps - almost nothing
    house.amountLastAttestReserves = 62500000;    // rr = 6.25% - the midpoint of [theta, rho]
    BOOST_CHECK_EQUAL(HouseBrassageBps(house), HOUSE_BRASSAGE_MAX_BPS / 4);  // prox=0.5 -> prox^2=0.25

    // Monotone: the closer to theta, the steeper the exit
    uint32_t nPrev = 0;
    for (CAmount R = 100000000; R >= 25000000; R -= 5000000) {
        house.amountLastAttestReserves = R;
        const uint32_t nBps = HouseBrassageBps(house);
        BOOST_CHECK(nBps >= nPrev);
        BOOST_CHECK(nBps <= HOUSE_BRASSAGE_MAX_BPS);
        nPrev = nBps;
    }

    // The spread amount itself
    BOOST_CHECK_EQUAL(HouseBrassageAmount(1000000, 300), 30000);   // 3% of 1e6
    BOOST_CHECK_EQUAL(HouseBrassageAmount(1000000, 0), 0);
    BOOST_CHECK_EQUAL(HouseBrassageAmount(0, 300), 0);
    BOOST_CHECK_EQUAL(HouseBrassageAmount(100, 300), 3);
    BOOST_CHECK_EQUAL(HouseBrassageAmount(10, 300), 0);            // floors to nothing on dust

    // 128-bit: R*10000 overflows u64 at money-range reserves, and the spread on
    // a lambda-max supply must not wrap.
    CHouse hBig;
    hBig.nMintedUnits = (uint64_t)MAX_MONEY * 3;
    hBig.amountLastAttestReserves = MAX_MONEY;
    BOOST_CHECK_EQUAL(HouseAttestedRatioBps(hBig), 3333);          // 33.3% - above rho, no spread
    BOOST_CHECK_EQUAL(HouseBrassageBps(hBig), 0);
    BOOST_CHECK(HouseBrassageAmount((uint64_t)MAX_MONEY * 3, HOUSE_BRASSAGE_MAX_BPS) <= (CAmount)MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(house_deferral_derivation)
{
    // 3.5: the option clause folds into the LAZY machine - 'd' is derived from
    // the stored invocation height alone. v0.2.18 (operator Q4/Q5): there is NO
    // end date; the only way from 'd' to 'i' is silence (next test).
    CHouse house;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    house.nStressSinceHeight = 1100;          // stressed by a ratio breach
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1200), HOUSE_STATUS_STRESSED);

    // Invoking at 1200 REPLACES the ordinary stress clock
    house.nDeferInvokedHeight = 1200;
    house.nDeferActivations = 1;
    house.nDeferLastActivation = 1200;
    house.nLastAttestHeight = 1190;           // DEFER needs a fresh attestation
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1200), HOUSE_STATUS_DEFERRED);
    // ...and the 1008-block stress clock no longer bites while deferring.
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1100 + HOUSE_STRESSED_WINDOW + 1), HOUSE_STATUS_DEFERRED);

    // v0.2.28 (FAILED_HOUSE_DESIGN.md C, Michael 2026-10-16 "12 months"): a house that keeps attesting stays
    // suspended up to nSuspensionCap after DEFER - and no further. (v0.2.18-v0.2.27 had no end date.)
    const uint32_t nCapAt = 1200u + Params().GetConsensus().nSuspensionCap;
    BOOST_CHECK_EQUAL(HouseDeferCapInsolventHeight(house), nCapAt);
    for (const uint32_t nAt : {1200u + 50u, nCapAt - 101u}) {
        CHouse h = house;
        h.nLastAttestHeight = nAt - 1;        // attesting on cadence
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, (int)nAt), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, (int)nAt + 100), HOUSE_STATUS_DEFERRED);
    }
    {
        CHouse h = house;
        h.nLastAttestHeight = nCapAt - 1;     // attested the block before: the cap still ends it
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, (int)nCapAt - 1), HOUSE_STATUS_DEFERRED);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, (int)nCapAt), HOUSE_STATUS_INSOLVENT);
        BOOST_CHECK_EQUAL(HouseInsolventSince(h, (int)nCapAt), nCapAt);
        BOOST_CHECK_EQUAL(HouseDeferInsolventHeight(h), nCapAt);
    }

    // Recovery (the ATTEST effect) lifts it: cleared origin + cleared invocation
    CHouse hRecovered = house;
    hRecovered.nDeferInvokedHeight = 0;
    hRecovered.nDeferRenewals = 0;
    hRecovered.nStressSinceHeight = 0;
    hRecovered.nLastAttestHeight = 1500;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hRecovered, 1500), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(HouseDeferSilenceInsolventHeight(hRecovered), 0u);   // not suspended

    // Suspended-block accounting (published) includes the running episode
    BOOST_CHECK_EQUAL(house.DeferSuspendedBlocks(1500), 300);   // 1500 - 1200
    BOOST_CHECK_EQUAL(house.DeferSuspendedBlocks(1200), 0);
    CHouse hClosed = house;
    hClosed.nDeferInvokedHeight = 0;
    hClosed.nDeferCumBlocks = 300;
    BOOST_CHECK_EQUAL(hClosed.DeferSuspendedBlocks(9999), 300); // closed episode: no accrual

    // A stored terminal status still short-circuits everything
    CHouse hWound = house;
    hWound.status = HOUSE_STATUS_WOUNDDOWN;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hWound, 999999), HOUSE_STATUS_WOUNDDOWN);
}

// v0.2.18 Q5: a SUSPENDED house becomes insolvent only by silence - it misses
// HOUSE_ATTEST_MISS_N cadences, then nDeferSilenceWindow more blocks. Checked
// at both networks' values (main 4,032; regtest small so gates can reach it).
static void CheckSilenceClock(uint32_t nSilence)
{
    BOOST_REQUIRE_EQUAL(Params().GetConsensus().nDeferSilenceWindow, nSilence);
    CHouse house;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nStressSinceHeight = 1100;
    house.nDeferInvokedHeight = 1200;
    house.nDeferActivations = 1;
    house.nDeferLastActivation = 1200;
    const uint32_t L = 1195;                  // last attestation
    house.nLastAttestHeight = L;
    const uint32_t nDeadline = L + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE;   // last height still "on cadence"
    const uint32_t nInsolvent = nDeadline + 1 + nSilence;
    BOOST_CHECK_EQUAL(HouseDeferSilenceInsolventHeight(house), nInsolvent);

    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)nDeadline), HOUSE_STATUS_DEFERRED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)nDeadline + 1), HOUSE_STATUS_DEFERRED);  // clock started
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)nInsolvent - 1), HOUSE_STATUS_DEFERRED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)nInsolvent), HOUSE_STATUS_INSOLVENT);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, (int)nInsolvent + 1000000), HOUSE_STATUS_INSOLVENT);

    // Attesting AGAIN inside the silence clock (one block before it runs out)
    // keeps the house suspended: the deadline is derived from the new height.
    CHouse hAttested = house;
    hAttested.nLastAttestHeight = nInsolvent - 1;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hAttested, (int)nInsolvent), HOUSE_STATUS_DEFERRED);
    BOOST_CHECK_EQUAL(HouseDeferSilenceInsolventHeight(hAttested),
                      nInsolvent - 1 + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1 + nSilence);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hAttested, (int)HouseDeferSilenceInsolventHeight(hAttested)),
                      HOUSE_STATUS_INSOLVENT);

    // A live protest does not shorten the suspended house's clock: while
    // suspended the clause governs (silence is the only way out).
    CHouse hProtest = house;
    hProtest.nProtestOpen = 1;
    hProtest.nProtestHeight = 1150;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hProtest, (int)nInsolvent - 1), HOUSE_STATUS_DEFERRED);

    // Gram-notes release: an OPEN house that misses its cadence stays Open (stress starts only on unpaid demand).
    CHouse hOpen = house;
    hOpen.nDeferInvokedHeight = 0;
    hOpen.nStressSinceHeight = 0;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hOpen, (int)nDeadline), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hOpen, (int)nDeadline + 1), HOUSE_STATUS_OPEN);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(hOpen, (int)(nDeadline + 1 + HOUSE_STRESSED_WINDOW)), HOUSE_STATUS_OPEN);
}

BOOST_AUTO_TEST_CASE(house_suspended_silence_clock)
{
    CheckSilenceClock(4032);                  // main: ~4 weeks (operator Q5)
    SelectParams(CBaseChainParams::REGTEST);
    CheckSilenceClock(40);                    // regtest: gate-testable
    SelectParams(CBaseChainParams::BETA);     // restore the fixture's network
    // The schedule is the same on every network: 10%/yr from block 0.
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::BETA, CBaseChainParams::REGTEST}) {
        const std::unique_ptr<const CChainParams> params = CreateChainParams(net);
        const std::vector<Consensus::DeferInterestStep>& v = params->GetConsensus().vDeferInterestSchedule;
        BOOST_REQUIRE_EQUAL(v.size(), 1u);
        BOOST_CHECK_EQUAL(v[0].nHeight, 0u);
        BOOST_CHECK_EQUAL(v[0].nBps, 1000u);
    }
}

BOOST_AUTO_TEST_CASE(house_mint_caps_rho_at_mint)
{
    // 3.5 D2: the binding mint cap is min(capital lambda*E, reserve R/rho).
    CHouse house;
    house.nTier = HOUSE_TIER_MULTI_PARTNER;   // lambda = 3.0
    HousePartner p;
    p.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p.amountPledge = 100000000;               // 1 BTX escrow
    p.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(p);

    // Capital cap = 3 * 1e8 = 3e8 units, independent of reserves
    BOOST_CHECK_EQUAL(HouseCapitalCapUnits(house), 300000000);

    // A house that has NEVER attested carries R = 0: reserve cap 0, so the
    // binding cap is 0 - it must attest before it can mint anything.
    BOOST_CHECK_EQUAL(house.amountLastAttestReserves, 0);
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), 0);
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 0);

    // rho = 10%: an attested till of R supports R/rho = 10*R units
    house.amountLastAttestReserves = 10000000;         // 0.1 BTX
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), 100000000);   // 1e8
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 100000000);      // RESERVE binds

    // Enough till to out-run the capital cap -> capital binds again
    house.amountLastAttestReserves = 50000000;         // 0.5 BTX -> 5e8 units
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), 500000000);
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 300000000);      // CAPITAL binds

    // Exactly at the crossover both agree
    house.amountLastAttestReserves = 30000000;         // 0.3 BTX -> 3e8 units
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(house), HouseCapitalCapUnits(house));
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 300000000);

    // The pre-3.5 hole this closes: escrow alone no longer authorizes issuance.
    // Top up escrow 10x with an unchanged till - the capital cap explodes, the
    // BINDING cap does not move.
    house.vPartner[0].amountPledge = 1000000000;       // 10 BTX
    BOOST_CHECK_EQUAL(HouseCapitalCapUnits(house), 3000000000);
    BOOST_CHECK_EQUAL(HouseMintCapUnits(house), 300000000);      // still the till

    // Money-range operands do not overflow u64 (R*100 = 2.1e17)
    CHouse hMax;
    hMax.amountLastAttestReserves = MAX_MONEY;
    BOOST_CHECK_EQUAL(HouseReserveCapUnits(hMax), (uint64_t)MAX_MONEY * 10);
}

BOOST_AUTO_TEST_CASE(house_attest_hash_helpers)
{
    // Challenge binds house, height, block hash, and outpoint independently
    const uint256 houseA = uint256S("aa"), houseB = uint256S("bb");
    const uint256 blockA = uint256S("c1"), blockB = uint256S("c2");
    const COutPoint outA(uint256S("d1"), 0), outB(uint256S("d1"), 1);

    const uint256 base = HouseAttestChallenge(houseA, 100, blockA, outA);
    BOOST_CHECK(base == HouseAttestChallenge(houseA, 100, blockA, outA));    // deterministic
    BOOST_CHECK(base != HouseAttestChallenge(houseB, 100, blockA, outA));    // cross-house
    BOOST_CHECK(base != HouseAttestChallenge(houseA, 101, blockA, outA));    // height
    BOOST_CHECK(base != HouseAttestChallenge(houseA, 100, blockB, outA));    // reorg
    BOOST_CHECK(base != HouseAttestChallenge(houseA, 100, blockA, outB));    // outpoint

    // Proof-set hash covers outpoints + pubkeys, NOT signatures
    AttestProof p1;
    p1.outpoint = outA;
    p1.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p1.vchSig = std::vector<unsigned char>(70, 0x30);
    AttestProof p2 = p1;
    p2.vchSig = std::vector<unsigned char>(70, 0x31);                        // different sig
    BOOST_CHECK(HouseAttestProofSetHash({p1}) == HouseAttestProofSetHash({p2}));
    AttestProof p3 = p1;
    p3.outpoint = outB;
    BOOST_CHECK(HouseAttestProofSetHash({p1}) != HouseAttestProofSetHash({p3}));
    BOOST_CHECK(HouseAttestProofSetHash({p1, p3}) != HouseAttestProofSetHash({p3, p1})); // order-bound

    // Approver sighash binds every field
    const uint256 ps = HouseAttestProofSetHash({p1});
    const uint256 ho = uint256S("ee");
    const uint256 sh = HouseAttestSigHash(houseA, 100, 5000, ps, ho);
    BOOST_CHECK(sh != HouseAttestSigHash(houseB, 100, 5000, ps, ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 101, 5000, ps, ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 100, 5001, ps, ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 100, 5000, HouseAttestProofSetHash({p3}), ho));
    BOOST_CHECK(sh != HouseAttestSigHash(houseA, 100, 5000, ps, uint256S("ef")));
}

// Build a shape-valid ATTEST tx around the given payload
static CMutableTransaction MakeAttestTx(const HouseAttest& att)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_ATTEST;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << att;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));   // fee funding
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));   // change
    return mtx;
}

BOOST_AUTO_TEST_CASE(house_attest_shape)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();

    HouseAttest att;
    att.nHouseID = 1;
    att.nSchemaVersion = 1;
    att.nAsOfHeight = 100;
    att.amountReserves = 50000;
    AttestProof proof;
    proof.outpoint = COutPoint(uint256S("d1"), 0);
    proof.vchPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    proof.vchSig = std::vector<unsigned char>(70, 0x30);
    att.vProofs.push_back(proof);
    att.vApproverIndex.push_back(0);
    att.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));

    CValidationState state;
    BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeAttestTx(att)), state));

    // Wrong schema version
    {
        HouseAttest bad = att;
        bad.nSchemaVersion = 2;
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
    // Duplicate proof outpoint (would double-count the coin)
    {
        HouseAttest bad = att;
        bad.vProofs.push_back(proof);
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
    // Positive claim with no proofs / zero claim with proofs
    {
        HouseAttest bad = att;
        bad.vProofs.clear();
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
        HouseAttest bad2 = att;
        bad2.amountReserves = 0;
        CValidationState s2;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad2)), s2));
    }
    // Zero-reserve, zero-proof attestation is a VALID honest report
    {
        HouseAttest zero = att;
        zero.amountReserves = 0;
        zero.vProofs.clear();
        CValidationState s;
        BOOST_CHECK(CheckHouseTransactionShape(CTransaction(MakeAttestTx(zero)), s));
    }
    // Null outpoint / bad pubkey size / oversized sig / no approvers
    {
        HouseAttest bad = att;
        bad.vProofs[0].outpoint.SetNull();
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
        HouseAttest bad2 = att;
        bad2.vProofs[0].vchPubKey = std::vector<unsigned char>(20, 0x02);
        CValidationState s2;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad2)), s2));
        HouseAttest bad3 = att;
        bad3.vProofs[0].vchSig = std::vector<unsigned char>(81, 0x30);
        CValidationState s3;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad3)), s3));
        HouseAttest bad4 = att;
        bad4.vApproverIndex.clear();
        bad4.vApproverSig.clear();
        CValidationState s4;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad4)), s4));
    }
    // Too many proofs
    {
        HouseAttest bad = att;
        bad.vProofs.clear();
        for (size_t i = 0; i <= MAX_ATTEST_PROOFS; i++) {
            AttestProof p = proof;
            p.outpoint = COutPoint(uint256S("d1"), (uint32_t)i);
            bad.vProofs.push_back(p);
        }
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
    // Negative / oversized reserve claim
    {
        HouseAttest bad = att;
        bad.amountReserves = -1;
        CValidationState s;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(MakeAttestTx(bad)), s));
    }
}

// ---------------------------------------------------------------------------
// R-i6: the NEGATIVE direction of the 3.5 house-op consensus guards.
//
// Before this, no test invoked CheckHouseOperation at all - the guards were
// reachable only through the wallet, which fail-fasts on the same conditions and
// so never builds a rejectable tx. Deleting a guard left the whole suite green.
// Each case below drives the contextual check directly and asserts the EXACT
// reject reason, so a fixture that trips an earlier guard is caught rather than
// passing for the wrong reason. Every reason asserted here fires BEFORE any
// ECDSA in its branch, so a placeholder approver/reclaim signature suffices.
// ---------------------------------------------------------------------------

namespace {
static bool GuardNoHash(const uint256&) { return false; }
static bool GuardNoClass(const std::string&) { return false; }
static bool GuardNoBlock(uint32_t, uint256&) { return false; }

// An effectively-OPEN multi-partner house: fresh attestation, ample reserves,
// no stress, not deferring. Partner 0 ACTIVE, partner 1 TAIL and past unlock.
static CHouse MakeGuardHouse()
{
    CHouse house;
    house.nHouseID = 7;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.strClassID = "guard";
    house.nDenomMgGold = 1000;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nLastAttestHeight = 1000;
    house.amountLastAttestReserves = 100 * COIN;

    HousePartner p0;
    p0.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p0.amountPledge = HOUSE_MIN_PLEDGE;
    p0.vOutPledge.push_back(COutPoint(uint256S("a0"), 0));
    p0.status = HOUSE_PARTNER_ACTIVE;

    HousePartner p1 = p0;
    p1.vOutPledge.clear();
    p1.vOutPledge.push_back(COutPoint(uint256S("a1"), 0));
    p1.status = HOUSE_PARTNER_TAIL;
    p1.nTailUnlockHeight = 900;

    house.vPartner.push_back(p0);
    house.vPartner.push_back(p1);
    return house;
}

// A house-escrow coin (fHouseEscrow, this house) at value v.
static Coin GuardEscrowCoin(uint32_t nHouseID, CAmount v)
{
    Coin coin(CTxOut(v, HouseEscrowScript(uint256S("f00d"))), 1000, false, false, false, uint256());
    coin.SetHouseEscrow(nHouseID);
    return coin;
}

static CMutableTransaction MakeReclaimTx(uint32_t nHouseID, uint32_t nPartnerIdx, const COutPoint& spend)
{
    HouseReclaim rec;
    rec.nHouseID = nHouseID;
    rec.nPartnerIndex = nPartnerIdx;
    rec.vchSig = std::vector<unsigned char>(70, 0x30);
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_RECLAIM;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rec;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(spend));
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
    return mtx;
}

static CMutableTransaction MakeHouseOpTx(uint8_t nOp, const CDataStream& payload)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = nOp;
    mtx.vchHousePayload = std::vector<unsigned char>(payload.begin(), payload.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
    return mtx;
}
} // namespace

BOOST_AUTO_TEST_CASE(house_reclaim_cannot_steal_escrow)
{
    // R-i6 CRITICAL regression: a tail partner must NOT spend the DEFER till or
    // the brassage pot (house-escrow coins in NO partner's pledge). The guard
    // fires before the D13 cap and the approver signature.
    CHouse house = MakeGuardHouse();
    const int nHeight = 1000;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nHeight), HOUSE_STATUS_OPEN);

    const COutPoint tillOut(uint256S("dead"), 0);
    house.vOutReserveLock.push_back(tillOut);
    Coin till = GuardEscrowCoin(house.nHouseID, 50 * COIN);

    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
        if (o == tillOut) { c = till; return true; }
        if (o == COutPoint(uint256S("a1"), 0)) { c = GuardEscrowCoin(house.nHouseID, HOUSE_MIN_PLEDGE); return true; }
        return false;
    };

    // Partner 1 (TAIL, unlocked) tries to reclaim the till -> theft rejected.
    {
        CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, tillOut);
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass, fnGetCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-reclaim-not-own-pledge");
    }
    // Control: reclaiming its OWN pledge coin (a1) passes the ownership guard and
    // only then fails on the placeholder signature - proving no over-rejection.
    {
        CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, COutPoint(uint256S("a1"), 0));
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass, fnGetCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-reclaim-sig");
    }
}

// S1X-17 (testing 2026-11-25; consensus batch item 6, Michael's yes 11-25). EXIT accepts both authorisation forms and
// skips the approvers once the partner's own signature verifies, and the digest covers the outputs only, so anyone can
// add junk approver entries to a signed voluntary EXIT: a new txid for the same exit, orphaning its children. The batch
// makes it exactly one form (partner-signed: no approver entries). Fix-agnostic: the control must pass before and after.
BOOST_AUTO_TEST_CASE(s1x_17_exit_takes_exactly_one_authorisation_form)
{
    CHouse house = MakeGuardHouse();   // multi-partner, effectively Open at 1000
    std::vector<CKey> keys(3);
    house.vPartner.clear();
    for (int i = 0; i < 3; i++) {
        keys[i].MakeNewKey(true);
        const CPubKey pub = keys[i].GetPubKey();
        HousePartner p;
        p.vchPubKey.assign(pub.begin(), pub.end());
        p.amountPledge = HOUSE_MIN_PLEDGE;
        p.vOutPledge.push_back(COutPoint(uint256S(strprintf("b%d", i)), 0));
        p.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(p);
    }
    house.nThresholdM = 2;   // three active, so one may leave
    const int nHeight = 1000;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, nHeight), HOUSE_STATUS_OPEN);
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };

    auto build = [&](bool fJunkApprover) {
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_EXIT, CDataStream(SER_NETWORK, PROTOCOL_VERSION));
        HouseExit ex;
        ex.nHouseID = house.nHouseID;
        ex.nPartnerIndex = 2;
        BOOST_REQUIRE(keys[2].Sign(HouseExitSigHash(house.houseID, 2, BillHashPrevouts(CTransaction(mtx)),   // S1X-16b
                                                    BillHashOutputs(CTransaction(mtx))), ex.vchPartnerSig));
        if (fJunkApprover) {   // what a relayer adds: unsigned by anyone, never checked
            ex.vApproverIndex.push_back(0);
            ex.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        }
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << ex;
        mtx.vchHousePayload.assign(ss.begin(), ss.end());
        return mtx;
    };

    {   // control: the partner's own signature, no approver entries
        CValidationState state; CHouse houseOut;
        BOOST_CHECK_MESSAGE(CheckHouseOperation(CTransaction(build(false)), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass,
                                                fnNoCoin, GuardNoBlock, houseOut),
                            "control: a voluntary EXIT refused: " + state.GetRejectReason());
    }
    {
        const CMutableTransaction a = build(false), b = build(true);
        BOOST_CHECK(CTransaction(a).GetHash() != CTransaction(b).GetHash());
        CValidationState state; CHouse houseOut;
        const bool fOk = CheckHouseOperation(CTransaction(b), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass,
                                             fnNoCoin, GuardNoBlock, houseOut);
        BOOST_CHECK_MESSAGE(!fOk, "S1X-17: a partner-signed EXIT with a junk approver entry added was accepted: same exit, "
                                  "new txid (anyone can re-wrap it)");
    }
}

BOOST_AUTO_TEST_CASE(house_op_status_guards)
{
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };

    // DEFER is a Stressed-only tool: an Open house is refused (expropriation bar).
    {
        CHouse house = MakeGuardHouse();               // Open
        HouseDefer def; def.nHouseID = house.nHouseID; def.nPrevLastActivation = 0;
        def.vApproverIndex.push_back(0); def.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << def;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_DEFER, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 1000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-defer-not-stressed");
    }
    // v0.2.18 (Q4): a REPEAT suspension is allowed. A house that suspended
    // recently AND has a huge cumulative suspension (both tripped the old D15
    // guard) gets a DEFER fully ACCEPTED, signature and all.
    {
        CKey keyPartner; keyPartner.MakeNewKey(true);
        const CPubKey pubPartner = keyPartner.GetPubKey();
        CHouse house = MakeGuardHouse();
        house.vPartner[0].vchPubKey = std::vector<unsigned char>(pubPartner.begin(), pubPartner.end());
        house.nLastAttestHeight = 2000; house.nStressSinceHeight = 2000; // Stressed at 2000, fresh attest
        house.nDeferActivations = 3;
        house.nDeferLastActivation = 1990;                               // inside the old 36-month window
        house.nDeferCumBlocks = 38880;                                   // the old 9-month cap
        house.nDeferEndedHeight = 1995;
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 2000), HOUSE_STATUS_STRESSED);
        HouseDefer def; def.nHouseID = house.nHouseID; def.nPrevLastActivation = house.nDeferLastActivation;
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_DEFER;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(house.amountLastAttestReserves, HouseEscrowScript(house.houseID)));   // the till lock
        mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
        def.vApproverIndex.push_back(0);
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(keyPartner.Sign(HouseDeferSigHash(house.houseID, def.nPrevLastActivation, BillHashOutputs(mtx)), vchSig));
        def.vApproverSig.push_back(vchSig);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << def;
        mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK_MESSAGE(CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut),
                            state.GetRejectReason());
        BOOST_CHECK_EQUAL(houseOut.nDeferActivations, 4u);
        BOOST_CHECK_EQUAL(houseOut.nDeferInvokedHeight, 2000u);
        BOOST_CHECK_EQUAL(houseOut.nDeferLastActivation, 2000u);
        BOOST_CHECK_EQUAL(houseOut.nDeferEndedHeight, 1995u);           // untouched by DEFER
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(houseOut, 2001), HOUSE_STATUS_DEFERRED);
        // ...and a DEFER while already suspended is still refused (nothing to extend).
        auto fnGetHouse2 = [&](uint32_t id, CHouse& out) { if (id == houseOut.nHouseID) { out = houseOut; return true; } return false; };
        CValidationState state2; CHouse houseOut2;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state2, 2001, fnGetHouse2, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut2));
        BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-house-defer-not-stressed");
    }
    // RELEASE is refused while the house is not effectively Open (till stays put).
    {
        CHouse house = MakeGuardHouse();
        house.nLastAttestHeight = 2000; house.nStressSinceHeight = 2000; // Stressed
        HouseRelease rel; rel.nHouseID = house.nHouseID;
        rel.vApproverIndex.push_back(0); rel.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << rel;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_RELEASE, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-release-not-open");
    }
    // RECLAIM is refused while the house is Stressed/Deferred - no pledge walks
    // out during the window - and this fires for a TAIL, unlock-passed partner
    // that would otherwise be eligible (the integration gate only ever presented
    // an ACTIVE partner, which trips the not-tail guard instead: R-i6 finding).
    {
        CHouse house = MakeGuardHouse();
        house.nLastAttestHeight = 2000; house.nStressSinceHeight = 2000; // Stressed
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 2000), HOUSE_STATUS_STRESSED);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, COutPoint(uint256S("a1"), 0));
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-reclaim-stressed");
    }

    // v0.2.18 (Q4): RENEW is RETIRED - refused at every status, both by the
    // context-free shape check and (belt) by the contextual check.
    for (const bool fDeferred : {false, true}) {
        CHouse house = MakeGuardHouse();
        if (fDeferred) {
            house.nDeferInvokedHeight = 1500;
            BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 1001), HOUSE_STATUS_DEFERRED);
        }
        HouseRenew ren; ren.nHouseID = house.nHouseID;
        ren.vApproverIndex.push_back(0); ren.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << ren;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_RENEW, ss);
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 1001, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-renew-retired");
        CValidationState stateShape;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), stateShape));
        BOOST_CHECK_EQUAL(stateShape.GetRejectReason(), "bad-house-renew-retired");
    }
}

BOOST_AUTO_TEST_CASE(house_release_renew_sighash_prevouts_binding)
{
    // R-i6 replay fix: RELEASE/RENEW approvals must bind the tx prevouts, so an
    // approval published in one deferral episode cannot be replayed against a
    // fresh till in a later one (the till coins are OP_TRUE - the approver sig is
    // their sole authorization).
    const uint256 id = uint256S("ab");
    const uint256 outs = uint256S("cd");
    const uint256 pvA = uint256S("11");
    const uint256 pvB = uint256S("22");

    BOOST_CHECK(HouseReleaseSigHash(id, pvA, outs) == HouseReleaseSigHash(id, pvA, outs));
    BOOST_CHECK(HouseReleaseSigHash(id, pvA, outs) != HouseReleaseSigHash(id, pvB, outs));

    // RENEW's index resets to 0 every episode, so the prevouts are what
    // distinguish one episode's approval from a later one's.
    BOOST_CHECK(HouseRenewSigHash(id, 0, pvA, outs) != HouseRenewSigHash(id, 0, pvB, outs));
    // Domain separation between the two ops holds too.
    BOOST_CHECK(HouseReleaseSigHash(id, pvA, outs) != HouseRenewSigHash(id, 0, pvA, outs));
}

//
// Phase 3.9 (B1) - the loan book L and match-funding. T-d1 gate.
//

/** A house with one active partner pledging amountEscrow. */
static CHouse LoanBookHouse(CAmount amountEscrow)
{
    CHouse h;
    h.nHouseID = 3;
    h.nTier = 1;
    h.nThresholdM = 1;
    HousePartner p;
    p.vchPubKey = std::vector<unsigned char>(33, 0x02);
    p.amountPledge = amountEscrow;
    p.status = HOUSE_PARTNER_ACTIVE;
    h.vPartner.push_back(p);
    return h;
}

BOOST_AUTO_TEST_CASE(house_loan_book_helper_boundaries)
{
    // THE regression that matters: the obvious mathematical form of the excess -
    // max(0, nLoanBookFace - ActiveEscrow()) - is a uint64 minus an int64, so it
    // WRAPS whenever the book sits inside permanent capital. That is the state of
    // every house at genesis, and it made the slice come out as the whole deposit
    // book, which then drove a division by a zero loan book: a remote SIGFPE
    // reachable by the FIRST term deposit on a chain with no bills at all.
    {
        CHouse h = LoanBookHouse(100000000);
        h.nDepositUnits = 20000000;
        h.SetDepositWtMaturity((unsigned __int128)20000000 * 5000);
        BOOST_CHECK_EQUAL(h.nLoanBookFace, 0);
        BOOST_CHECK_EQUAL(HouseLoanBookExcess(h, 1000), 0);     // MUST NOT wrap
        BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), 0);
        BOOST_CHECK(HouseLoanBookDuration(h, 1000) == 0); // MUST NOT divide by zero
        BOOST_CHECK(HouseMatchFundingOK(h, 1000));
    }
    {
        // Same, with no escrow at all.
        CHouse h = LoanBookHouse(0);
        h.nDepositUnits = 20000000;
        h.SetDepositWtMaturity((unsigned __int128)20000000 * 5000);
        BOOST_CHECK_EQUAL(HouseLoanBookExcess(h, 1000), 0);
        BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), 0);
        BOOST_CHECK(HouseMatchFundingOK(h, 1000));
    }

    // D == 0 is structurally vacuous however large the book: the flagship
    // mint-funded flow can never punish itself (the failure that killed the
    // bare-ActiveEscrow pin).
    {
        CHouse h = LoanBookHouse(100000000);
        h.nLoanBookFace = 300000000;
        h.SetLoanWtMaturity((unsigned __int128)300000000 * 100000);
        BOOST_CHECK_EQUAL(HouseLoanBookExcess(h, 1000), 200000000);
        BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), 0);      // no deposits
        BOOST_CHECK(HouseMatchFundingOK(h, 1000));
    }

    // A book inside permanent capital needs no matching, deposits or not.
    {
        CHouse h = LoanBookHouse(100000000);
        h.nLoanBookFace = 40000000;
        h.SetLoanWtMaturity((unsigned __int128)40000000 * 8740);
        h.nDepositUnits = 20000000;
        h.SetDepositWtMaturity((unsigned __int128)20000000 * 5320);
        BOOST_CHECK_EQUAL(HouseLoanBookExcess(h, 1000), 0);
        BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), 0);
        BOOST_CHECK(HouseMatchFundingOK(h, 100));
    }

    // Exactly at the capacity boundary: L == E is still no excess.
    {
        CHouse h = LoanBookHouse(100000000);
        h.nLoanBookFace = 100000000;
        h.SetLoanWtMaturity((unsigned __int128)100000000 * 8740);
        h.nDepositUnits = 20000000;
        BOOST_CHECK_EQUAL(HouseLoanBookExcess(h, 1000), 0);
        BOOST_CHECK(HouseMatchFundingOK(h, 100));
        // One satoshi past it, the excess appears.
        h.nLoanBookFace = 100000001;
        BOOST_CHECK_EQUAL(HouseLoanBookExcess(h, 1000), 1);
    }
}

BOOST_AUTO_TEST_CASE(house_match_funding_duration_rule)
{
    // The spec's scene 2: L = 200M face of ~60-day paper, E = 100M, D = 50M of
    // 30-day money. slice = min(200M-100M, 50M) = 50M > 0, and short money
    // funding long assets fails.
    const int h0 = 100;
    CHouse h = LoanBookHouse(100000000);
    h.nLoanBookFace = 200000000;
    h.SetLoanWtMaturity((unsigned __int128)200000000 * (h0 + 8640));
    h.nDepositUnits = 50000000;
    h.SetDepositWtMaturity((unsigned __int128)50000000 * (h0 + 4320));

    BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), 50000000);
    BOOST_CHECK(HouseLoanBookDuration(h, h0) == (unsigned __int128)200000000 * 8640);
    BOOST_CHECK(HouseDepositDuration(h, h0) == (unsigned __int128)50000000 * 4320);
    BOOST_CHECK(!HouseMatchFundingOK(h, h0));

    // Cure 1: longer deposits. The rule is L*DepDur >= slice*BookDur. Here
    // slice == D, and BookDur == L * avgRemaining, so the requirement collapses
    // to "the deposits' average remaining term must reach the BOOK's average
    // remaining term" - 8640 blocks. That is what proportional attribution
    // means: the deposit-funded sliver carries the book's average maturity, so
    // its size never softens the term requirement (spec s3.1 approximation (i)).
    h.SetDepositWtMaturity((unsigned __int128)50000000 * (h0 + 8640));
    BOOST_CHECK(HouseMatchFundingOK(h, h0));              // exact equality passes
    h.SetDepositWtMaturity((unsigned __int128)50000000 * (h0 + 8639));
    BOOST_CHECK(!HouseMatchFundingOK(h, h0));             // one block short fails

    // Cure 2: deposits mature and are withdrawn (never blocked, B1 OD-4), so the
    // slice collapses and the rule goes vacuous.
    h.nDepositUnits = 0;
    h.SetDepositWtMaturity(0);
    BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), 0);
    BOOST_CHECK(HouseMatchFundingOK(h, h0));

    // Cure 3: more permanent capital lifts the book back inside capacity.
    h.nDepositUnits = 50000000;
    h.SetDepositWtMaturity((unsigned __int128)50000000 * (h0 + 4320));
    BOOST_CHECK(!HouseMatchFundingOK(h, h0));
    h.vPartner[0].amountPledge = 200000000;               // TOPUP
    BOOST_CHECK_EQUAL(HouseLoanBookExcess(h, 1000), 0);
    BOOST_CHECK(HouseMatchFundingOK(h, h0));
}

BOOST_AUTO_TEST_CASE(house_match_funding_no_ratchet_on_runoff)
{
    // Duration, not average maturity. Under an AVERAGE-based rule, retiring the
    // SHORT bill raises the book's average and can flip a compliant house into
    // violation - so a drawee paying his own bill early could freeze his bank,
    // and "let the book run off" would be a cure that makes things worse. With a
    // duration comparison, any bill leaving reduces book duration.
    const int h0 = 0;
    CHouse h = LoanBookHouse(0);                          // E = 0 so slice == min(L, D)
    // Book: 100M @ remaining 10, 100M @ remaining 10000.
    h.nLoanBookFace = 200000000;
    h.SetLoanWtMaturity((unsigned __int128)100000000 * 10 + (unsigned __int128)100000000 * 10000);
    h.nDepositUnits = 200000000;
    h.SetDepositWtMaturity((unsigned __int128)200000000 * 6000);
    BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), 200000000);
    // slice == L, so the rule reduces to DepDur >= BookDur.
    const unsigned __int128 bookDurBefore = HouseLoanBookDuration(h, h0);
    BOOST_CHECK(HouseDepositDuration(h, h0) >= bookDurBefore);
    BOOST_CHECK(HouseMatchFundingOK(h, h0));

    // The acceptor of the SHORT bill retires it (shipped RETIRE has no maturity
    // gate, so this is always available to him).
    h.nLoanBookFace -= 100000000;
    h.SetLoanWtMaturity(h.LoanWtMaturity() - (unsigned __int128)100000000 * 10);
    BOOST_CHECK(HouseLoanBookDuration(h, h0) < bookDurBefore);   // duration FELL
    BOOST_CHECK(HouseMatchFundingOK(h, h0));                     // still compliant

    // The average, by contrast, doubled: 5005 -> 10000. An average-based rule
    // with DepositWAM 6000 would now be in violation, with no act of the house.
    const uint64_t avgAfter = (uint64_t)(h.LoanWtMaturity() / h.nLoanBookFace);
    BOOST_CHECK_EQUAL(avgAfter, 10000);
}

BOOST_AUTO_TEST_CASE(house_match_funding_max_magnitude)
{
    // The cross-multiplication must not overflow at the stated ceilings:
    // L <= MAX_MONEY < 2^51 and DepositDuration < 2^73 give a left side < 2^124;
    // slice < 2^51 and BookDuration < 2^71 give a right side < 2^122.
    CHouse h = LoanBookHouse(0);
    h.nLoanBookFace = (uint64_t)MAX_MONEY;
    h.SetLoanWtMaturity((unsigned __int128)MAX_MONEY * MAX_BILL_TENOR_BLOCKS);
    h.nDepositUnits = (uint64_t)MAX_MONEY;
    h.SetDepositWtMaturity((unsigned __int128)MAX_MONEY * MAX_DEPOSIT_TERM_BLOCKS);

    BOOST_CHECK_EQUAL(HouseLoanBookSlice(h, 1000), (uint64_t)MAX_MONEY);
    const unsigned __int128 bookDur = HouseLoanBookDuration(h, 0);
    const unsigned __int128 depDur = HouseDepositDuration(h, 0);
    BOOST_CHECK(bookDur == (unsigned __int128)MAX_MONEY * MAX_BILL_TENOR_BLOCKS);
    BOOST_CHECK(depDur == (unsigned __int128)MAX_MONEY * MAX_DEPOSIT_TERM_BLOCKS);
    // Both products are representable, and the longer deposit book wins.
    const unsigned __int128 lhs = (unsigned __int128)h.nLoanBookFace * depDur;
    const unsigned __int128 rhs = (unsigned __int128)HouseLoanBookSlice(h, 1000) * bookDur;
    BOOST_CHECK(lhs > rhs);
    BOOST_CHECK(lhs / h.nLoanBookFace == depDur);      // no wrap occurred
    BOOST_CHECK(HouseMatchFundingOK(h, 0));
    BOOST_CHECK_EQUAL(LOAN_BOOK_MAX_FACE, (uint64_t)MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(house_ser_v8_loan_book_migration)
{
    // v8 adds the loan book. A v7 record must read at its old layout with the
    // book defaulting to empty - which is exactly right, since no discount op
    // existed before v8, so L was structurally 0 on every pre-B1 record.
    CHouse h = LoanBookHouse(100000000);
    h.houseID = uint256S("0a0b");
    h.strClassID = "ayr";
    h.vchRedemptionDestPK = std::vector<unsigned char>(33, 0x02);
    h.nMintedUnits = 90000000;
    h.nLoanBookFace = 40000000;
    h.SetLoanWtMaturity((unsigned __int128)40000000 * 8740);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << h;
    std::vector<unsigned char> vch(ss.begin(), ss.end());
    BOOST_CHECK_EQUAL(vch[0], HOUSE_SER_VERSION);
    // TRIPWIRE, and it has now fired once (B3 T-b1, v8 -> v9): bumping the
    // record version MUST come here, because the v7 synthesis below strips a
    // FIXED number of trailing bytes and every new version adds more. Update
    // BOTH this pin and the addendum arithmetic together, or the synthesis
    // silently builds a malformed record and the migration it claims to prove
    // proves nothing.
    BOOST_CHECK_EQUAL(HOUSE_SER_VERSION, 15);   // fired again at v9 -> v10 (members-only flags, 1 byte),
                                                // v10 -> v11 (token backing, 1 u64), v12 -> v13 (gram snapshot),
                                                // v13 -> v14 (Gold B no-cure height u32 + tranche list)
                                                // and v14 -> v15 (UR-ext-12 episode counters: 2 u32 + 2 u8)

    CHouse back;
    CDataStream ssIn(vch, SER_NETWORK, PROTOCOL_VERSION);
    ssIn >> back;
    BOOST_CHECK_EQUAL(back.nLoanBookFace, h.nLoanBookFace);
    BOOST_CHECK(back.LoanWtMaturity() == h.LoanWtMaturity());
    BOOST_CHECK_EQUAL(back.nMintedUnits, h.nMintedUnits);

    // Re-writing reproduces the same bytes (byte-exact reorg compare).
    CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
    ssOut << back;
    BOOST_CHECK(std::vector<unsigned char>(ssOut.begin(), ssOut.end()) == vch);

    // A v7 record (the live HouseDB's current layout) must read with the book
    // defaulting to empty: synthesise one by stamping v7 and dropping the
    // 24-byte v8 addendum from a record whose book is zero.
    {
        CHouse v8zero = LoanBookHouse(100000000);
        v8zero.nHouseID = 12;
        v8zero.strClassID = "clyde";
        v8zero.nMintedUnits = 5000;
        v8zero.nLastSettleHeight = 990;               // the v7 leg must survive
        CDataStream ssZ(SER_NETWORK, PROTOCOL_VERSION);
        ssZ << v8zero;
        std::vector<char> b(ssZ.begin(), ssZ.end());
        BOOST_REQUIRE_EQUAL((uint8_t)b[0], (uint8_t)HOUSE_SER_VERSION);
        b[0] = (char)7;
        // Strip EVERY post-v7 addendum, newest first:
        //   v8 loan book   = 3 x uint64 = 24 bytes
        //   v9 protest     = 3 x uint32 = 12 bytes
        //   v10 flags      = 1 x uint8  =  1 byte
        //   v11 tokens     = 1 x uint64 =  8 bytes
        static const size_t V8_ADDENDUM = 3 * sizeof(uint64_t);
        static const size_t V9_ADDENDUM = 3 * sizeof(uint32_t);
        static const size_t V10_ADDENDUM = sizeof(uint8_t);
        static const size_t V11_ADDENDUM = sizeof(uint64_t);
        static const size_t V12_ADDENDUM = 4 * sizeof(uint64_t) + 4 * sizeof(uint32_t);   // the token claim totals
        static const size_t V13_ADDENDUM = 2 * sizeof(uint64_t) + sizeof(uint32_t);       // the gram snapshot + equity
        static const size_t V14_ADDENDUM = sizeof(uint32_t) + 1 + sizeof(uint32_t);   // no-cure height, tranches, cure left
        static const size_t V15_ADDENDUM = 3 * sizeof(uint32_t) + 2 * sizeof(uint8_t);  // UR-ext-12 episode counters + end height
        b.resize(b.size() - (V8_ADDENDUM + V9_ADDENDUM + V10_ADDENDUM + V11_ADDENDUM + V12_ADDENDUM + V13_ADDENDUM +
                             V14_ADDENDUM + V15_ADDENDUM));
        CDataStream ssV7(b, SER_NETWORK, PROTOCOL_VERSION);
        CHouse h7;
        ssV7 >> h7;                                   // must not throw
        BOOST_CHECK_EQUAL(h7.nHouseID, 12);
        BOOST_CHECK_EQUAL(h7.nLastSettleHeight, 990);
        BOOST_CHECK_EQUAL(h7.nLoanBookFace, 0);       // empty book, as every pre-B1 house
        BOOST_CHECK(h7.LoanWtMaturity() == 0);
        // ...and no live protest, as every pre-B3 house (v9 defaults)
        BOOST_CHECK_EQUAL(h7.nProtestOpen, 0u);
        BOOST_CHECK_EQUAL(h7.nProtestHeight, 0u);
        BOOST_CHECK(!h7.ProtestLive());
        BOOST_CHECK(HouseMatchFundingOK(h7, 1000));   // and vacuously compliant
    }

    // A FUTURE version is a hard read failure - consensus state is never
    // silently defaulted.
    vch[0] = HOUSE_SER_VERSION + 1;
    CHouse bad;
    CDataStream ssBad(vch, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_THROW(ssBad >> bad, std::ios_base::failure);
}

// ===========================================================================
// v0.2.28 (FAILED_HOUSE_DESIGN.md B, E): collect then pay; CLOSE; the mutual fund lock
// ===========================================================================
namespace {
// The guard house, failed: stored Insolvent with a snapshot of 100 note units against a pot of `pot`, and its two
// partners' pledge coins a0 / a1 live at pot/2 each.
static CHouse MakeFailedHouse(CAmount pot)
{
    CHouse house = MakeGuardHouse();
    // Gram-notes release: the old missed-cadence origin, stored (it no longer derives).
    house.nStressSinceHeight = house.nLastAttestHeight + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1;
    house.status = HOUSE_STATUS_INSOLVENT;
    house.nInsolventHeight = 1500;
    house.nInsolventUnits = 100;
    house.nMintedUnits = 40;                     // 60 units already claimed or burned
    house.amountInsolventPot = pot;
    house.nInsolventSatsPerGram = 1000;   // gram-notes release: the snapshot price (1 mg = 1 sat)
    house.vPartner[0].amountInsolventPledge = pot / 2;
    house.vPartner[1].amountInsolventPledge = pot / 2;
    return house;
}

static CMutableTransaction MakeCloseTx(uint32_t nHouseID, const std::vector<COutPoint>& vIn,
                                       const std::vector<CTxOut>& vOut)
{
    HouseClose cl;
    cl.nHouseID = nHouseID;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_CLOSE;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << cl;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    for (const COutPoint& o : vIn)
        mtx.vin.push_back(CTxIn(o));
    mtx.vout = vOut;
    return mtx;
}
} // namespace

BOOST_AUTO_TEST_CASE(house_collection_gate)
{
    CHouse house = MakeFailedHouse(60);
    const uint32_t nE = HouseInsolventSince(house, 1000000);
    BOOST_REQUIRE(nE != 0);
    const uint32_t nWin = Params().GetConsensus().nCollectWindow;
    house.nLoanBookFace = 5000;                  // the book has not run off
    BOOST_CHECK(!HouseCollectionDone(house, (int)(nE + nWin - 1)));
    BOOST_CHECK(HouseCollectionDone(house, (int)(nE + nWin)));
    house.nLoanBookFace = 0;                     // ...or it has: payouts open at once
    BOOST_CHECK(HouseCollectionDone(house, (int)nE));
    BOOST_CHECK(!HouseCollectionDone(MakeGuardHouse(), 1000));   // not insolvent: never
}

BOOST_AUTO_TEST_CASE(house_close_after_the_claim_window)
{
    const COutPoint a0(uint256S("a0"), 0), a1(uint256S("a1"), 0);
    auto run = [&](const CHouse& house, int nHeight, const CMutableTransaction& mtx, CHouse& houseOut) {
        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        auto fnGetCoin = [&](const COutPoint& o, Coin& c) {
            if (o == a0 || o == a1) { c = GuardEscrowCoin(house.nHouseID, house.amountInsolventPot / 2); return true; }
            if (o == COutPoint(uint256S("e9"), 0)) { c = GuardEscrowCoin(house.nHouseID, 7); return true; }  // unlisted
            return false;
        };
        CValidationState state;
        const bool f = CheckHouseOperation(CTransaction(mtx), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass,
                                           fnGetCoin, GuardNoBlock, houseOut);
        return f ? std::string("OK") : state.GetRejectReason();
    };
    // Under par (pot 60 < 100 units): partners get nothing, the fund gets all 60.
    {
        const CHouse house = MakeFailedHouse(60);
        const int nOpen = (int)HouseClaimWindowCloses(house, 1000000);
        BOOST_REQUIRE(nOpen > 0);
        const CMutableTransaction good = MakeCloseTx(house.nHouseID, {a0, a1}, {CTxOut(60, MutualFundScript())});
        CHouse out;
        BOOST_CHECK_EQUAL(run(house, nOpen - 1, good, out), "bad-house-close-window-open");
        BOOST_CHECK_EQUAL(run(house, nOpen, good, out), "OK");
        BOOST_CHECK(HouseClosed(out));
        // A second CLOSE, and every claim after it, refuse.
        BOOST_CHECK_EQUAL(run(out, nOpen + 1, good, out), "bad-house-close-closed");
        // Pinned: every live escrow coin, the exact fund value, nothing escrow-shaped after.
        BOOST_CHECK_EQUAL(run(house, nOpen, MakeCloseTx(house.nHouseID, {a0}, {CTxOut(30, MutualFundScript())}), out),
                          "bad-house-close-incomplete");
        BOOST_CHECK_EQUAL(run(house, nOpen, MakeCloseTx(house.nHouseID, {a0, a1}, {CTxOut(59, MutualFundScript())}), out),
                          "bad-house-close-fund");
        BOOST_CHECK_EQUAL(run(house, nOpen, MakeCloseTx(house.nHouseID, {a0, a1},
                          {CTxOut(60, MutualFundScript()), CTxOut(1, MutualFundScript())}), out), "bad-house-close-stray");
        BOOST_CHECK_EQUAL(run(house, nOpen, MakeCloseTx(house.nHouseID, {a0, a1},
                          {CTxOut(60, MutualFundScript()), CTxOut(1, HouseEscrowScript(house.houseID))}), out),
                          "bad-house-close-stray");
        // Not insolvent: never.
        BOOST_CHECK_EQUAL(run(MakeGuardHouse(), 1000, good, out), "bad-house-close-not-insolvent");
        // A bill still in the book would be stuck for good once closed: clear it first (op 11, anyone).
        CHouse hBook = house;
        hBook.nLoanBookFace = 5000;
        BOOST_CHECK_EQUAL(run(hBook, nOpen, good, out), "bad-house-close-book-open");
        // An escrow coin the house does not list may not ride along (its value would leave as change).
        BOOST_CHECK_EQUAL(run(house, nOpen, MakeCloseTx(house.nHouseID, {a0, a1, COutPoint(uint256S("e9"), 0)},
                          {CTxOut(60, MutualFundScript())}), out), "bad-house-close-unlisted-escrow");
    }
    // Over par (pot 160 > 100 units): partners get EXACTLY the residual 60 (30 each), the fund the other 100.
    {
        const CHouse house = MakeFailedHouse(160);
        const int nOpen = (int)HouseClaimWindowCloses(house, 1000000);
        const CScript p0 = NoteScriptForPubKey(house.vPartner[0].vchPubKey);
        const CScript p1 = NoteScriptForPubKey(house.vPartner[1].vchPubKey);
        CHouse out;
        BOOST_CHECK_EQUAL(run(house, nOpen, MakeCloseTx(house.nHouseID, {a0, a1},
                          {CTxOut(30, p0), CTxOut(30, p1), CTxOut(100, MutualFundScript())}), out), "OK");
        // No sweep: the partners may not take the fund's share.
        BOOST_CHECK_EQUAL(run(house, nOpen, MakeCloseTx(house.nHouseID, {a0, a1},
                          {CTxOut(30, p0), CTxOut(130, p1), CTxOut(0, MutualFundScript())}), out),
                          "bad-house-close-payout");
    }
}

BOOST_AUTO_TEST_CASE(mutual_fund_output_is_locked)
{
    // Open at the script layer, locked by consensus: no transaction of any kind spends it.
    CCoinsView base;
    CCoinsViewCache cache(&base);
    const COutPoint fundOut(uint256S("f0f0"), 0);
    cache.AddCoin(fundOut, Coin(CTxOut(5 * COIN, MutualFundScript()), 100, false, false, false, uint256()), false);
    for (int nVersion : {1, TRANSACTION_HOUSE_VERSION}) {
        CMutableTransaction mtx;
        mtx.nVersion = nVersion;
        if (nVersion == TRANSACTION_HOUSE_VERSION) {
            mtx.nHouseOp = HOUSE_OP_CLOSE;
            HouseClose cl; cl.nHouseID = 7;
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << cl;
            mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
        }
        mtx.vin.push_back(CTxIn(fundOut));
        mtx.vout.push_back(CTxOut(4 * COIN, GetScriptForDestination(CKeyID())));
        CValidationState state;
        CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-spend-mutual-fund");
    }
    // It can never pass for an escrow script either.
    BOOST_CHECK(!IsHouseEscrowScript(MutualFundScript()));
}

// Gold B (D-2026-11-07-2/-3): a house closes only when it doesn't pay a demand. A protest starts a cure (Stressed for
// the window, then insolvent unless the demand is paid); one cure per 180 days - a fresh protest episode within
// HOUSE_CURE_SPACING_BLOCKS of the last one's END (UR-ext-12 precision 2) finds none, and the house is insolvent from
// that block.
BOOST_AUTO_TEST_CASE(house_one_cure_per_180_days)
{
    CHouse house = MakeGuardHouse();
    const uint32_t nH1 = 2000;
    // The first protest episode is a cure.
    HouseProtestEpisodeStart(house, nH1);
    BOOST_CHECK_EQUAL(house.nNoCureHeight, 0u);
    house.nProtestOpen = 1;              // what the protest op writes after the call
    house.nProtestHeight = nH1;
    house.nProtestDemandHeight = nH1 - 100;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nH1), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nH1 + HOUSE_STRESSED_WINDOW - 1), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nH1 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_INSOLVENT);
    BOOST_CHECK_EQUAL(HouseInsolventSince(house, nH1 + HOUSE_STRESSED_WINDOW + 5), nH1 + HOUSE_STRESSED_WINDOW);
    // Cured: the demand paid takes the counter to zero and ends the episode; the heights stay as inert leftovers.
    const uint32_t nPaid = nH1 + 100;
    house.nProtestOpen = 0;
    HouseDischargeMaybeEndsEpisode(house, nPaid);
    BOOST_CHECK_EQUAL(house.nEpisodeEndHeight, nPaid);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, nH1 + HOUSE_STRESSED_WINDOW), HOUSE_STATUS_OPEN);

    // A second unpaid demand protested within 180 days of the episode's end: no cure, insolvent from that block.
    {
        CHouse h = house;
        const uint32_t nH2 = nPaid + HOUSE_CURE_SPACING_BLOCKS - 1;
        HouseProtestEpisodeStart(h, nH2);
        BOOST_CHECK_EQUAL(h.nNoCureHeight, nH2);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, nH2 - 1), HOUSE_STATUS_OPEN);
        BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, nH2), HOUSE_STATUS_INSOLVENT);
        BOOST_CHECK_EQUAL(HouseInsolventSince(h, nH2 + 10), nH2);
    }
    // 180 days after the START but not the end: still no cure (precision 2).
    {
        CHouse h = house;
        HouseProtestEpisodeStart(h, nH1 + HOUSE_CURE_SPACING_BLOCKS);
        BOOST_CHECK_EQUAL(h.nNoCureHeight, nH1 + HOUSE_CURE_SPACING_BLOCKS);
    }
    // 180 days after the episode's end, a protest is a fresh cure.
    {
        CHouse h = house;
        HouseProtestEpisodeStart(h, nPaid + HOUSE_CURE_SPACING_BLOCKS);
        BOOST_CHECK_EQUAL(h.nNoCureHeight, 0u);
    }

    // The v14 field round-trips.
    {
        CHouse h = house;
        h.nNoCureHeight = 4242;
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << h;
        CHouse back;
        ss >> back;
        BOOST_CHECK_EQUAL(back.nNoCureHeight, 4242u);
    }

    // The EQUITY op (17) is retired: bad loans never close a house, since a house can repay a bill for its borrower.
    {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_RETIRED_EQUITY;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
        mtx.vchHousePayload = {0x01, 0x00, 0x00, 0x00};
        CValidationState state;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-op-retired");
    }
}

// Gold B clocks in time (GOLD_B.md §6): windows count clock blocks (600 s of chain active time), so a chain that makes a
// block every 30 minutes (three clock blocks each) runs its windows in a third of the blocks.
static int64_t SparseClock(int nHeight) { return nHeight <= 0 ? 0 : 3 * (int64_t)nHeight; }

BOOST_AUTO_TEST_CASE(clock_windows_count_time)
{
    const ClockAtFn fnPrev = g_fnClockAt;
    g_fnClockAt = &SparseClock;

    BOOST_CHECK_EQUAL(ClockSince(100, 110), 30);
    BOOST_CHECK_EQUAL(ClockSince(110, 100), 0);
    // 1008 clock blocks from block 1000 have run at the first h with 3h - 3000 >= 1008: 1336.
    BOOST_CHECK_EQUAL(ClockDeadlineHeight(1000, 1008, 5000), 1336u);
    // Not yet run by 1100 (300 of 1008): estimated 708 blocks on.
    BOOST_CHECK_EQUAL(ClockDeadlineHeight(1000, 1008, 1100), 1808u);
    // A bill issued at 1000 naming maturity 2000 (a 1000-clock-block term) matures at 1334 (3 x 334 = 1002 >= 1000).
    BOOST_CHECK_EQUAL(TermDeadlineHeight(1000, 2000, 0, 5000), 1334u);
    BOOST_CHECK_EQUAL(TermDeadlineHeight(0, 2000, 0, 5000), 2000u);   // no start: counts from the target

    // The cure: a protest at 2000 runs out at 2000 + 1008/3 = 2336.
    CHouse house = MakeGuardHouse();
    house.nProtestOpen = 1;
    house.nProtestHeight = 2000;
    house.nProtestDemandHeight = 1900;
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 2335), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(house, 2336), HOUSE_STATUS_INSOLVENT);
    BOOST_CHECK_EQUAL(HouseInsolventSince(house, 2400), 2336u);
    BOOST_CHECK_EQUAL(HouseInsolventSince(house, 9999), 2336u);   // E never moves

    // One cure per 180 days counts time: 25920 clock blocks = 8640 of these blocks (from the episode's end: paid at 2000).
    house.nProtestOpen = 0;
    house.nEpisodeEndHeight = 2000;
    {
        CHouse h = house;
        HouseProtestEpisodeStart(h, 2000 + 8639);
        BOOST_CHECK_EQUAL(h.nNoCureHeight, 2000u + 8639);
    }
    {
        CHouse h = house;
        HouseProtestEpisodeStart(h, 2000 + 8640);
        BOOST_CHECK_EQUAL(h.nNoCureHeight, 0u);
    }

    // Interest accrues by time: a plain demand at 1000 paid at 1100 owes 300 clock blocks of interest, not 100.
    {
        CHouse h = MakeGuardHouse();
        const Consensus::Params& cp = Params().GetConsensus();
        const uint64_t nUnits = 52560000;
        BOOST_CHECK_EQUAL(NoteDemandInterest(h, 1000, nUnits, 1100, cp),
                          NoteDeferralInterest(nUnits, 3000, 3300, cp.vDeferInterestSchedule));
        g_fnClockAt = nullptr;   // the height clock: 100 blocks
        BOOST_CHECK_EQUAL(NoteDemandInterest(h, 1000, nUnits, 1100, cp),
                          NoteDeferralInterest(nUnits, 1000, 1100, cp.vDeferInterestSchedule));
    }

    g_fnClockAt = fnPrev;
}

// Gold B ramp (GOLD_B.md §5): each escrow tranche counts 1x, doubling per clean period (180 days of clock blocks) up to
// the 10% floor's 10x; new escrow starts at 1x; a protest resets every tranche.
BOOST_AUTO_TEST_CASE(escrow_ramp)
{
    const auto fnPrevCap = g_fnCapitalForChecksTestOverride;
    g_fnCapitalForChecksTestOverride = nullptr;   // the real count (the fixture's rate: 1000 sats per gram, so sats = mg)
    const uint32_t P = Params().GetConsensus().GramAt(1).nRampPeriodBlocks;
    CHouse h;
    h.nHouseID = 9;
    h.nRegisteredHeight = 100;
    HousePartner p;
    p.amountPledge = 1000000;
    p.status = HOUSE_PARTNER_ACTIVE;
    h.vPartner.push_back(p);
    h.vEscrowTranche.emplace_back(0, 1000000, 100);
    auto fnCap = [&](const CHouse& house, int nHeight) {
        CHouseCapital cap;
        BOOST_REQUIRE(HouseCapitalForChecks(house, nHeight, 0, cap));
        return cap.nCapacityMg;
    };
    BOOST_CHECK_EQUAL(fnCap(h, 100 + P - 1), 1000000u);       // 1x
    BOOST_CHECK_EQUAL(fnCap(h, 100 + P), 2000000u);           // a clean period: 2x
    BOOST_CHECK_EQUAL(fnCap(h, 100 + 3 * P), 8000000u);       // 8x
    BOOST_CHECK_EQUAL(fnCap(h, 100 + 4 * P), 10000000u);      // capped at the floor's 10x
    // A top-up arrives at 1x.
    h.vPartner[0].amountPledge += 1000000;
    h.vEscrowTranche.emplace_back(0, 1000000, 100 + 4 * P);
    BOOST_CHECK_EQUAL(fnCap(h, 100 + 4 * P), 11000000u);
    // A protest resets every tranche to 1x.
    h.nProtestHeight = 100 + 4 * P + 10;
    BOOST_CHECK_EQUAL(fnCap(h, 100 + 4 * P + 10), 2000000u);
    BOOST_CHECK_EQUAL(fnCap(h, 100 + 5 * P + 10), 4000000u);
    // ...and so does the end of a suspension (security stage A V1): the time suspended is not clean.
    CHouse susp = h;
    susp.nDeferEndedHeight = 100 + 7 * P + 10;
    BOOST_CHECK_EQUAL(fnCap(susp, 100 + 7 * P + 10), 2000000u);   // back to 1x at the recovery, not 10x
    BOOST_CHECK_EQUAL(fnCap(susp, 100 + 8 * P + 10), 4000000u);
    // An exited partner's escrow doesn't count; a record without tranches counts from registration.
    CHouse legacy = h;
    legacy.vEscrowTranche.clear();
    legacy.nProtestHeight = 0;
    BOOST_CHECK_EQUAL(fnCap(legacy, 100 + P), 4000000u);      // 2,000,000 at 2x
    legacy.vPartner[0].status = HOUSE_PARTNER_TAIL;
    BOOST_CHECK_EQUAL(fnCap(legacy, 100 + P), 0u);
    g_fnCapitalForChecksTestOverride = fnPrevCap;
}

// Design 2026-11-08: a suspension's recovery that re-arms a live protest CONTINUES its cure with the time left
// (CHouse::nCureLeft), and the 180-day spacing counts from the end of the last episode (the recovery).
BOOST_AUTO_TEST_CASE(cure_continues_after_recovery)
{
    CHouse h = MakeGuardHouse();
    h.nProtestOpen = 1;
    h.nProtestHeight = 100;
    h.nDeferEndedHeight = 300;   // the recovery that re-armed the protest
    h.nCureLeft = 50;
    BOOST_CHECK_EQUAL(HouseCureWindow(h, 300), 50u);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, 349), HOUSE_STATUS_STRESSED);
    BOOST_CHECK_EQUAL(HouseEffectiveStatus(h, 350), HOUSE_STATUS_INSOLVENT);
    BOOST_CHECK_EQUAL(HouseInsolventSince(h, 400), 350u);
    // A fresh protest (no re-arm) gets the whole window.
    CHouse f = h;
    f.nDeferEndedHeight = 0;
    BOOST_CHECK_EQUAL(HouseCureWindow(f, 100), (uint64_t)HOUSE_STRESSED_WINDOW);
    // The spacing counts from the episode's end - here the payment at 320, after the recovery re-armed the protest -
    // not the protest's start or the recovery (UR-ext-12 precision 2).
    CHouse g = h;
    g.nProtestOpen = 0;
    HouseDischargeMaybeEndsEpisode(g, 320);
    HouseProtestEpisodeStart(g, 320 + HOUSE_CURE_SPACING_BLOCKS - 1);
    BOOST_CHECK_EQUAL(g.nNoCureHeight, 320u + HOUSE_CURE_SPACING_BLOCKS - 1);
    CHouse g2 = h;
    g2.nProtestOpen = 0;
    HouseDischargeMaybeEndsEpisode(g2, 320);
    HouseProtestEpisodeStart(g2, 320 + HOUSE_CURE_SPACING_BLOCKS);
    BOOST_CHECK_EQUAL(g2.nNoCureHeight, 0u);
}

// The overdue bills the chain sees (information for the RPCs and the explorer; no rule reads it, D-2026-11-07-3):
// this house's bills unpaid nBillOverdueBlocks past maturity.
BOOST_AUTO_TEST_CASE(house_overdue_bills_seen)
{
    sidechain_test::SideDBScope sideDBs;
    CHouse house = MakeGuardHouse();
    CBill bill;
    bill.nBillID = 1;
    bill.billID = uint256S("b1");
    bill.amount = 5000;
    bill.nMaturityHeight = 1000;
    bill.nOwnerHouseID = house.nHouseID;
    CBill other = bill;
    other.nBillID = 2;
    other.billID = uint256S("b2");
    other.nOwnerHouseID = house.nHouseID + 1;
    BOOST_REQUIRE(pbilltree->WriteBills({bill, other}));
    BOOST_CHECK(HouseOverdueBills(house, 2000) == std::vector<uint32_t>{1});
    BOOST_CHECK(HouseOverdueBills(house, 1432).empty());
}

// testing (2026-11-10), ultra s3 UR3-3. Six contextual checks reject an op whose undo PRIORS are stale (a block just
// changed the house or bill record) at DoS 100 even in the mempool. Stale state is the honest relayer's case: a peer one
// block behind, or a block from another miner. The file's own rule (the ATTEST as-of checks: fMempool ? 0 : 100) says a
// mempool reject of something a block could have made stale must not ban. Represented by HOUSE_OP_DEFER's prior (the
// same pattern as ATTEST and bill DISCOUNT/RETIRE/HRETIRE_NOTES/RECOURSE). The block-context score must stay 100.
// FAILS on v1.2.1 (the mempool score is 100).
BOOST_AUTO_TEST_CASE(testing_ur3_3_stale_prior_does_not_ban_in_mempool)
{
    CKey keyPartner;
    keyPartner.MakeNewKey(true);
    const CPubKey pubPartner = keyPartner.GetPubKey();
    CHouse house = MakeGuardHouse();
    house.vPartner[0].vchPubKey = std::vector<unsigned char>(pubPartner.begin(), pubPartner.end());
    house.nLastAttestHeight = 2000;
    house.nStressSinceHeight = 2000;
    house.nDeferActivations = 3;
    house.nDeferLastActivation = 1990;   // the record NOW, after a block moved it
    house.nDeferCumBlocks = 38880;
    house.nDeferEndedHeight = 1995;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, 2000), HOUSE_STATUS_STRESSED);

    // Built and signed correctly against the record as it stood before that block (last activation 1980).
    HouseDefer def;
    def.nHouseID = house.nHouseID;
    def.nPrevLastActivation = 1980;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_DEFER;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    mtx.vout.push_back(CTxOut(house.amountLastAttestReserves, HouseEscrowScript(house.houseID)));   // the till lock
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
    def.vApproverIndex.push_back(0);
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyPartner.Sign(HouseDeferSigHash(house.houseID, def.nPrevLastActivation, BillHashOutputs(mtx)), vchSig));
    def.vApproverSig.push_back(vchSig);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << def;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };

    // In a block it is invalid: refused at DoS 100.
    {
        CValidationState state;
        CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut, false));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-defer-priors");
        int nDoS = -1;
        BOOST_CHECK(state.IsInvalid(nDoS) && nDoS == 100);
    }
    // In the mempool it is refused too, but the relaying peer did nothing wrong: DoS 0.
    {
        CValidationState state;
        CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, 2000, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut, true));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-defer-priors");
        int nDoS = -1;
        BOOST_CHECK_MESSAGE(state.IsInvalid(nDoS) && nDoS == 0,
                            "a stale-prior DEFER in the mempool scored DoS " << nDoS << " - an honest relayer one block behind is banned (UR3-3)");
    }

    // The same class at the ATTEST monotone check (the 7th site, freebankd 11-10): a block confirmed another ATTEST for
    // the house (last attest now 1999), and a peer relays one built before it with as-of 1999 - valid when built.
    CHouse h2 = MakeGuardHouse();
    h2.nLastAttestHeight = 1999;
    const int nEff = HouseEffectiveStatus(h2, 2000);
    BOOST_REQUIRE(nEff == HOUSE_STATUS_OPEN || nEff == HOUSE_STATUS_STRESSED);
    HouseAttest att;
    att.nHouseID = h2.nHouseID;
    att.nSchemaVersion = 1;
    att.nAsOfHeight = 1999;   // not in the future, not stale - only no longer above the last attest
    auto fnGetH2 = [&](uint32_t id, CHouse& out) { if (id == h2.nHouseID) { out = h2; return true; } return false; };
    for (const bool fMempool : {false, true}) {
        CValidationState state;
        CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(MakeAttestTx(att)), state, 2000, fnGetH2, GuardNoHash, GuardNoClass, fnNoCoin, GuardNoBlock, houseOut, fMempool));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-attest-monotone");
        int nDoS = -1;
        BOOST_CHECK_MESSAGE(state.IsInvalid(nDoS) && nDoS == (fMempool ? 0 : 100),
                            "ATTEST monotone in " << (fMempool ? "the mempool" : "a block") << " scored DoS " << nDoS
                            << ", want " << (fMempool ? 0 : 100) << " (UR3-3, 7th site)");
    }
}

// The same declaration as a REGISTER_MO (members-only): the house id, and so the escrow outputs, bind the flags. The
// shape check verifies no founding signature (that is contextual), so the REGISTER's signatures can stay.
static CMutableTransaction AsRegisterMoTx(const CMutableTransaction& mtxReg, const HouseRegister& reg)
{
    CMutableTransaction mtx(mtxReg);
    HouseRegisterMO mo;
    mo.reg = reg;
    mo.nFlags = HOUSE_FLAG_MEMBERS_ONLY;
    mtx.nHouseOp = HOUSE_OP_REGISTER_MO;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mo;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    const CScript escrow = HouseEscrowScript(HouseIDFromDeclaration(reg, mo.nFlags));
    for (CTxOut& o : mtx.vout)
        o.scriptPubKey = escrow;
    return mtx;
}

// testing (2026-11-10), ultra s1 UR1-3. The shape check gives every bill op past DISCOUNT the tight MAX_BILL_OP_PAYLOAD
// cap (4096) on the stated grounds that those ops "carry neither" an approver set nor a proof set - but BILL_OP_HCLAIM
// carries the house's full M-of-N approver set. So a house can register with a threshold whose approvals can't fit an
// HCLAIM, and its bills' escrow can then never be claimed. Whatever the fix (raise the cap, or refuse such a threshold
// at REGISTER and REGISTER_MO), the largest threshold either register op accepts must have its HCLAIM fit - and its
// settle EXCHANGE, which carries BOTH houses' approver sets in one MAX_SETTLE_PAYLOAD (4096) payload (freebankd
// 2026-11-10: that is what makes 24 the limit; NET has no payload cap of its own). Real shape checks throughout; only
// coinbase and op-range run before the bill size cap, and this HCLAIM passes both. FAILS on v1.2.1.
BOOST_AUTO_TEST_CASE(testing_ur1_3_registrable_threshold_fits_hclaim)
{
    // The largest threshold each multi-partner register op's shape check accepts (one partner per approver).
    uint32_t nLargestReg = 0, nLargestMo = 0;
    for (uint32_t M = MAX_HOUSE_PARTNERS; M >= 2 && (nLargestReg == 0 || nLargestMo == 0); M--) {
        HouseRegister reg;
        std::vector<CKey> vKey;
        const CMutableTransaction mtxReg = MakeRegisterTx(reg, vKey, HOUSE_TIER_MULTI_PARTNER, M, M, "ur13m" + std::to_string(M));
        CValidationState stateReg, stateMo;
        if (nLargestReg == 0 && CheckHouseTransactionShape(CTransaction(mtxReg), stateReg))
            nLargestReg = M;
        if (nLargestMo == 0 && CheckHouseTransactionShape(CTransaction(AsRegisterMoTx(mtxReg, reg)), stateMo))
            nLargestMo = M;
    }
    BOOST_REQUIRE_MESSAGE(nLargestReg >= 2, "no multi-partner REGISTER was accepted at all");
    BOOST_REQUIRE_MESSAGE(nLargestMo >= 2, "no multi-partner REGISTER_MO was accepted at all");
    BOOST_TEST_MESSAGE("largest threshold accepted: REGISTER " << nLargestReg << ", REGISTER_MO " << nLargestMo);
    const uint32_t nLargest = std::max(nLargestReg, nLargestMo);

    // A settle EXCHANGE between two such houses, every signature at the DER maximum (72 bytes).
    {
        SettleExchange x;
        x.nHouseA = 1;
        x.nHouseB = 2;
        x.nMode = 1;
        x.nUnitsANotes = 2;
        x.nUnitsBNotes = 1;
        x.nCountANotes = 1;
        x.nCountBNotes = 1;
        x.vchPresentKeyOfANotes.assign(33, 0x02);
        x.vchPresentKeyOfBNotes.assign(33, 0x03);
        x.amountResidual = SETTLE_MIN_RESIDUAL_SATS;
        x.vchPresentSigOfANotes.assign(72, 0x30);
        x.vchPresentSigOfBNotes.assign(72, 0x30);
        for (uint32_t i = 0; i < nLargest; i++) {
            x.vApproverIndexA.push_back(i);
            x.vApproverSigA.push_back(std::vector<unsigned char>(72, 0x30));
            x.vApproverIndexB.push_back(i);
            x.vApproverSigB.push_back(std::vector<unsigned char>(72, 0x30));
        }
        CMutableTransaction mtxS;
        mtxS.nVersion = TRANSACTION_SETTLE_VERSION;
        mtxS.nSettleOp = SETTLE_OP_EXCHANGE;
        CDataStream ssS(SER_NETWORK, PROTOCOL_VERSION);
        ssS << x;
        mtxS.vchSettlePayload.assign(ssS.begin(), ssS.end());
        mtxS.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtxS.vin.push_back(CTxIn(COutPoint(uint256S("02"), 0)));
        mtxS.vout.push_back(CTxOut(SETTLE_MIN_RESIDUAL_SATS, CScript() << OP_TRUE));
        CValidationState stateS;
        CheckSettleTransactionShape(CTransaction(mtxS), stateS);   // only the size matters here
        BOOST_CHECK_MESSAGE(stateS.GetRejectReason() != "bad-settle-payload-size",
                            "two houses can register with threshold " << nLargest << " but their settle EXCHANGE ("
                            << mtxS.vchSettlePayload.size() << " bytes) exceeds the " << MAX_SETTLE_PAYLOAD
                            << "-byte cap: they can never settle bilaterally (UR1-3)");
    }

    // An HCLAIM carrying that many approvals, each a maximum-size DER signature (72 bytes).
    BillHClaim c;
    c.nBillID = 1;
    c.nOwnerHouseID = 1;
    c.amountFace = COIN;
    c.nBillMaturityHeight = 1000;
    for (uint32_t i = 0; i < nLargest; i++) {
        c.vApproverIndex.push_back(i);
        c.vApproverSig.push_back(std::vector<unsigned char>(72, 0x30));
    }
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_HCLAIM;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << c;
    mtx.vchBillPayload.assign(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));   // not a coinbase
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    CValidationState state;
    CheckBillTransactionShape(CTransaction(mtx), state);   // may fail later for other reasons: only the size matters here
    BOOST_CHECK_MESSAGE(state.GetRejectReason() != "bad-bill-payload-oversize",
                        "a house can register with threshold " << nLargest << " but an HCLAIM carrying that many approvals ("
                        << mtx.vchBillPayload.size() << " bytes) exceeds the " << MAX_BILL_OP_PAYLOAD
                        << "-byte cap: that house's bill escrow can never be claimed (UR1-3)");
}

// ===========================================================================
// testing (2026-11-10): UR-ext-12 (GPT-6.1, external s3 round 2; security: Medium). Defer/recover cycles keep an unpaid
// protest alive for ever: each recovery re-arms the cure with max(time left, 144) and each suspension gets its own
// 12-month cap, so a house that suspends, recovers, and suspends again a block later never reaches Insolvent. Michael
// signed off item 1 on 2026-11-10 (freebank docs-local/CONSENSUS_SIGNOFF_2026-11-10.md): one trouble episode lasts until
// every protest in it is paid; per episode one 7-day cure, one 24-hour floor and at most 12 months suspended in total.
// The bound under test: an unpaid demand reaches payment or Insolvent within 7 days of cure + 12 months suspended +
// 1 day of its protest, however many defer/recover cycles - here HOUSE_STRESSED_WINDOW + nSuspensionCap + 144 blocks
// (unit tests count windows in blocks).
// The house plays the attacker with real signed ops through CheckHouseOperation, one op per block: it lets each cure
// run to its last block, DEFERs there (attesting first when its last attestation is too old), then recovers with a
// zero-reserve ATTEST on the last block
// before its suspension would end. The protest is never paid. FAILS on master a00fb05 (still not Insolvent past the
// bound). If the fix adds undo priors to ATTEST or DEFER, set them in URX12Attest / URX12Defer: a refusal of either for
// priors, payload or signatures fails this test as a setup fault rather than passing it.
// ===========================================================================
namespace {
std::vector<unsigned char> URX12Sign(const CKey& key, const uint256& hash)
{
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(key.Sign(hash, vchSig));
    return vchSig;
}

CMutableTransaction URX12Attest(const CHouse& house, uint32_t nHeight, const CKey& key)
{
    HouseAttest att;
    att.nHouseID = house.nHouseID;
    att.nSchemaVersion = 1;
    att.nAsOfHeight = nHeight - 1;
    att.nPrevLastAttestHeight = house.nLastAttestHeight;
    att.nPrevStressSince = house.nStressSinceHeight;
    att.amountPrevReserves = house.amountLastAttestReserves;
    att.nPrevDeferInvokedHeight = house.nDeferInvokedHeight;
    att.nPrevDeferRenewals = house.nDeferRenewals;
    att.nPrevDeferCumBlocks = house.nDeferCumBlocks;
    att.nPrevDeferEndedHeight = house.nDeferEndedHeight;
    att.nPrevCureLeft = house.nCureLeft;
    att.nPrevEpisodeDeferBlocks = house.nEpisodeDeferBlocks;   // UR-ext-12 fix: the new undo priors
    att.nPrevEpisodeFloorUsed = house.fEpisodeFloorUsed;
    att.nPrevDeferInEpisode = house.fDeferInEpisode;
    att.amountReserves = 0;   // zero reserves: the floor is 0 when nothing is minted
    CMutableTransaction mtx = MakeAttestTx(att);
    att.vApproverIndex.push_back(0);
    att.vApproverSig.push_back(URX12Sign(key, HouseAttestSigHash(house.houseID, att.nAsOfHeight, att.amountReserves,
                                                                 HouseAttestProofSetHash(att.vProofs),
                                                                 BillHashOutputs(mtx))));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << att;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    return mtx;
}

CMutableTransaction URX12Defer(const CHouse& house, const CKey& key)
{
    HouseDefer def;
    def.nHouseID = house.nHouseID;
    def.nPrevLastActivation = house.nDeferLastActivation;
    def.nPrevEpisodeAnchor = house.nEpisodeAnchor;             // UR-ext-12 fix: the new undo priors
    def.nPrevEpisodeDeferBlocks = house.nEpisodeDeferBlocks;
    def.nPrevEpisodeFloorUsed = house.fEpisodeFloorUsed;
    def.nPrevDeferInEpisode = house.fDeferInEpisode;
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_DEFER;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("12"), house.nDeferActivations)));
    mtx.vout.push_back(CTxOut(std::max<CAmount>(house.amountLastAttestReserves, 1000), HouseEscrowScript(house.houseID)));
    mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
    def.vApproverIndex.push_back(0);
    def.vApproverSig.push_back(URX12Sign(key, HouseDeferSigHash(house.houseID, def.nPrevLastActivation,
                                                                BillHashOutputs(mtx))));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << def;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    return mtx;
}

// Runs one house op at nHeight against `house`; on accept, `house` becomes the result. Returns "" or the reason.
std::string URX12Run(CHouse& house, const CMutableTransaction& mtx, uint32_t nHeight)
{
    const CHouse h = house;
    auto fnGetHouse = [h](uint32_t id, CHouse& out) { if (id != h.nHouseID) return false; out = h; return true; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    auto fnBlock = [](uint32_t, uint256& hash) { hash = uint256S("b12"); return true; };
    CValidationState state;
    CHouse houseOut;
    if (!CheckHouseOperation(CTransaction(mtx), state, (int)nHeight, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin,
                             fnBlock, houseOut))
        return state.GetRejectReason().empty() ? std::string("(refused, no reason)") : state.GetRejectReason();
    house = houseOut;
    return std::string();
}

// The first height at or after nFrom whose effective status is not chStatus (scanning at most nMax blocks; 0 if none).
uint32_t URX12StatusEnds(const CHouse& house, uint32_t nFrom, char chStatus, uint32_t nMax)
{
    for (uint32_t h = nFrom; h < nFrom + nMax; h++)
        if (HouseEffectiveStatus(house, (int)h) != chStatus)
            return h;
    return 0;
}

bool URX12SetupFault(const std::string& strReason)
{
    return strReason.find("priors") != std::string::npos || strReason.find("payload") != std::string::npos ||
           strReason.find("approver") != std::string::npos || strReason.find("sig") != std::string::npos ||
           strReason.find("monotone") != std::string::npos || strReason.find("future") != std::string::npos ||
           strReason.find("stale") != std::string::npos || strReason.find("lock") != std::string::npos;
}
} // namespace

BOOST_AUTO_TEST_CASE(ur_ext_12_defer_recover_cycles_cannot_outrun_the_bound)
{
    CKey keyPartner;
    keyPartner.MakeNewKey(true);
    const CPubKey pubPartner = keyPartner.GetPubKey();
    CHouse house = MakeGuardHouse();
    house.vPartner[0].vchPubKey = std::vector<unsigned char>(pubPartner.begin(), pubPartner.end());
    house.nMintedUnits = 0;               // a zero-reserve ATTEST
    house.amountLastAttestReserves = 0;

    // A demand protested at P0 and never paid; the house attested at P0.
    const uint32_t P0 = 2000;
    house.nProtestOpen = 1;
    house.nProtestHeight = P0;
    house.nProtestDemandHeight = P0 - 10;
    house.nLastAttestHeight = P0;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, P0 + 1), HOUSE_STATUS_STRESSED);

    const Consensus::Params& cp = Params().GetConsensus();
    const uint32_t nSpan = HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1 + cp.nDeferSilenceWindow;
    const uint32_t nBound = P0 + HOUSE_STRESSED_WINDOW + cp.nSuspensionCap + 144;
    const uint32_t nScan = cp.nSuspensionCap + nSpan + HOUSE_STRESSED_WINDOW + 1000;

    uint32_t h = P0 + 1;          // the next height to consider
    uint32_t nLastOp = P0;        // one op per house per block
    uint32_t nInsolvent = 0;      // the first height the house is effectively Insolvent
    int nDefers = 0, nRecoveries = 0;
    uint64_t nSuspended = 0;
    std::string strStop;

    for (int nGuard = 0; nGuard < 400 && h <= nBound + 1; nGuard++) {
        const char chStatus = HouseEffectiveStatus(house, (int)h);
        if (chStatus == HOUSE_STATUS_INSOLVENT) {
            nInsolvent = h;
            break;
        }
        if (chStatus == HOUSE_STATUS_STRESSED) {
            const uint32_t nEnd = URX12StatusEnds(house, h, HOUSE_STATUS_STRESSED, nScan);
            BOOST_REQUIRE_MESSAGE(nEnd != 0, "UR-ext-12 setup: the cure never ends");
            const uint32_t nDeferAt = nEnd - 1;   // the cure's last block
            if (nDeferAt < h || nDeferAt <= nLastOp) {
                h = nEnd;                         // no block left to suspend in
                continue;
            }
            if (nDeferAt < house.nLastAttestHeight ||
                    nDeferAt - house.nLastAttestHeight > HOUSE_ATTEST_CADENCE) {
                // DEFER needs a fresh attestation: attest on the block before.
                if (nDeferAt - 1 <= nLastOp || nDeferAt - 2 <= house.nLastAttestHeight) {   // as-of must be newer
                    h = nEnd;
                    continue;
                }
                const std::string strA = URX12Run(house, URX12Attest(house, nDeferAt - 1, keyPartner), nDeferAt - 1);
                BOOST_REQUIRE_MESSAGE(strA.empty(), "UR-ext-12 setup: the stressed house's ATTEST at " +
                                      std::to_string(nDeferAt - 1) + " was refused: " + strA);
                nLastOp = nDeferAt - 1;
            }
            const std::string strD = URX12Run(house, URX12Defer(house, keyPartner), nDeferAt);
            if (!strD.empty()) {
                BOOST_REQUIRE_MESSAGE(!URX12SetupFault(strD), "UR-ext-12 setup: DEFER at " + std::to_string(nDeferAt) +
                                      " refused for a builder reason: " + strD);
                strStop = "DEFER refused at " + std::to_string(nDeferAt) + ": " + strD;
                h = nEnd;
                continue;
            }
            nDefers++;
            nLastOp = nDeferAt;
            h = nDeferAt + 1;
            continue;
        }
        if (chStatus == HOUSE_STATUS_DEFERRED) {
            const uint32_t nEnd = URX12StatusEnds(house, h, HOUSE_STATUS_DEFERRED, nScan);
            BOOST_REQUIRE_MESSAGE(nEnd != 0, "UR-ext-12 setup: the suspension never ends");
            const uint32_t nRecoverAt = nEnd - 1;   // the suspension's last block
            if (nRecoverAt < h || nRecoverAt <= nLastOp || nRecoverAt - 1 <= house.nLastAttestHeight) {
                h = nEnd;
                continue;
            }
            const uint32_t nInvoked = house.nDeferInvokedHeight;
            const std::string strA = URX12Run(house, URX12Attest(house, nRecoverAt, keyPartner), nRecoverAt);
            BOOST_REQUIRE_MESSAGE(strA.empty(), "UR-ext-12 setup: the recovery ATTEST at " +
                                  std::to_string(nRecoverAt) + " was refused: " + strA);
            nLastOp = nRecoverAt;
            if (house.nDeferInvokedHeight == 0) {
                nRecoveries++;
                nSuspended += nRecoverAt - nInvoked;
            }
            h = nRecoverAt + 1;
            continue;
        }
        strStop = std::string("unexpected status '") + chStatus + "' at " + std::to_string(h);
        break;
    }

    // The attack must at least run: one suspension and one recovery, whatever the rule.
    BOOST_CHECK_MESSAGE(nDefers >= 1 && nRecoveries >= 1, "UR-ext-12 setup: the cycle never ran (defers " +
                        std::to_string(nDefers) + ", recoveries " + std::to_string(nRecoveries) + "; " + strStop + ")");
    BOOST_CHECK_MESSAGE(nInsolvent != 0 && nInsolvent <= nBound,
                        "UR-ext-12: a demand protested at " + std::to_string(P0) + " and never paid left the house " +
                        (nInsolvent ? "Insolvent only at " + std::to_string(nInsolvent)
                                    : std::string("not Insolvent at ") + std::to_string(h)) +
                        "; the bound is " + std::to_string(nBound) + " (7 days + 12 months + 1 day). " +
                        std::to_string(nDefers) + " DEFERs, " + std::to_string(nRecoveries) + " recoveries, " +
                        std::to_string(nSuspended) + " blocks suspended in all" +
                        (strStop.empty() ? std::string() : "; last stop: " + strStop));
}

// ===========================================================================
// testing (2026-11-10): UR-ext-13 (GPT-6.1, external s3 round 2). A payload signature carries no network: one made on
// easynet (or beta, or regtest) verifies on main whenever the same keys and objects exist there. Michael signed off
// item 9 on 2026-11-10 (freebank docs-local/CONSENSUS_SIGNOFF_2026-11-10.md): "put the network's genesis hash in every
// house-op signature hash". testing found the same gap in 16 more payload digests that bind neither the network nor
// the tx's prevouts, Bill ISSUE the clearest (security: Medium, 2026-11-10); widening item 9 to them waits on Michael.
// The fix (freebankd 2026-11-10): one shared helper appends Params()'s genesis hash inside each SigHash function, so
// each digest is computed here under main, easynet, beta and regtest and all four must differ.
// FAILS on master a00fb05 (every digest is identical on all four). Case 1 is item 9 as signed off; case 2 is the
// widening - if Michael says no to it, drop case 2.
// ===========================================================================
namespace {
typedef std::vector<std::pair<std::string, std::function<uint256()>>> URX13Set;

const uint256 URX13_ID = uint256S("ab13");
const uint256 URX13_HP = uint256S("1313");
const uint256 URX13_HO = uint256S("3131");
const std::vector<unsigned char> URX13_PUB(33, 0x02);
const std::vector<unsigned char> URX13_PUB2(33, 0x03);
const std::vector<unsigned char> URX13_SCRIPT = {0x76, 0xa9, 0x14, 0x13, 0x88, 0xac};

URX13Set URX13HouseDigests()
{
    const CTransaction tx{CMutableTransaction()};
    URX13Set v;
    v.push_back({"HouseRegisterSigHash", [] { return HouseRegisterSigHash(URX13_ID, 0, 100000); }});
    v.push_back({"HouseTopupSigHash", [] { return HouseTopupSigHash(URX13_ID, 0, URX13_HP, URX13_HO); }});
    v.push_back({"HouseAdmitSigHash", [] { return HouseAdmitSigHash(URX13_ID, URX13_PUB, 100000, 500); }});
    v.push_back({"HouseExitSigHash", [] { return HouseExitSigHash(URX13_ID, 0, URX13_HP, URX13_HO); }});
    v.push_back({"HouseWinddownSigHash", [] { return HouseWinddownSigHash(URX13_ID, URX13_HP, URX13_HO); }});
    v.push_back({"HouseReclaimSigHash", [] { return HouseReclaimSigHash(URX13_ID, 0, URX13_HP, URX13_HO); }});
    v.push_back({"HouseDeferSigHash", [] { return HouseDeferSigHash(URX13_ID, 0, URX13_HO); }});
    v.push_back({"HouseRenewSigHash", [] { return HouseRenewSigHash(URX13_ID, 0, URX13_HP, URX13_HO); }});
    v.push_back({"HouseReleaseSigHash", [] { return HouseReleaseSigHash(URX13_ID, URX13_HP, URX13_HO); }});
    v.push_back({"HouseMemberSigHash",
                 [] { return HouseMemberSigHash(URX13_ID, HOUSE_OP_MEMBER_ADD, HouseMemberOp(), URX13_HP); }});
    v.push_back({"HouseRateSigHash", [tx] { return HouseRateSigHash(1, tx, HouseRate()); }});
    v.push_back({"HouseCharterSigHash", [tx] { return HouseCharterSigHash(1, tx, HouseCharter()); }});
    v.push_back({"HouseAttestSigHash", [] { return HouseAttestSigHash(URX13_ID, 100, 100000, URX13_HP, URX13_HO); }});
    return v;
}

URX13Set URX13OtherDigests()
{
    const std::vector<uint64_t> vUnits{100};
    URX13Set v;
    v.push_back({"BillIssueSigHash", [] {
        return BillIssueSigHash(URX13_ID, 10000, 546, 8000, 144, URX13_PUB, URX13_PUB2, URX13_PUB, 5); }});
    v.push_back({"BillEndorseSigHash", [] { return BillEndorseSigHash(URX13_ID, URX13_PUB, 100); }});
    v.push_back({"BillRetireSigHash", [] { return BillRetireSigHash(URX13_ID, 1000, URX13_HP, URX13_HO, false); }});
    v.push_back({"BillClaimSigHash", [] { return BillClaimSigHash(URX13_ID, URX13_HP, URX13_HO, false); }});
    v.push_back({"DepositTransferSigHash", [] { return DepositTransferSigHash(1, 100000, 500, 8000, 100, URX13_HO); }});
    v.push_back({"DepositWithdrawSigHash", [] { return DepositWithdrawSigHash(1, 100000, 8000, 100, URX13_HO); }});
    v.push_back({"DepositClaimSigHash", [] { return DepositClaimSigHash(1, 100000, URX13_HO); }});
    v.push_back({"DepositPreAuthSigHash",
                 [] { return DepositPreAuthSigHash(1, 100000, 500, 8000, 100, URX13_SCRIPT); }});
    v.push_back({"DepositProtestSigHash", [] { return DepositProtestSigHash(1, 100000, 100, 0, URX13_HO); }});
    v.push_back({"NoteTransferSigHash", [vUnits] { return NoteTransferSigHash(1, vUnits, URX13_HO); }});
    v.push_back({"NoteRedeemSigHash", [] { return NoteRedeemSigHash(1, 100, URX13_HO); }});
    v.push_back({"NoteClaimSigHash", [] { return NoteClaimSigHash(1, 100, URX13_HO); }});
    v.push_back({"NoteDemandSigHash", [vUnits] { return NoteDemandSigHash(1, vUnits, URX13_HO); }});
    v.push_back({"NotePreAuthSigHash", [vUnits] { return NotePreAuthSigHash(1, vUnits, URX13_SCRIPT, uint256()); }});
    v.push_back({"NoteProtestSigHash", [vUnits] { return NoteProtestSigHash(1, vUnits, URX13_HO); }});
    v.push_back({"TokenClaimSigHash", [] {
        return TokenClaimSigHash(1, uint256S("7713"), URX13_SCRIPT, 10, URX13_SCRIPT); }});
    return v;
}

// Case 3 (security's suggestion 2026-11-10, defence in depth): the payload digests that already bind the tx's prevouts
// (or the tx itself), so they don't replay across networks today; the shared genesis helper covers them too.
URX13Set URX13BoundDigests()
{
    const CTransaction tx{CMutableTransaction()};
    const std::vector<uint64_t> vUnits{100};
    URX13Set v;
    v.push_back({"BillDiscountSigHash", [] { return BillDiscountSigHash(BillDiscount(), URX13_ID, URX13_HP, URX13_HO); }});
    v.push_back({"BillRecourseSigHash", [] { return BillRecourseSigHash(BillRecourse(), URX13_ID, URX13_HP, URX13_HO); }});
    v.push_back({"BillHRetireNotesSigHash",
                 [] { return BillHRetireNotesSigHash(BillHRetireNotes(), URX13_ID, URX13_HP, URX13_HO); }});
    v.push_back({"BillHRetireEscrowSigHash",
                 [] { return BillHRetireEscrowSigHash(BillHRetireNotes(), URX13_ID, URX13_HP, URX13_HO); }});
    v.push_back({"DepositOriginateSigHash",
                 [] { return DepositOriginateSigHash(1, {100000}, {500}, {8000}, URX13_HP, URX13_HO); }});
    v.push_back({"NoteMintSigHash", [vUnits] { return NoteMintSigHash(1, vUnits, URX13_HP, URX13_HO); }});
    v.push_back({"NoteLockSigHash", [] { return NoteLockSigHash(1, 100, {}, URX13_HP, URX13_HO); }});
    v.push_back({"NoteUnlockSigHash", [vUnits] { return NoteUnlockSigHash(1, vUnits, URX13_HP, URX13_HO); }});
    v.push_back({"NoteSwapSigHash", [tx] { return NoteSwapSigHash(NoteSwap(), tx); }});
    v.push_back({"PoolCreateSigHash", [] { return PoolCreateSigHash(1, 30, 1000, 1000, 0, URX13_HP, URX13_HO); }});
    v.push_back({"PoolAddLiqSigHash", [] { return PoolAddLiqSigHash(PoolAddLiq(), URX13_HP, URX13_HO); }});
    v.push_back({"PoolRemoveLiqSigHash", [] { return PoolRemoveLiqSigHash(PoolRemoveLiq(), URX13_HP, URX13_HO); }});
    v.push_back({"PoolSwapSigHash", [] { return PoolSwapSigHash(PoolSwap(), URX13_HP, URX13_HO); }});
    v.push_back({"PoolRetireSigHash", [] { return PoolRetireSigHash(PoolRetire(), URX13_HP, URX13_HO); }});
    v.push_back({"SettleExchangeSigHash", [] { return SettleExchangeSigHash(SettleExchange(), URX13_HP, URX13_HO); }});
    v.push_back({"SettleNetSigHash", [] { return SettleNetSigHash(SettleNet(), URX13_HP, URX13_HO); }});
    v.push_back({"TokenKeysetSigHash", [] { return TokenKeysetSigHash(NoteTokenKeyset(), URX13_HP); }});
    v.push_back({"TokenPostSigHash", [] { return TokenPostSigHash(NoteTokenPost(), URX13_HP); }});
    v.push_back({"IssuedSigHash", [tx] { return IssuedSigHash(tx); }});
    // S1X-11: the reserve-proof challenge and the proof-set hash carry the network too.
    v.push_back({"HouseAttestChallenge", [] { return HouseAttestChallenge(URX13_ID, 100, URX13_HP, COutPoint(URX13_HO, 1)); }});
    v.push_back({"HouseAttestProofSetHash", [] { return HouseAttestProofSetHash({}); }});
    return v;
}

const std::vector<std::string>& URX13Networks()
{
    static const std::vector<std::string> v = {CBaseChainParams::MAIN, CBaseChainParams::EASYNET,
                                               CBaseChainParams::BETA, CBaseChainParams::REGTEST};
    return v;
}

void URX13Check(const URX13Set& vSet, const std::string& strWhich)
{
    const std::string strWas = Params().NetworkIDString();
    const std::vector<std::string>& vNet = URX13Networks();
    std::vector<uint256> vGenesis;
    std::vector<std::vector<uint256>> vDigest;   // [network][digest]
    for (const std::string& strNet : vNet) {
        SelectParams(strNet);
        vGenesis.push_back(Params().GetConsensus().hashGenesisBlock);
        std::vector<uint256> d;
        for (const auto& e : vSet)
            d.push_back(e.second());
        vDigest.push_back(d);
    }
    SelectParams(strWas);

    // The fix can only work if the four genesis hashes differ (chainparams.cpp asserts each one).
    for (size_t a = 0; a < vNet.size(); a++)
        for (size_t b = a + 1; b < vNet.size(); b++)
            BOOST_REQUIRE_MESSAGE(vGenesis[a] != vGenesis[b], "UR-ext-13 setup: " + vNet[a] + " and " + vNet[b] +
                                  " share a genesis hash, so a genesis tag can't tell them apart");

    for (size_t i = 0; i < vSet.size(); i++) {
        std::string strSame;
        for (size_t a = 0; a < vNet.size(); a++)
            for (size_t b = a + 1; b < vNet.size(); b++)
                if (vDigest[a][i] == vDigest[b][i])
                    strSame += " " + vNet[a] + "=" + vNet[b];
        BOOST_CHECK_MESSAGE(strSame.empty(), "UR-ext-13 (" + strWhich + "): " + vSet[i].first +
                            " is the same digest on" + strSame + " - a signature made on one verifies on the other");
    }
}
} // namespace

BOOST_AUTO_TEST_CASE(ur_ext_13_house_sighashes_bind_the_network)
{
    URX13Check(URX13HouseDigests(), "a house op, item 9 as signed off");
}

BOOST_AUTO_TEST_CASE(ur_ext_13_other_payload_sighashes_bind_the_network)
{
    URX13Check(URX13OtherDigests(), "the widening, Michael's yes 2026-11-11");
}

BOOST_AUTO_TEST_CASE(ur_ext_13_prevout_bound_sighashes_bind_the_network)
{
    URX13Check(URX13BoundDigests(), "prevout-bound, defence in depth, with the widening");
}

// ===========================================================================
// testing (2026-11-11): UR-ext-10 (GPT-6.1, external s3 round 2; security: Medium). DisconnectBlock wrote each HouseDB
// record as it went and stepped the marker back afterwards, so a crash in between restarted with the marker still on
// the block and re-ran the undo over half-undone records (EscrowChangeBeforeOp re-appends prevouts, counters invert
// twice; RemoveHouse of a gone house fails the disconnect for good). freebankd's fix stages the undo
// (StagedDBWrapper) and commits it with the marker in one batch. Modelled on billdb_block_effects_atomic_undo, over an
// in-memory HouseDB: block B2 changes house 1, registers house 2, adds a member and token records; its undo is then
//   - staged and ABORTED (the crash before the commit): every record and the marker byte-identical to after B2;
//   - staged and COMMITTED: byte-identical to after B1, as one clean undo;
//   - committed again on an empty stage: still the same (a repeat is a no-op).
// Inside a stage, reads see the staged writes (two undo steps on one house in one block), and a write then an erase of
// one key leaves it absent. Needs the staged API, so it builds only with the fix.
// ===========================================================================
namespace {
template <typename T>
std::string URX10Bytes(bool fHave, const T& rec)
{
    if (!fHave)
        return "-";
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << rec;
    return HexStr(ss.begin(), ss.end());
}

const uint160 URX10_KEY = uint160(std::vector<unsigned char>(20, 0x10));
const std::vector<unsigned char> URX10_B(33, 0x02);
const uint256 URX10_Y = uint256S("10e7");

// Every record B2 or its undo touches, serialized; "-" for an absent one.
std::string URX10Snapshot(HouseDB& db, const CHouse& h1, const CHouse& h2)
{
    std::string s;
    for (const CHouse* p : {&h1, &h2}) {
        CHouse h;
        uint32_t nID = 0;
        s += URX10Bytes(db.GetHouse(p->nHouseID, h), h) + "|";
        s += URX10Bytes(db.GetHouseIDByHash(p->houseID, nID), nID) + "|";
        s += URX10Bytes(db.GetHouseIDByClassID(p->strClassID, nID), nID) + "|";
    }
    CHouseMember m;
    s += URX10Bytes(db.GetHouseMember(h1.nHouseID, URX10_KEY, m), m) + "|";
    s += std::to_string(db.GetHouseMemberCount(h1.nHouseID)) + "|";
    CTokenMark mark;
    s += URX10Bytes(db.GetTokenIssued(h1.nHouseID, URX10_B, mark), mark) + "|";
    s += URX10Bytes(db.GetTokenSpent(h1.nHouseID, URX10_Y, mark), mark) + "|";
    CTokenClaim claim;
    s += URX10Bytes(db.GetTokenClaim(h1.nHouseID, URX10_Y, claim), claim) + "|";
    uint32_t nLast = 0;
    s += URX10Bytes(db.GetLastHouseID(nLast), nLast) + "|";
    uint256 hashBest;
    s += URX10Bytes(db.GetBestBlock(hashBest), hashBest);
    return s;
}
} // namespace

BOOST_AUTO_TEST_CASE(testing_ur_ext_10_house_undo_is_staged_and_atomic)
{
    LOCK(cs_main);   // a stage is opened only under cs_main (UR-ext-10 hardening)
    HouseDB db(1 << 20, true, true);   // in-memory
    const uint256 hashB1 = uint256S("b1"), hashB2 = uint256S("b2");

    CHouse h1 = MakeGuardHouse();      // house 7
    h1.nHouseID = 1;
    h1.houseID = uint256S("10a1");
    h1.strClassID = "urx10-a";
    CHouse h2 = h1;
    h2.nHouseID = 2;
    h2.houseID = uint256S("10a2");
    h2.strClassID = "urx10-b";

    // B1: house 1 alone.
    const uint32_t nLast1 = 1;
    BOOST_REQUIRE(db.WriteBlockEffects({h1}, &nLast1, hashB1));
    const std::string strAfterB1 = URX10Snapshot(db, h1, h2);

    // B2: house 1 changes (twice in the block: an ATTEST, then a TOPUP's escrow change), house 2 registers, a member
    // and the token records land.
    CHouse h1a = h1;
    h1a.nLastAttestHeight = 1500;
    CHouse h1b = h1a;
    h1b.vOutEscrowChange.push_back(COutPoint(uint256S("ec"), 1));
    HouseMemberEffects mem;
    HouseMemberPrior added;
    added.fPresent = 1;
    added.rec = CHouseMember(1500, 0);
    mem.mapRecord[std::make_pair(h1.nHouseID, URX10_KEY)] = added;
    mem.mapCount[h1.nHouseID] = 1;
    TokenEffects tok;
    CTokenMark mark;
    mark.nHeight = 1500;
    mark.txid = uint256S("70");
    tok.mapIssued[std::make_pair(h1.nHouseID, URX10_B)] = mark;
    tok.mapSpent[std::make_pair(h1.nHouseID, URX10_Y)] = mark;
    CTokenClaim claim;
    claim.nAmount = 5;
    claim.nHeight = 1500;
    tok.mapClaim[std::make_pair(h1.nHouseID, URX10_Y)] = claim;
    const uint32_t nLast2 = 2;
    BOOST_REQUIRE(db.WriteBlockEffects({h1b, h2}, &nLast2, hashB2, &mem, &tok));
    const std::string strAfterB2 = URX10Snapshot(db, h1, h2);
    BOOST_REQUIRE(strAfterB2 != strAfterB1);

    // B2's undo, the way DisconnectBlock walks it (later op first): every write lands in the open stage.
    auto fnUndoB2 = [&]() {
        BOOST_REQUIRE(db.WriteHouse(h1a));                       // the TOPUP's escrow change undone
        CHouse got;
        BOOST_REQUIRE(db.GetHouse(h1.nHouseID, got));            // the next step reads the staged record
        BOOST_CHECK_MESSAGE(got.vOutEscrowChange.empty() && got.nLastAttestHeight == 1500,
                            "UR-ext-10: a read inside the stage didn't see the stage's own write");
        BOOST_REQUIRE(db.WriteHouse(h1));                        // then the ATTEST undone
        BOOST_REQUIRE(db.RemoveHouse(h2.nHouseID));              // the REGISTER undone
        BOOST_REQUIRE(db.WriteLastHouseID(nLast1));
        HouseMemberPrior absent;
        BOOST_REQUIRE(db.WriteHouseMember(h1.nHouseID, URX10_KEY, absent));
        BOOST_REQUIRE(db.WriteHouseMemberCount(h1.nHouseID, 0));
        BOOST_REQUIRE(db.EraseTokenMarks(h1.nHouseID, {URX10_B}, {URX10_Y}));
        BOOST_REQUIRE(db.EraseTokenClaim(h1.nHouseID, URX10_Y));
    };

    // The crash before the commit: nothing reached the DB, the marker is still on B2.
    db.BeginStage();
    fnUndoB2();
    const auto fnNoMarker = [](const std::string& x) { return x.substr(0, x.rfind('|')); };   // the marker isn't staged
    BOOST_CHECK_MESSAGE(fnNoMarker(URX10Snapshot(db, h1, h2)) == fnNoMarker(strAfterB1),
                        "UR-ext-10: inside the stage the undo doesn't read as done");
    db.AbortStage();
    BOOST_CHECK_MESSAGE(URX10Snapshot(db, h1, h2) == strAfterB2,
                        "UR-ext-10: an aborted (crashed) undo stage changed HouseDB - a replay would undo twice");

    // The replayed undo, this time committed with the marker: exactly one clean undo.
    db.BeginStage();
    fnUndoB2();
    BOOST_REQUIRE(db.CommitUndoStage(hashB1, true));
    BOOST_CHECK_MESSAGE(URX10Snapshot(db, h1, h2) == strAfterB1,
                        "UR-ext-10: the committed undo is not byte-identical to the state before B2");
    BOOST_CHECK(!db.Staged());

    // A repeat of the commit (an empty stage) is a no-op with the same marker.
    db.BeginStage();
    BOOST_REQUIRE(db.CommitUndoStage(hashB1, true));
    BOOST_CHECK_MESSAGE(URX10Snapshot(db, h1, h2) == strAfterB1, "UR-ext-10: an empty repeated commit changed HouseDB");

    // A write then an erase of one key inside a stage leaves it absent, staged and committed.
    const uint256 y2 = uint256S("10e8");
    db.BeginStage();
    BOOST_REQUIRE(db.WriteTokenClaim(h1.nHouseID, y2, claim));
    BOOST_REQUIRE(db.EraseTokenClaim(h1.nHouseID, y2));
    CTokenClaim gone;
    BOOST_CHECK(!db.GetTokenClaim(h1.nHouseID, y2, gone));
    BOOST_REQUIRE(db.CommitUndoStage(hashB1, true));
    BOOST_CHECK(!db.GetTokenClaim(h1.nHouseID, y2, gone));
    BOOST_CHECK_MESSAGE(URX10Snapshot(db, h1, h2) == strAfterB1, "UR-ext-10: the write-then-erase stage left a trace");
}

// UR-ext-12 precision 2 (design 2026-11-10, security's conditions 4-5): an episode ends when its last protest is paid
// with the house not suspended, or at the recovery that ends the suspension it was paid in, whichever comes last. The
// 180-day spacing counts from that end; 0 = no earlier episode, so no spacing check (not "height 0").
BOOST_AUTO_TEST_CASE(ur_ext_12_precision2_spacing_from_the_end)
{
    CHouse house = MakeGuardHouse();
    BOOST_CHECK_EQUAL(house.nEpisodeEndHeight, 0u);

    // Condition 4: no earlier episode, no check - even a protest at block 1, or after old protests and recoveries whose
    // heights are leftovers (they are not ends).
    {
        CHouse h = house;
        HouseProtestEpisodeStart(h, 1);
        BOOST_CHECK_EQUAL(h.nNoCureHeight, 0u);
        CHouse h2 = house;
        h2.nProtestHeight = 500;
        h2.nDeferEndedHeight = 600;
        HouseProtestEpisodeStart(h2, 700);
        BOOST_CHECK_EQUAL(h2.nNoCureHeight, 0u);
    }

    // A discharge that leaves a protest open does not end the episode.
    {
        CHouse h = house;
        h.nProtestOpen = 1;
        HouseDischargeMaybeEndsEpisode(h, 900);
        BOOST_CHECK_EQUAL(h.nEpisodeEndHeight, 0u);
    }
    // The last one, with the house not suspended, does.
    {
        CHouse h = house;
        h.nProtestOpen = 0;
        HouseDischargeMaybeEndsEpisode(h, 900);
        BOOST_CHECK_EQUAL(h.nEpisodeEndHeight, 900u);
        // A later episode's end replaces it.
        HouseDischargeMaybeEndsEpisode(h, 40000);
        BOOST_CHECK_EQUAL(h.nEpisodeEndHeight, 40000u);
    }
    // Paid while suspended: the episode is not over (queued demands can't protest a suspended house). The recovery
    // ATTEST ends it (validation.cpp; covered by the gate).
    {
        CHouse h = house;
        h.nProtestOpen = 0;
        h.nDeferInvokedHeight = 850;
        HouseDischargeMaybeEndsEpisode(h, 900);
        BOOST_CHECK_EQUAL(h.nEpisodeEndHeight, 0u);
    }

    // The end, not the start: an episode that started at 1000 and ended at 2000 gives no cure to a protest 180 days
    // after the start, and one to a protest 180 days after the end.
    {
        CHouse h = house;
        h.nProtestHeight = 1000;
        h.nEpisodeEndHeight = 2000;
        CHouse a = h;
        HouseProtestEpisodeStart(a, 1000 + HOUSE_CURE_SPACING_BLOCKS);
        BOOST_CHECK_EQUAL(a.nNoCureHeight, 1000u + HOUSE_CURE_SPACING_BLOCKS);
        CHouse b = h;
        HouseProtestEpisodeStart(b, 2000 + HOUSE_CURE_SPACING_BLOCKS - 1);
        BOOST_CHECK_EQUAL(b.nNoCureHeight, 2000u + HOUSE_CURE_SPACING_BLOCKS - 1);
        CHouse c = h;
        HouseProtestEpisodeStart(c, 2000 + HOUSE_CURE_SPACING_BLOCKS);
        BOOST_CHECK_EQUAL(c.nNoCureHeight, 0u);
    }

    // The field round-trips, last in the v15 tail.
    {
        CHouse h = house;
        h.nEpisodeEndHeight = 0x01020304;
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << h;
        BOOST_REQUIRE(ss.size() >= 4);
        BOOST_CHECK_EQUAL((uint8_t)ss[ss.size() - 4], 0x04);   // little-endian, the record's last four bytes
        BOOST_CHECK_EQUAL((uint8_t)ss[ss.size() - 1], 0x01);
        CHouse back;
        ss >> back;
        BOOST_CHECK_EQUAL(back.nEpisodeEndHeight, 0x01020304u);
    }
}

// UR-ext-12 precision 2, option B (security's conditions 1-3): HouseDB keeps one episode-end record per connected block
// (block hash -> [(house id, pre-block nEpisodeEndHeight)]), written in the block's own batch even when empty, and the
// staged undo reads and erases it. An aborted stage leaves it; a committed one removes it with the marker step-back.
BOOST_AUTO_TEST_CASE(ur_ext_12_episode_end_undo_record)
{
    LOCK(cs_main);   // a stage is opened only under cs_main (UR-ext-10 hardening)
    HouseDB db(1 << 20, true, true);   // in-memory
    CHouse h1 = MakeGuardHouse();
    h1.nHouseID = 1;
    const uint32_t nLast1 = 1;
    const uint256 hashB1 = uint256S("e1"), hashB2 = uint256S("e2");
    const std::vector<std::pair<uint32_t, uint32_t>> vNone;
    BOOST_REQUIRE(db.WriteBlockEffects({h1}, &nLast1, hashB1, nullptr, nullptr, &vNone));
    // B2 ends house 1's episode at 900 (it was 0 before).
    CHouse h1b = h1;
    h1b.nEpisodeEndHeight = 900;
    const std::vector<std::pair<uint32_t, uint32_t>> vB2{{1u, 0u}};
    BOOST_REQUIRE(db.WriteBlockEffects({h1b}, nullptr, hashB2, nullptr, nullptr, &vB2));

    // An empty record is still a record: the undo can tell "no change" from "lost".
    std::vector<std::pair<uint32_t, uint32_t>> v;
    BOOST_CHECK(db.GetEpisodeEndUndo(hashB1, v));
    BOOST_CHECK(v.empty());
    BOOST_REQUIRE(db.GetEpisodeEndUndo(hashB2, v));
    BOOST_REQUIRE_EQUAL(v.size(), 1u);
    BOOST_CHECK_EQUAL(v[0].first, 1u);
    BOOST_CHECK_EQUAL(v[0].second, 0u);
    BOOST_CHECK(!db.GetEpisodeEndUndo(uint256S("e3"), v));   // never connected: absent

    // The undo as DisconnectBlock runs it, aborted (a crash before the commit): record and house untouched.
    db.BeginStage();
    {
        CHouse h;
        BOOST_REQUIRE(db.GetHouse(1, h));
        h.nEpisodeEndHeight = v[0].second;
        BOOST_REQUIRE(db.WriteHouse(h));
        BOOST_REQUIRE(db.EraseEpisodeEndUndo(hashB2));
        BOOST_CHECK(!db.GetEpisodeEndUndo(hashB2, v));   // the stage sees its own erase
    }
    db.AbortStage();
    BOOST_CHECK(db.GetEpisodeEndUndo(hashB2, v));
    {
        CHouse h;
        BOOST_REQUIRE(db.GetHouse(1, h));
        BOOST_CHECK_EQUAL(h.nEpisodeEndHeight, 900u);
    }

    // Committed: house 1 back to its pre-B2 bytes, the record gone, the marker at B1.
    db.BeginStage();
    {
        CHouse h;
        BOOST_REQUIRE(db.GetHouse(1, h));
        h.nEpisodeEndHeight = 0;
        BOOST_REQUIRE(db.WriteHouse(h));
        BOOST_REQUIRE(db.EraseEpisodeEndUndo(hashB2));
    }
    BOOST_REQUIRE(db.CommitUndoStage(hashB1, true));
    BOOST_CHECK(!db.GetEpisodeEndUndo(hashB2, v));
    BOOST_CHECK(db.GetEpisodeEndUndo(hashB1, v));
    CHouse back;
    BOOST_REQUIRE(db.GetHouse(1, back));
    CDataStream a(SER_DISK, CLIENT_VERSION), b(SER_DISK, CLIENT_VERSION);
    a << back;
    b << h1;
    BOOST_CHECK(a.str() == b.str());
    uint256 hashBest;
    BOOST_CHECK(db.GetBestBlock(hashBest) && hashBest == hashB1);
}

// MM-1 switch-on (security 11-11): the public networks require standard transactions, whichever one a build runs (one
// public network per build, so a gate on a build sees only its own: this covers all four). Regtest stays non-strict for
// the gates (FB_STD=1 runs them strict); beta is dead for our stack and keeps BitAssets' setting.
BOOST_AUTO_TEST_CASE(mm1_public_networks_require_standard)
{
    BOOST_CHECK(CreateChainParams(CBaseChainParams::MAIN)->RequireStandard());
    BOOST_CHECK(CreateChainParams(CBaseChainParams::EASYNET)->RequireStandard());
    BOOST_CHECK(!CreateChainParams(CBaseChainParams::REGTEST)->RequireStandard());
    BOOST_CHECK(!CreateChainParams(CBaseChainParams::BETA)->RequireStandard());
}

// MM-1 (security 11-11): a FreeBank family-script output is standard only where consensus tags it. The escrow script is
// <house id> OP_DROP OP_TRUE: untagged, it is an anyone-can-spend coin the payer may take for escrow (SA-N4's trap).
BOOST_AUTO_TEST_CASE(mm1_untagged_family_output_is_nonstandard)
{
    const uint256 houseID = uint256S("aa11");
    const CScript scriptEscrow = HouseEscrowScript(houseID);
    const CScript scriptPlain = GetScriptForDestination(CKeyID(uint160(std::vector<unsigned char>(20, 0x11))));
    std::string reason;

    // TOPUP posts its escrow at vout[0], which consensus tags: standard.
    CMutableTransaction topup;
    topup.nVersion = TRANSACTION_HOUSE_VERSION;
    topup.nHouseOp = HOUSE_OP_TOPUP;
    topup.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
    topup.vout.push_back(CTxOut(COIN, scriptEscrow));
    topup.vout.push_back(CTxOut(COIN, scriptPlain));
    BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(topup), reason, true), "TOPUP refused: " + reason);
    BOOST_CHECK_MESSAGE(AreFreeBankOutputsStandard(CTransaction(topup), reason), "a tagged TOPUP escrow was refused: " + reason);

    // The same script at a position consensus doesn't tag: refused (after the inputs are known, MM1-R1).
    CMutableTransaction stray = topup;
    std::swap(stray.vout[0], stray.vout[1]);
    BOOST_CHECK(!AreFreeBankOutputsStandard(CTransaction(stray), reason));
    BOOST_CHECK_EQUAL(reason, "freebank-untagged-family-output");

    // In a plain tx: refused.
    CMutableTransaction plain;
    plain.nVersion = 2;
    plain.vin.push_back(CTxIn(COutPoint(uint256S("02"), 0)));
    plain.vout.push_back(CTxOut(COIN, scriptEscrow));
    BOOST_CHECK(!AreFreeBankOutputsStandard(CTransaction(plain), reason));
    BOOST_CHECK_EQUAL(reason, "freebank-untagged-family-output");

    // MM1-R2: a family script must carry its OWN family's tag - B3 custody (a note script) or a token pool script where
    // consensus tags house escrow is refused.
    CMutableTransaction wrong = topup;
    wrong.vout[0].scriptPubKey = NotePreAuthScript(std::vector<unsigned char>(33, 0x02));
    BOOST_CHECK(!AreFreeBankOutputsStandard(CTransaction(wrong), reason));
    BOOST_CHECK_EQUAL(reason, "freebank-untagged-family-output");
    wrong.vout[0].scriptPubKey = TokenPoolScript(uint256S("bb22"));
    BOOST_CHECK(!AreFreeBankOutputsStandard(CTransaction(wrong), reason));
    BOOST_CHECK_EQUAL(reason, "freebank-untagged-family-output");
    // House, bill and pool escrow are one shape, told apart by tag only: a pool-escrow script where consensus tags
    // house escrow is that shape with an escrow tag, so standard (consensus governs which escrow it is).
    wrong.vout[0].scriptPubKey = PoolEscrowScript(7);
    BOOST_CHECK_MESSAGE(AreFreeBankOutputsStandard(CTransaction(wrong), reason), "escrow shape with an escrow tag: " + reason);

    // Data outputs: one, or two only when one is a withdrawal's sidechain object (multi-op-return otherwise).
    CMutableTransaction data = plain;
    data.vout.clear();
    data.vout.push_back(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>(10, 0x01)));
    data.vout.push_back(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>(10, 0x02)));
    data.vout.push_back(CTxOut(COIN, scriptPlain));
    BOOST_CHECK(!IsStandardTx(CTransaction(data), reason, true));
    BOOST_CHECK_EQUAL(reason, "multi-op-return");
}

// MM1-R1 (security 11-11): the worst case of the tag step - a bill op with a large payload and thousands of outputs.
// It runs only after the inputs exist (ATMP), so this measures what a tx with real inputs can cost; logged, not asserted.
BOOST_AUTO_TEST_CASE(mm1_tag_step_worst_case_time)
{
    // IsStandardTx refuses a FreeBank tx with more than MAX_STANDARD_FREEBANK_OUTPUTS outputs before the tag step runs.
    const CScript scriptPlain = GetScriptForDestination(CKeyID(uint160(std::vector<unsigned char>(20, 0x12))));
    {
        CMutableTransaction m;
        m.nVersion = TRANSACTION_NOTE_VERSION;
        m.nNoteOp = NOTE_OP_TRANSFER;
        m.vin.push_back(CTxIn(COutPoint(uint256S("04"), 0)));
        for (unsigned int i = 0; i <= MAX_STANDARD_FREEBANK_OUTPUTS; i++)
            m.vout.push_back(CTxOut(1000, scriptPlain));
        std::string reason;
        BOOST_CHECK(!IsStandardTx(CTransaction(m), reason, true));
        BOOST_CHECK_EQUAL(reason, "freebank-too-many-outputs");
        m.vout.pop_back();
        BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(m), reason, true), "at the cap: " + reason);
    }

    // The worst a standard tx can cost: a bill DISCOUNT at the output cap whose payload decodes in full each time (100
    // units, 64 reserve proofs, 64 approver sigs), then the same at 9,000 outputs (over both caps) to show the growth.
    BillDiscount d;
    d.nBillID = 1; d.nHouseID = 1; d.amountPrice = 100; d.amountFace = 100; d.nNoteOutputs = 100;
    d.vUnits.assign(100, 1);
    d.vchCustodyPubKey.assign(33, 0x02);
    for (int i = 0; i < (int)MAX_ATTEST_PROOFS; i++) {
        AttestProof pr;
        pr.outpoint = COutPoint(uint256S("05"), i);
        pr.vchPubKey.assign(33, 0x02);
        pr.vchSig.assign(72, 0x30);
        d.vReserveProofs.push_back(pr);
        d.vApproverIndex.push_back(i);
        d.vApproverSig.push_back(std::vector<unsigned char>(72, 0x30));
    }
    d.vchSellerSig.assign(72, 0x30);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << d;
    for (const unsigned int nOut : {MAX_STANDARD_FREEBANK_OUTPUTS, 9000u}) {
        CMutableTransaction m;
        m.nVersion = TRANSACTION_BILL_VERSION;
        m.nBillOp = BILL_OP_DISCOUNT;
        m.vchBillPayload.assign(ss.begin(), ss.end());
        m.vin.push_back(CTxIn(COutPoint(uint256S("03"), 0)));
        for (unsigned int i = 0; i < nOut; i++)
            m.vout.push_back(CTxOut(1000, scriptPlain));
        const CTransaction tx(m);
        std::string reason;
        const int64_t t0 = GetTimeMicros();
        AreFreeBankOutputsStandard(tx, reason);
        const int64_t dt = GetTimeMicros() - t0;
        BOOST_TEST_MESSAGE("MM1-R1: the tag step on " << tx.vout.size() << " outputs and a " << ss.size()
                           << "-byte DISCOUNT payload (" << GetTransactionWeight(tx) / 4 << " vbytes) took " << dt << " us");
        BOOST_CHECK(dt >= 0);
    }
}


// ===========================================================================
// testing (2026-11-20): S2X-6 (Gemini 4 on s2 at v1.2.2; security: Medium; D-2026-11-20-2 rule 1, "A house can't wind
// down while it owes a swap shortfall claim (one paid in the last 90 days)"). WINDDOWN checks GetHouseLiabilities
// (minted + deposits + pending swaps), which leaves out the failed-swap shortfalls the house paid below its bid. A solo
// house's pledge unlocks at the WINDDOWN height (no tail), so a house can pay a swap short, wind down, and take its
// pledge before the holder's claim (which the waterfall pays only from a FAILED house) can reach it. The residual
// settle already waits for live shortfalls (bad-house-settle-swaps-outstanding).
// For a multi-partner house and a solo house, each with a valid partner signature: (1) control, no shortfall: WINDDOWN
// accepted; (2) a 2,000 mg shortfall paid the block before: WINDDOWN refused; (3) the same shortfall paid just past the
// 90-day lapse: WINDDOWN accepted (the rule bites only while the claim lives). (2) FAILS on master 457a538.
// ===========================================================================
BOOST_AUTO_TEST_CASE(s2x_6_winddown_refused_while_a_swap_shortfall_is_live)
{
    const int H = 20000;
    const int64_t nLapse = (int64_t)Params().GetConsensus().GramAt(H).nShortfallLapseSecs / 600;   // as the settle reads it
    BOOST_REQUIRE(nLapse > 0 && ClockAtHeight(H) - nLapse - 1 > 0);
    struct Case { const char* name; int64_t nPaidClock; bool fRefuse; };
    const Case cases[] = {{"control, no shortfall", -1, false},
                          {"a shortfall paid the block before", ClockAtHeight(H - 1), true},
                          {"a shortfall paid just past the 90-day lapse", ClockAtHeight(H) - nLapse - 1, false}};
    for (const uint8_t nTier : {(uint8_t)HOUSE_TIER_MULTI_PARTNER, (uint8_t)HOUSE_TIER_BONDED_SOLO}) {
        const std::string strTier = nTier == HOUSE_TIER_MULTI_PARTNER ? "multi-partner" : "solo";
        for (const Case& c : cases) {
            CKey keyPartner; keyPartner.MakeNewKey(true);
            const CPubKey pubPartner = keyPartner.GetPubKey();
            CHouse house = MakeGuardHouse();
            house.nTier = nTier;
            if (nTier != HOUSE_TIER_MULTI_PARTNER)
                house.vPartner.resize(1);                                    // one issuer
            house.vPartner[0].vchPubKey = std::vector<unsigned char>(pubPartner.begin(), pubPartner.end());
            house.nLastAttestHeight = H;                                     // fresh: effectively Open at H
            BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
            BOOST_REQUIRE_EQUAL(house.nMintedUnits, 0u);
            BOOST_REQUIRE_EQUAL(house.nDepositUnits, 0u);

            CUnitsView units(nullptr);
            if (c.nPaidClock >= 0) {
                CShortfallLedger led;
                led.vEntry.push_back(std::make_pair(c.nPaidClock, (uint64_t)2000));
                units.Put(ShortfallLedgerKey(house.nHouseID), led);
            }
            UnitsCheckScope scope(&units);
            BOOST_REQUIRE_EQUAL(HousePendingSwapUnitsForChecks(house.nHouseID), 0u);
            const bool fLive = HouseLiveShortfallMgForChecks(house.nHouseID, ClockAtHeight(H), nLapse) != 0;
            BOOST_REQUIRE_EQUAL(fLive, c.fRefuse);                          // the case is what it says

            HouseWinddown wd;
            wd.nHouseID = house.nHouseID;
            CMutableTransaction mtx;
            mtx.nVersion = TRANSACTION_HOUSE_VERSION;
            mtx.nHouseOp = HOUSE_OP_WINDDOWN;
            mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
            mtx.vout.push_back(CTxOut(1 * COIN, GetScriptForDestination(CKeyID())));
            wd.vApproverIndex.push_back(0);
            std::vector<unsigned char> vchSig;
            BOOST_REQUIRE(keyPartner.Sign(HouseWinddownSigHash(house.houseID, BillHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx)), vchSig));
            wd.vApproverSig.push_back(vchSig);
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << wd;
            mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());

            auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
            auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
            CValidationState state; CHouse houseOut;
            const bool fOk = CheckHouseOperation(CTransaction(mtx), state, H, fnGetHouse, GuardNoHash, GuardNoClass,
                                                 fnNoCoin, GuardNoBlock, houseOut);
            if (c.fRefuse) {
                BOOST_CHECK_MESSAGE(!fOk, "S2X-6 (" + strTier + ", " + c.name + "): WINDDOWN was accepted while the house "
                                          "owes a live swap shortfall claim (status after: " +
                                          std::to_string((int)houseOut.status) + ")");
                if (!fOk)
                    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-winddown-shortfall");
            } else {
                BOOST_CHECK_MESSAGE(fOk, "S2X-6 control (" + strTier + ", " + c.name + "): WINDDOWN was refused: " +
                                         state.GetRejectReason());
                if (fOk)
                    BOOST_CHECK_EQUAL(houseOut.status, HOUSE_STATUS_WOUNDDOWN);
            }
        }
    }
}

// S1X-6, RECLAIM (security 11-23: Medium; the MINT cases are in note_tests). A tail partner may take
// its pledge only while the house's capital still covers notes and deposits (bad-house-reclaim-cap, CapitalCapUnits).
// A live swap shortfall is still owed at failure (MaterializeInsolvency counts it), so it must use the room as pending
// swaps do. Capital capacity set to 100,000 mg (the test hook), 90,000 minted: (a) control, nothing owed: the cap passes
// (the placeholder signature fails after it); (b) 10,001 pending in swaps: refused at the cap (the rule as built);
// (c) a live 20,000 mg shortfall paid the block before: refused at the cap; (d) the same paid just past the 90-day
// lapse: the cap passes. (c) FAILS on master 4686200.
BOOST_AUTO_TEST_CASE(s1x_6_reclaim_counts_a_live_shortfall_against_the_capital)
{
    const int H = 20000;
    const int64_t nLapse = (int64_t)Params().GetConsensus().GramAt(H).nShortfallLapseSecs / 600;
    BOOST_REQUIRE(nLapse > 0 && ClockAtHeight(H) - nLapse - 1 > 0);
    struct Case { const char* name; uint64_t nPending; int64_t nPaidClock; bool fRefuse; };
    const Case cases[] = {{"control, nothing owed", 0, -1, false},
                          {"10,001 pending in swaps (reference)", 10001, -1, true},
                          {"a live shortfall paid the block before", 0, ClockAtHeight(H - 1), true},
                          {"the shortfall paid just past the lapse", 0, ClockAtHeight(H) - nLapse - 1, false}};
    const auto fnPrev = g_fnCapitalForChecksTestOverride;
    g_fnCapitalForChecksTestOverride = [](const CHouse&, int, CHouseCapital& cap) {
        cap.nEscrowMg = cap.nCapacityMg = 100000;
        cap.nTillMg = 100 * 100000;
    };
    for (const Case& c : cases) {
        CHouse house = MakeGuardHouse();
        house.nLastAttestHeight = H;                                     // fresh: effectively Open at H
        house.nMintedUnits = 90000;
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_OPEN);
        CUnitsView units(nullptr);
        if (c.nPending)
            units.Put(SwapPendingKey(house.nHouseID), c.nPending);
        if (c.nPaidClock >= 0) {
            CShortfallLedger led;
            led.vEntry.push_back(std::make_pair(c.nPaidClock, (uint64_t)20000));
            units.Put(ShortfallLedgerKey(house.nHouseID), led);
        }
        UnitsCheckScope scope(&units);

        auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
        auto fnGetCoin = [&](const COutPoint& o, Coin& coin) {
            if (o == COutPoint(uint256S("a1"), 0)) { coin = GuardEscrowCoin(house.nHouseID, HOUSE_MIN_PLEDGE); return true; }
            return false;
        };
        CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, COutPoint(uint256S("a1"), 0));
        CValidationState state; CHouse houseOut;
        CheckHouseOperation(CTransaction(mtx), state, H, fnGetHouse, GuardNoHash, GuardNoClass, fnGetCoin, GuardNoBlock,
                            houseOut);
        const std::string strReason = state.GetRejectReason();
        if (c.fRefuse)
            BOOST_CHECK_MESSAGE(strReason == "bad-house-reclaim-cap", std::string("S1X-6 RECLAIM (") + c.name + "): the "
                                "tail partner's pledge left a house whose capital covers 90,000 minted only if what it "
                                "still owes is ignored (went on to: " + (strReason.empty() ? std::string("accepted") : strReason) + ")");
        else
            BOOST_CHECK_MESSAGE(strReason == "bad-house-reclaim-sig", std::string("S1X-6 RECLAIM control (") + c.name +
                                "): want the placeholder-signature refusal after the cap, got " + strReason);
    }
    g_fnCapitalForChecksTestOverride = fnPrev;
}

// UF4-1, case 5 (security 11-23). A suspended house stays alive only by attesting: it turns
// Insolvent, by height alone, when its silence clock runs out (CheckSilenceClock above). Its ATTEST sent in the last
// block before that height is valid at the house's own tip, and every peer already one block on refuses it as
// bad-house-attest-closed. At ban score 100 each of those peers bans the house's node, at the moment its attestation
// matters most. On the mempool path the refusal must score 0, as attest-future/-stale/-monotone/-priors already do.
BOOST_AUTO_TEST_CASE(uf4_1_deferred_house_attest_at_its_silence_deadline_bans_no_peer)
{
    CHouse house;
    house.nHouseID = 1;
    house.houseID = uint256S("f00d");
    house.nTier = HOUSE_TIER_MULTI_PARTNER;
    house.nThresholdM = 1;
    house.status = HOUSE_STATUS_OPEN;
    house.nRegisteredHeight = 1000;
    house.nStressSinceHeight = 1100;
    house.nDeferInvokedHeight = 1200;
    house.nDeferActivations = 1;
    house.nDeferLastActivation = 1200;
    house.nLastAttestHeight = 1195;
    HousePartner pt;
    pt.vchPubKey = std::vector<unsigned char>(33, 0x02);
    pt.amountPledge = HOUSE_MIN_PLEDGE;
    pt.status = HOUSE_PARTNER_ACTIVE;
    house.vPartner.push_back(pt);

    const uint32_t nInsolvent = HouseDeferSilenceInsolventHeight(house);
    BOOST_REQUIRE(nInsolvent > 1200);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)nInsolvent - 1), HOUSE_STATUS_DEFERRED);
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, (int)nInsolvent), HOUSE_STATUS_INSOLVENT);

    CKey key; key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    HouseAttest att;
    att.nHouseID = 1;
    att.nSchemaVersion = 1;
    att.nAsOfHeight = nInsolvent - 2;
    att.amountReserves = 50000;
    AttestProof proof;
    proof.outpoint = COutPoint(uint256S("d1"), 0);
    proof.vchPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
    proof.vchSig = std::vector<unsigned char>(70, 0x30);
    att.vProofs.push_back(proof);
    att.vApproverIndex.push_back(0);
    att.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
    const CMutableTransaction mtx = MakeAttestTx(att);

    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == 1) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    auto verdict = [&](int nHeight, bool fMempool, int& nDoS) {
        CValidationState state; CHouse houseOut;
        BOOST_CHECK(!CheckHouseOperation(CTransaction(mtx), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass,
                                         fnNoCoin, GuardNoBlock, houseOut, fMempool));
        nDoS = 0;
        state.IsInvalid(nDoS);
        return state.GetRejectReason();
    };
    int nDoS = 0;
    // The house's own tip: still Deferred, so the status gate passes (a later gate refuses the junk proof).
    BOOST_CHECK(verdict((int)nInsolvent - 1, true, nDoS) != "bad-house-attest-closed");
    // A peer one block on.
    BOOST_CHECK_EQUAL(verdict((int)nInsolvent, true, nDoS), "bad-house-attest-closed");
    BOOST_CHECK_MESSAGE(nDoS == 0, "mempool attest-closed at the silence deadline scores " << nDoS << ", want 0 (UF4-1)");
    // In a block the refusal keeps its ban.
    BOOST_CHECK_EQUAL(verdict((int)nInsolvent, false, nDoS), "bad-house-attest-closed");
    BOOST_CHECK_EQUAL(nDoS, 100);
}

// ===========================================================================
// S1X-3 (security 2026-11-24: re-rated Medium). A
// SWAP moves its units out of nMintedUnits into pending, but the deferral recovery test at ATTEST (validation.cpp
// ~5110: till >= nMintedUnits x nTillMinBps), GoldParEligible and GoldTillRatioBps (issued_connect.cpp ~624-646) read
// nMintedUnits alone. In a run, as holders swap, a suspended house recovers on a till sized to the units left, the
// deferral lifts, and HOUSE_OP_RELEASE takes the locked till out of the pot while the swaps are still owed: the S1X-6
// class. Agreed fix: count pending swaps and the live shortfall (MaterializeInsolvency's lapse) in all three readers,
// one helper shared with S1X-6's caps.
// Setup: N = 100,000 minted; the till set (test hook) to exactly the floor for N. Cases: (a) nothing owed: the ATTEST
// recovers and RELEASE passes (control); (b) 50,000 pending in swaps: no recovery, RELEASE refused as not Open;
// (c) a live 50,000 mg shortfall paid the block before: the same; (d) that shortfall paid just past the lapse: recovers
// (control). Then par and the brassage curve at the same till. (b) and (c) FAIL on master 71b3558.
// ===========================================================================
namespace {
struct S1X3Scope {
    std::function<void(const CHouse&, int, CHouseCapital&)> fnPrev;
    CUnitsView units;
    std::unique_ptr<UnitsCheckScope> pScope;
    S1X3Scope(uint32_t nHouseID, uint64_t nTillMg, uint64_t nPending, uint64_t nShortfallMg, int64_t nPaidClock)
        : fnPrev(g_fnCapitalForChecksTestOverride), units(nullptr)
    {
        g_fnCapitalForChecksTestOverride = [nTillMg](const CHouse&, int, CHouseCapital& cap) {
            cap.nEscrowMg = cap.nCapacityMg = 100 * 1000 * 1000;   // capital never binds here
            cap.nTillMg = nTillMg;
        };
        if (nPending)
            units.Put(SwapPendingKey(nHouseID), nPending);
        if (nShortfallMg) {
            CShortfallLedger led;
            led.vEntry.push_back(std::make_pair(nPaidClock, nShortfallMg));
            units.Put(ShortfallLedgerKey(nHouseID), led);
        }
        pScope.reset(new UnitsCheckScope(&units));
    }
    ~S1X3Scope()
    {
        pScope.reset();
        g_fnCapitalForChecksTestOverride = fnPrev;
    }
};

CMutableTransaction S1X3Release(const CHouse& house, const CKey& key)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_RELEASE;
    for (const COutPoint& out : house.vOutReserveLock)
        mtx.vin.push_back(CTxIn(out));
    const CPubKey pub = key.GetPubKey();
    mtx.vout.push_back(CTxOut(1000, GetScriptForDestination(pub.GetID())));
    HouseRelease rel;
    rel.nHouseID = house.nHouseID;
    rel.vApproverIndex.push_back(0);
    rel.vApproverSig.push_back(URX12Sign(key, HouseReleaseSigHash(house.houseID, NoteHashPrevouts(CTransaction(mtx)),
                                                                   BillHashOutputs(mtx))));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rel;
    mtx.vchHousePayload.assign(ss.begin(), ss.end());
    return mtx;
}
} // namespace

BOOST_AUTO_TEST_CASE(s1x_3_recovery_par_and_brassage_count_what_the_house_still_owes)
{
    const uint32_t B = 20000;          // history enough for the shortfall lapse (as the S1X-6 tests)
    const int H = (int)B + 1300;
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(H);
    const int64_t nLapse = (int64_t)gp.nShortfallLapseSecs / 600;   // as MaterializeInsolvency reads it
    BOOST_REQUIRE(nLapse > 0 && ClockAtHeight(H) - nLapse - 1 > 0);
    const uint64_t N = 100000, P = 50000, S = 50000;
    const uint64_t nTill = (uint64_t)(((unsigned __int128)N * gp.nTillMinBps + 9999) / 10000);   // the floor for N
    BOOST_REQUIRE(nTill > 0);

    CKey keyPartner;
    keyPartner.MakeNewKey(true);
    const CPubKey pubPartner = keyPartner.GetPubKey();
    // A suspended house: stressed at B+1100, deferred at B+1200 with its till locked, last attested at B+1195.
    CHouse house = MakeGuardHouse();
    house.vPartner[0].vchPubKey = std::vector<unsigned char>(pubPartner.begin(), pubPartner.end());
    house.nMintedUnits = N;
    house.amountLastAttestReserves = 0;
    house.nStressSinceHeight = B + 1100;
    house.nDeferInvokedHeight = B + 1200;
    house.nDeferActivations = 1;
    house.nDeferLastActivation = B + 1200;
    house.nLastAttestHeight = B + 1195;
    house.vOutReserveLock.push_back(COutPoint(uint256S("10c4"), 0));   // the till locked at DEFER
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, H), HOUSE_STATUS_DEFERRED);

    struct Case { const char* name; uint64_t nPending; uint64_t nShortfall; int64_t nPaidClock; bool fRecovers; };
    const int64_t nPaidRecent = ClockAtHeight(H - 1);
    const int64_t nPaidLapsed = ClockAtHeight(H) - nLapse - 1;
    const Case cases[] = {{"(a) nothing owed", 0, 0, 0, true},
                          {"(b) 50,000 pending in swaps", P, 0, 0, false},
                          {"(c) a live 50,000 mg shortfall paid the block before", 0, S, nPaidRecent, false},
                          {"(d) that shortfall paid just past the lapse", 0, S, nPaidLapsed, true}};
    for (const Case& c : cases) {
        S1X3Scope scope(house.nHouseID, nTill, c.nPending, c.nShortfall, c.nPaidClock);
        CHouse h = house;
        const std::string strAttest = URX12Run(h, URX12Attest(house, H, keyPartner), H);
        BOOST_REQUIRE_MESSAGE(strAttest.empty(), std::string("S1X-3 setup ") + c.name + ": the ATTEST was refused: " + strAttest);
        const char chAfter = HouseEffectiveStatus(h, H + 1);
        CHouse hRel = h;
        const std::string strRelease = URX12Run(hRel, S1X3Release(h, keyPartner), H + 1);
        if (c.fRecovers) {
            BOOST_CHECK_MESSAGE(chAfter == HOUSE_STATUS_OPEN, std::string("S1X-3 control ") + c.name +
                                ": a till at the floor for every unit owed did not lift the deferral (status " + chAfter + ")");
            BOOST_CHECK_MESSAGE(strRelease.empty(), std::string("S1X-3 control ") + c.name + ": RELEASE after recovery "
                                "was refused: " + strRelease);
        } else {
            BOOST_CHECK_MESSAGE(chAfter != HOUSE_STATUS_OPEN, std::string("S1X-3 ") + c.name + ": the deferral lifted "
                                "on a till sized to the 100,000 minted units alone, though the house still owes more");
            BOOST_CHECK_MESSAGE(strRelease == "bad-house-release-not-open", std::string("S1X-3 ") + c.name +
                                ": RELEASE took the locked till out of the pot while the house still owes it (got " +
                                (strRelease.empty() ? std::string("accepted") : strRelease) + ")");
        }
    }

    // Par and the brassage curve read the same denominator. An Open house at the same till: par with nothing owed
    // (control), not with swaps pending or a live shortfall; the till ratio falls and a suspended house's spread rises.
    CHouse open = MakeGuardHouse();
    open.nMintedUnits = N;
    open.nLastAttestHeight = H - 1;
    BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(open, H), HOUSE_STATUS_OPEN);
    uint32_t nRatio0 = 0, nSpread0 = 0;
    {
        S1X3Scope scope(open.nHouseID, nTill, 0, 0, 0);
        BOOST_CHECK_MESSAGE(GoldParEligible(open, H), "S1X-3 control: an Open house with its till at the floor is not par eligible");
        nRatio0 = GoldTillRatioBps(open, H);
        nSpread0 = GoldBrassageBps(house, H);   // the suspended house above, nothing owed
    }
    struct Owed { const char* name; uint64_t nPending; uint64_t nShortfall; int64_t nPaidClock; };
    const Owed owed[] = {{"50,000 pending in swaps", P, 0, 0},
                         {"a live 50,000 mg shortfall", 0, S, nPaidRecent}};
    for (const Owed& o : owed) {
        S1X3Scope scope(open.nHouseID, nTill, o.nPending, o.nShortfall, o.nPaidClock);
        BOOST_CHECK_MESSAGE(!GoldParEligible(open, H), std::string("S1X-3 par (") + o.name + "): the house still settles "
                            "at par on a till that covers only the minted units");
        const uint32_t nRatio = GoldTillRatioBps(open, H);
        BOOST_CHECK_MESSAGE(nRatio < nRatio0, std::string("S1X-3 till ratio (") + o.name + "): " + std::to_string(nRatio) +
                            " bps, the same as with nothing owed (" + std::to_string(nRatio0) + ")");
        const uint32_t nSpread = GoldBrassageBps(house, H);
        BOOST_CHECK_MESSAGE(nSpread > nSpread0, std::string("S1X-3 brassage (") + o.name + "): a suspended house's "
                            "spread is " + std::to_string(nSpread) + " bps, no higher than with nothing owed (" +
                            std::to_string(nSpread0) + ")");
    }
}

// No new #include lines: house_tests.cpp already has houserate.h, issued.h and units.h.

// ---------------------------------------------------------------------------
// S1X-5, the two house-op snapshot sites (security 2026-11-23: Medium). See the note_tests case
// for the gate and the three checks. Neither site can be held by the S1X-5 gate in practice, so these PIN that and
// pass on master 71b3558:
//  - residual settle (insolvent RECLAIM, validation.cpp ~4868): it already refuses while ANY swap is pending
//    (bad-house-settle-swaps-outstanding, before the snapshot), so with a swap pending at the failure it is refused
//    before and after E + the deadline; settled DONE, it reaches the same verdict as with no swap.
//  - CLOSE (~4724): it waits for the 2-year claim window, far past E + the swap deadline, so the gate is always open
//    by then. Pinned: the window outlasts the deadline; at the window's end a swap still pending does not hold CLOSE.
// The house failed by the stress path and was never materialized (status still Open), so each op would take the
// snapshot itself.
// ---------------------------------------------------------------------------
namespace {
bool S1X5HouseEnds(const std::string& s, const std::string& suffix)
{
    return s.size() > suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// The guard house, failed by the stress path (as token_tests' FailedHouse) and never materialized.
CHouse S1X5LazyFailedGuardHouse(uint64_t nMinted)
{
    CHouse house = MakeGuardHouse();
    house.nLastAttestHeight = 1000;
    house.nStressSinceHeight = house.nLastAttestHeight + HOUSE_ATTEST_MISS_N * HOUSE_ATTEST_CADENCE + 1;
    house.nMintedUnits = nMinted;
    return house;
}

// The units the checks read at h: the chain clock, and (nSwap 1) another holder's swap opened at E - 10 still pending,
// or (nSwap 2) settled DONE at h.
void S1X5HouseUnits(CUnitsView& units, uint32_t nHouseID, uint32_t E, int h, int nSwap)
{
    CChainClock clock;
    clock.nHeight = (uint32_t)(h - 1);
    clock.nMonoTime = clock.nActiveTime = (int64_t)h * 600;
    units.Put(ChainClockKey(), clock);
    if (!nSwap)
        return;
    const uint32_t D = Params().GetConsensus().GramAt((int)E).nSwapDeadlineSecs;
    const uint256 hashLock = uint256S("5150");
    CSwapRecord rec;
    rec.nHouseID = nHouseID;
    rec.nUnits = 20000;
    rec.nBid0 = 1000;
    rec.nDemandHeight = E - 10;
    rec.nDeadlineActive = (int64_t)(E - 10) * 600 + D + 234;
    rec.vchPayoutScript = ParseHex("76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac");
    SwapOpen(units, hashLock, rec);
    if (nSwap == 2)
        SwapSettle(units, hashLock, SWAP_DONE, 0, (int64_t)h * 600, h, 12960);
}

std::string S1X5HouseVerdict(const CHouse& house, const CMutableTransaction& mtx, int h, uint32_t E, int nSwap)
{
    CUnitsView units(nullptr);
    S1X5HouseUnits(units, house.nHouseID, E, h, nSwap);
    UnitsCheckScope scope(&units);
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    CValidationState state; CHouse houseOut;
    const bool f = CheckHouseOperation(CTransaction(mtx), state, h, fnGetHouse, GuardNoHash, GuardNoClass, fnNoCoin,
                                       GuardNoBlock, houseOut);
    return f ? std::string("OK") : state.GetRejectReason();
}
} // namespace

BOOST_AUTO_TEST_CASE(s1x_5_residual_settle_waits_for_every_pending_swap)
{
    BOOST_REQUIRE(g_fClockIsHeightForTests);
    const CHouse house = S1X5LazyFailedGuardHouse(0);   // zero liability: the partners' settle is the first waterfall op
    const uint32_t E = HouseInsolventSince(house, 1000000);
    BOOST_REQUIRE(E > 20);
    BOOST_REQUIRE_EQUAL(house.status, HOUSE_STATUS_OPEN);
    const uint32_t D = Params().GetConsensus().GramAt((int)E).nSwapDeadlineSecs;
    const int64_t nDeadline = (int64_t)(E - 10) * 600 + D + 234;
    const uint32_t h1 = (uint32_t)((nDeadline - 1) / 600);
    const uint32_t h2 = E + (D + 599) / 600 + 1;
    BOOST_REQUIRE(h1 >= E);
    const CMutableTransaction mtx = MakeReclaimTx(house.nHouseID, 1, COutPoint(uint256S("a1"), 0));
    const std::string strControl = S1X5HouseVerdict(house, mtx, (int)h1, E, 0);
    BOOST_REQUIRE_MESSAGE(strControl != "bad-house-reclaim-stressed" && strControl != "bad-house-settle-notes-outstanding",
                          "S1X-5 setup: the residual settle stopped before the snapshot site: " + strControl);
    for (uint32_t h : {h1, h2}) {
        const std::string s = S1X5HouseVerdict(house, mtx, (int)h, E, 1);
        BOOST_CHECK_MESSAGE(S1X5HouseEnds(s, "-swaps-outstanding") || S1X5HouseEnds(s, "-swaps-pending"),
                            "S1X-5 residual settle at height " + std::to_string(h) + ": the partners settled while a swap "
                            "the snapshot counts is still pending: got '" + s + "'");
    }
    BOOST_CHECK_EQUAL(S1X5HouseVerdict(house, mtx, (int)h1, E, 2), strControl);   // DONE: nothing pending
}

BOOST_AUTO_TEST_CASE(s1x_5_close_is_never_held_by_a_swap_past_the_deadline)
{
    BOOST_REQUIRE(g_fClockIsHeightForTests);
    const CHouse house = S1X5LazyFailedGuardHouse(40);
    const uint32_t E = HouseInsolventSince(house, 1000000);
    BOOST_REQUIRE(E > 20);
    BOOST_REQUIRE_EQUAL(house.status, HOUSE_STATUS_OPEN);
    const uint32_t D = Params().GetConsensus().GramAt((int)E).nSwapDeadlineSecs;
    const uint32_t nWait = (D + 599) / 600;
    const int64_t nDeadline = (int64_t)(E - 10) * 600 + D + 234;
    const uint32_t h1 = (uint32_t)((nDeadline - 1) / 600);
    const uint32_t nOpen = HouseClaimWindowCloses(house, 1000000);
    // The claim window outlasts any swap pending at the failure: if this ever fails, the S1X-5 gate can bind at CLOSE
    // and CLOSE needs the three checks the claims have.
    BOOST_REQUIRE_MESSAGE(nOpen > E + nWait + 1, "S1X-5: the claim window (" << nOpen - E << " blocks) no longer "
                          "outlasts the swap deadline (" << nWait << " clock blocks)");
    const CMutableTransaction mtx = MakeCloseTx(house.nHouseID, {}, {});
    BOOST_CHECK_EQUAL(S1X5HouseVerdict(house, mtx, (int)h1, E, 1), "bad-house-close-window-open");
    const std::string strControl = S1X5HouseVerdict(house, mtx, (int)nOpen, E, 0);
    BOOST_REQUIRE_MESSAGE(strControl != "bad-house-close-window-open" && strControl != "bad-house-close-not-insolvent",
                          "S1X-5 setup: CLOSE stopped before the snapshot site: " + strControl);
    const std::string s = S1X5HouseVerdict(house, mtx, (int)nOpen, E, 1);
    BOOST_CHECK_MESSAGE(!S1X5HouseEnds(s, "-swaps-pending"), "S1X-5 CLOSE: a swap still pending two years after the "
                        "failure held CLOSE (" + s + "); the gate must open once E + the deadline has passed");
    BOOST_CHECK_EQUAL(s, strControl);
}


// S1X-27: a pooled REGISTER is keyed by its declared house id and by its class id, so a second REGISTER colliding on
// either is found by one lookup (it was a scan decoding every pooled REGISTER), and a re-wrap is found too.
BOOST_AUTO_TEST_CASE(s1x_27_pooled_identity_keys_register)
{
    HouseRegister regA, regB, regC;
    std::vector<CKey> vKeyA, vKeyB, vKeyC;
    const CMutableTransaction mtxA = MakeRegisterTx(regA, vKeyA, HOUSE_TIER_BONDED_SOLO, 1, 1, "clyde");
    const CMutableTransaction mtxB = MakeRegisterTx(regB, vKeyB, HOUSE_TIER_BONDED_SOLO, 1, 1, "clyde");   // same class
    const CMutableTransaction mtxC = MakeRegisterTx(regC, vKeyC, HOUSE_TIER_BONDED_SOLO, 1, 1, "tweed");
    std::vector<uint256> vA, vB, vC, vRe;
    PooledIdentityKeys(CTransaction(mtxA), vA);
    PooledIdentityKeys(CTransaction(mtxB), vB);
    PooledIdentityKeys(CTransaction(mtxC), vC);
    BOOST_REQUIRE_EQUAL(vA.size(), 2u);
    BOOST_REQUIRE_EQUAL(vB.size(), 2u);
    BOOST_REQUIRE_EQUAL(vC.size(), 2u);
    BOOST_CHECK(vA[0] != vB[0]);   // other partners: other house id
    BOOST_CHECK(vA[1] == vB[1]);   // same class id
    BOOST_CHECK(vA[0] != vC[0] && vA[1] != vC[1] && vA[0] != vC[1] && vA[1] != vC[0]);
    CMutableTransaction mtxRe = mtxA;
    mtxRe.vin[0].prevout = COutPoint(uint256S("05"), 2);
    mtxRe.nLockTime = 9;
    PooledIdentityKeys(CTransaction(mtxRe), vRe);
    BOOST_CHECK(vRe == vA);

    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    const CTransaction txA(mtxA);
    {
        LOCK(pool.cs);
        pool.addUnchecked(txA.GetHash(), entry.FromTx(txA));
    }
    BOOST_CHECK(pool.HaveIdentityKey(vB));    // the class collides: house-op-in-mempool
    BOOST_CHECK(pool.HaveIdentityKey(vRe));   // the re-wrap collides
    BOOST_CHECK(!pool.HaveIdentityKey(vC));
    pool.removeRecursive(txA);
    BOOST_CHECK(!pool.HaveIdentityKey(vB));
}


// S1X-8 (security: Low; Michael 11-25 yes): the spread is one ceiling division over the exact curve. Below the floor
// every redemption owes at least 1 mg; it is never less than the old floored amount, and never more than it plus 1 mg
// over the exact rational value.
BOOST_AUTO_TEST_CASE(s1x_8_brassage_amount_rounds_up_once)
{
    const uint32_t nRho = 200;   // the 2% till floor, in bps
    BOOST_CHECK_EQUAL(BrassageAmountAt(1000000, nRho, nRho), 0);         // at the floor: par
    BOOST_CHECK_EQUAL(BrassageAmountAt(1000000, nRho + 5, nRho), 0);
    BOOST_CHECK_EQUAL(BrassageAmountAt(0, 0, nRho), 0);
    BOOST_CHECK_EQUAL(BrassageAmountAt(1, nRho - 1, nRho), 1);           // 1 mg just under the floor owes 1 mg
    BOOST_CHECK_EQUAL(HouseBrassageAmount(1, BrassageBpsAt(nRho - 1, nRho)), 0);   // the old rounding owed nothing
    BOOST_CHECK_EQUAL(BrassageAmountAt(24, 0, nRho), (24 * (int64_t)HOUSE_BRASSAGE_MAX_BPS + 9999) / 10000);
    for (uint64_t u : {1ULL, 7ULL, 24ULL, 25ULL, 999ULL, 123457ULL, 1000000007ULL}) {
        for (uint32_t r = 0; r <= nRho + 2; r++) {
            const CAmount a = BrassageAmountAt(u, r, nRho);
            BOOST_CHECK(a >= HouseBrassageAmount(u, BrassageBpsAt(r, nRho)));
            // Against the exact rational value U * MAX * p^2 / (10000 q^2) (or U * MAX / 10000 at or below theta).
            const uint32_t nTheta = nRho / 4;
            long double x = 0;
            if (r < nRho) {
                if (r <= nTheta) x = (long double)u * HOUSE_BRASSAGE_MAX_BPS / 10000;
                else {
                    const long double p = nRho - r, q = nRho - nTheta;
                    x = (long double)u * HOUSE_BRASSAGE_MAX_BPS * p * p / (10000 * q * q);
                }
            }
            BOOST_CHECK((long double)a >= x - 1e-6);
            BOOST_CHECK((long double)a < x + 1 + 1e-6);
            if (r < nRho)
                BOOST_CHECK(a >= 1);
        }
    }
}


// S1X-18 (security: Low; Michael 11-25 yes): ESCROW_MERGE consolidates ONE escrow list into one coin holding exactly the
// merged sum; every escrow input must be on that list (fail closed), and change never mixes with reserve.
BOOST_AUTO_TEST_CASE(s1x_18_escrow_merge)
{
    CHouse house = MakeGuardHouse();
    const COutPoint A(uint256S("a1"), 0), B(uint256S("b2"), 1), C(uint256S("c3"), 2), R(uint256S("d4"), 0);
    const COutPoint N(uint256S("e5"), 0);   // a listed escrow coin that also carries a note tag (security's note 3)
    house.vOutEscrowChange = {A, B, C, N};
    std::sort(house.vOutEscrowChange.begin(), house.vOutEscrowChange.end());
    house.vOutReserveLock = {R};
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnGetCoin = [&](const COutPoint& out, Coin& coin) {
        if (out == A || out == B || out == C || out == R || out == N) {
            coin = Coin(CTxOut(out == A ? 1000 : out == B ? 2000 : out == C ? 3000 : 4000, HouseEscrowScript(house.houseID)), 10, false, false, false, uint256());
            coin.SetHouseEscrow(house.nHouseID);
            if (out == N)
                coin.SetNote(house.nHouseID, 5, 0);
            return true;
        }
        coin = Coin(CTxOut(50000, CScript() << OP_TRUE), 10, false, false, false, uint256());   // a plain fee coin
        return true;
    };
    auto build = [&](uint8_t nList, const std::vector<COutPoint>& vIn, CAmount nOut) {
        HouseEscrowMerge m;
        m.nHouseID = house.nHouseID;
        m.nList = nList;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << m;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_ESCROW_MERGE, ss);
        mtx.vin.clear();
        for (const COutPoint& o : vIn)
            mtx.vin.push_back(CTxIn(o));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("fee"), 0)));
        mtx.vout.clear();
        mtx.vout.push_back(CTxOut(nOut, HouseEscrowScript(house.houseID)));
        return mtx;
    };
    auto run = [&](const CMutableTransaction& mtx, CHouse& houseOut) {
        CValidationState state;
        const bool fOk = CheckHouseOperation(CTransaction(mtx), state, 1000, fnGetHouse, GuardNoHash, GuardNoClass,
                                             fnGetCoin, GuardNoBlock, houseOut);
        return fOk ? std::string() : state.GetRejectReason();
    };
    {
        CHouse out;
        const CMutableTransaction mtx = build(HOUSE_ESCROW_LIST_CHANGE, {A, B}, 3000);
        BOOST_CHECK_EQUAL(run(mtx, out), "");
        std::vector<COutPoint> vWant = {C, N, COutPoint(CTransaction(mtx).GetHash(), 0)};
        std::sort(vWant.begin(), vWant.end());
        BOOST_CHECK(out.vOutEscrowChange == vWant);
        BOOST_CHECK(out.vOutReserveLock == house.vOutReserveLock);   // the other list is untouched
        CValidationState state;
        BOOST_CHECK(CheckHouseTransactionShape(CTransaction(mtx), state));
    }
    CHouse out;
    BOOST_CHECK_EQUAL(run(build(HOUSE_ESCROW_LIST_CHANGE, {A, B}, 2999), out), "bad-house-merge-output");   // not the sum
    BOOST_CHECK_EQUAL(run(build(HOUSE_ESCROW_LIST_CHANGE, {A}, 1000), out), "bad-house-merge-inputs");      // one coin
    BOOST_CHECK_EQUAL(run(build(HOUSE_ESCROW_LIST_CHANGE, {A, R}, 5000), out), "bad-house-merge-not-listed");   // reserve into change
    BOOST_CHECK_EQUAL(run(build(HOUSE_ESCROW_LIST_RESERVE, {R, A}, 5000), out), "bad-house-merge-not-listed");  // change into reserve
    BOOST_CHECK_EQUAL(run(build(HOUSE_ESCROW_LIST_CHANGE, {A, N}, 5000), out), "bad-house-merge-tagged-input");  // a note tag would be lost
    {   // a stray escrow output beyond vout[0] is refused at the shape
        CMutableTransaction mtx = build(HOUSE_ESCROW_LIST_CHANGE, {A, B}, 3000);
        mtx.vout.push_back(CTxOut(10, HouseEscrowScript(house.houseID)));
        CValidationState state;
        BOOST_CHECK(!CheckHouseTransactionShape(CTransaction(mtx), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-house-merge-stray-escrow");
    }
}

// testing (2026-11-25): S1X-18, security's addition (d): a test at CLOSE's weight limit. A CLOSE (and a settle) must spend
// every coin on the house's escrow lists; each spread-paying REDEEM adds one, and only claims took them off. At 2,500
// listed change coins a CLOSE's inputs alone weigh past MAX_STANDARD_TX_WEIGHT, so policy would never relay it. MERGEs of
// up to 500 coins, each a standard transaction, bring the list back to one coin; 501 in one MERGE is refused.
BOOST_AUTO_TEST_CASE(s1x_18_merges_bring_a_close_back_under_the_weight_limit)
{
    CHouse house = MakeGuardHouse();
    const size_t N = 2500;
    std::map<COutPoint, CAmount> mapEscrow;   // every escrow coin the checks may read, with its value
    for (size_t i = 0; i < N; i++) {
        const COutPoint o(uint256S(strprintf("%x", 0xe00000 + i)), 0);
        house.vOutEscrowChange.push_back(o);
        mapEscrow[o] = 1000 + (CAmount)i;
    }
    std::sort(house.vOutEscrowChange.begin(), house.vOutEscrowChange.end());
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnGetCoin = [&](const COutPoint& out, Coin& coin) {
        auto it = mapEscrow.find(out);
        if (it != mapEscrow.end()) {
            coin = Coin(CTxOut(it->second, HouseEscrowScript(house.houseID)), 10, false, false, false, uint256());
            coin.SetHouseEscrow(house.nHouseID);
            return true;
        }
        coin = Coin(CTxOut(50000, CScript() << OP_TRUE), 10, false, false, false, uint256());   // a plain fee coin
        return true;
    };
    const CScript scriptPlain = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x18) << OP_EQUALVERIFY << OP_CHECKSIG;
    auto closeOf = [&](const std::vector<COutPoint>& vList) {
        HouseClose cl;
        cl.nHouseID = house.nHouseID;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << cl;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_CLOSE, ss);
        mtx.vin.clear();
        for (const COutPoint& o : vList)
            mtx.vin.push_back(CTxIn(o));
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("fee"), 0)));
        mtx.vout.clear();
        mtx.vout.push_back(CTxOut(100000, scriptPlain));
        return mtx;
    };
    auto mergeOf = [&](const std::vector<COutPoint>& vIn) {
        HouseEscrowMerge m;
        m.nHouseID = house.nHouseID;
        m.nList = HOUSE_ESCROW_LIST_CHANGE;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << m;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_ESCROW_MERGE, ss);
        mtx.vin.clear();
        CAmount nSum = 0;
        for (const COutPoint& o : vIn) {
            mtx.vin.push_back(CTxIn(o));
            nSum += mapEscrow.at(o);
        }
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("fee"), 1)));
        mtx.vout.clear();
        mtx.vout.push_back(CTxOut(nSum, HouseEscrowScript(house.houseID)));
        return mtx;
    };
    auto run = [&](const CMutableTransaction& mtx, CHouse& houseOut) {
        CValidationState state;
        const bool fOk = CheckHouseOperation(CTransaction(mtx), state, 1000, fnGetHouse, GuardNoHash, GuardNoClass,
                                             fnGetCoin, GuardNoBlock, houseOut);
        return fOk ? std::string() : state.GetRejectReason();
    };

    // The premise: a CLOSE of all 2,500 listed coins is over the standard weight.
    const int64_t nCloseWeight = GetTransactionWeight(CTransaction(closeOf(house.vOutEscrowChange)));
    BOOST_REQUIRE_MESSAGE(nCloseWeight >= (int64_t)MAX_STANDARD_TX_WEIGHT,
                          strprintf("S1X-18 setup: a CLOSE of %u listed coins weighs %d, under the standard %u", N, nCloseWeight,
                                    MAX_STANDARD_TX_WEIGHT));

    // 501 coins in one MERGE are refused.
    {
        CHouse out;
        const std::vector<COutPoint> v501(house.vOutEscrowChange.begin(), house.vOutEscrowChange.begin() + 501);
        BOOST_CHECK_EQUAL(run(mergeOf(v501), out), "bad-house-merge-inputs");
    }

    // MERGEs of 500, each standard and valid, until one coin is left.
    int nMerges = 0;
    while (house.vOutEscrowChange.size() > 1) {
        const size_t n = std::min<size_t>(MAX_HOUSE_ESCROW_MERGE_INPUTS, house.vOutEscrowChange.size());
        const std::vector<COutPoint> vIn(house.vOutEscrowChange.begin(), house.vOutEscrowChange.begin() + n);
        const CMutableTransaction mtx = mergeOf(vIn);
        const CTransaction tx(mtx);
        std::string strReason;
        BOOST_CHECK_MESSAGE(IsStandardTx(tx, strReason, true),
                            strprintf("S1X-18: a MERGE of %u coins is not standard (%s, weight %d)", n, strReason, GetTransactionWeight(tx)));
        CValidationState state;
        BOOST_REQUIRE(CheckHouseTransactionShape(tx, state));
        CHouse out;
        BOOST_REQUIRE_EQUAL(run(mtx, out), "");
        BOOST_REQUIRE_EQUAL(out.vOutEscrowChange.size(), house.vOutEscrowChange.size() - n + 1);
        mapEscrow[COutPoint(tx.GetHash(), 0)] = tx.vout[0].nValue;
        house = out;
        BOOST_REQUIRE(++nMerges <= 10);
    }
    BOOST_CHECK_EQUAL(nMerges, 6);   // 2,500 -> 2,001 -> 1,502 -> 1,003 -> 504 -> 5 -> 1
    CAmount nTotal = 0;
    for (size_t i = 0; i < N; i++)
        nTotal += 1000 + (CAmount)i;
    BOOST_CHECK_EQUAL(mapEscrow.at(house.vOutEscrowChange[0]), nTotal);   // nothing left the escrow
    BOOST_CHECK(GetTransactionWeight(CTransaction(closeOf(house.vOutEscrowChange))) < (int64_t)MAX_STANDARD_TX_WEIGHT / 100);
}

// testing (2026-11-25): S1X-16a (security: Low; consensus batch fb8146d): an ADMIT approval names its expiry height,
// signed by the new partner and the approvers, and is refused at any height past it; it may name at most
// HOUSE_ADMIT_APPROVAL_MAX_BLOCKS ahead. Past the expiry the refusal scores 0 in the mempool (one block can turn it stale
// with no tx in between, UF4-1) and 100 at connect. The gate s1x_16a_admit_expiry_roundtrip shows it on a node.
BOOST_AUTO_TEST_CASE(s1x_16a_admit_approval_expires)
{
    CHouse house = MakeGuardHouse();   // multi-partner, effectively Open from 1000
    std::vector<CKey> keys(3);
    house.vPartner.clear();
    for (int i = 0; i < 3; i++) {
        keys[i].MakeNewKey(true);
        const CPubKey pub = keys[i].GetPubKey();
        HousePartner p;
        p.vchPubKey.assign(pub.begin(), pub.end());
        p.amountPledge = HOUSE_MIN_PLEDGE;
        p.vOutPledge.push_back(COutPoint(uint256S(strprintf("c%d", i)), 0));
        p.status = HOUSE_PARTNER_ACTIVE;
        house.vPartner.push_back(p);
    }
    house.nThresholdM = 2;
    const int H = 1000;
    auto fnGetHouse = [&](uint32_t id, CHouse& out) { if (id == house.nHouseID) { out = house; return true; } return false; };
    auto fnNoCoin = [](const COutPoint&, Coin&) { return false; };
    CKey keyNew;
    keyNew.MakeNewKey(true);
    const CPubKey pubNew = keyNew.GetPubKey();

    auto build = [&](uint32_t nSignedExpiry, uint32_t nPayloadExpiry) {
        HouseAdmit admit;
        admit.nHouseID = house.nHouseID;
        admit.vchNewPubKey.assign(pubNew.begin(), pubNew.end());
        const uint256 h = HouseAdmitSigHash(house.houseID, admit.vchNewPubKey, HOUSE_MIN_PLEDGE, nSignedExpiry);
        BOOST_REQUIRE(keyNew.Sign(h, admit.vchNewSig));
        for (uint32_t i : {0u, 1u}) {
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(keys[i].Sign(h, sig));
            admit.vApproverIndex.push_back(i);
            admit.vApproverSig.push_back(sig);
        }
        admit.nExpiryHeight = nPayloadExpiry;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << admit;
        CMutableTransaction mtx = MakeHouseOpTx(HOUSE_OP_ADMIT, ss);
        mtx.vout.clear();
        mtx.vout.push_back(CTxOut(HOUSE_MIN_PLEDGE, HouseEscrowScript(house.houseID)));
        return mtx;
    };
    struct Verdict { std::string strReason; int nDoS; };
    auto run = [&](const CMutableTransaction& mtx, int nHeight, bool fMempool) {
        BOOST_REQUIRE_EQUAL(HouseEffectiveStatus(house, nHeight), HOUSE_STATUS_OPEN);
        CValidationState state; CHouse houseOut;
        const bool fOk = CheckHouseOperation(CTransaction(mtx), state, nHeight, fnGetHouse, GuardNoHash, GuardNoClass,
                                             fnNoCoin, GuardNoBlock, houseOut, fMempool);
        Verdict v{fOk ? std::string() : state.GetRejectReason(), 0};
        state.IsInvalid(v.nDoS);
        return v;
    };

    // The boundary: valid in the block at the expiry height, refused in the next.
    const uint32_t E = H + 144;
    BOOST_CHECK_EQUAL(run(build(E, E), (int)E, false).strReason, "");
    for (const bool fMempool : {true, false}) {
        const Verdict v = run(build(E, E), (int)E + 1, fMempool);
        BOOST_CHECK_EQUAL(v.strReason, "bad-house-admit-expired");
        BOOST_CHECK_EQUAL(v.nDoS, fMempool ? 0 : 100);
    }
    // The cap: at most HOUSE_ADMIT_APPROVAL_MAX_BLOCKS ahead of the height it is checked at.
    BOOST_CHECK_EQUAL(run(build(H + HOUSE_ADMIT_APPROVAL_MAX_BLOCKS, H + HOUSE_ADMIT_APPROVAL_MAX_BLOCKS), H, false).strReason, "");
    BOOST_CHECK_EQUAL(run(build(H + HOUSE_ADMIT_APPROVAL_MAX_BLOCKS + 1, H + HOUSE_ADMIT_APPROVAL_MAX_BLOCKS + 1), H, false).strReason,
                      "bad-house-admit-expiry-far");
    // The signatures bind the expiry: a relayer can't extend an approval.
    BOOST_CHECK_EQUAL(run(build(E, E + 100), (int)E + 1, false).strReason, "bad-house-admit-new-sig");
}

BOOST_AUTO_TEST_SUITE_END()
