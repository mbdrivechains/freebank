// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>

#include <coins.h>
#include <consensus/params.h>   // GramParams (SA-N2)
#include <houserate.h>        // per-house rates in a test view (SA-N2)
#include <issued.h>           // UnitsCheckScope (SA-N2)
#include <units.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <key.h>
#include <note.h>             // NOTE_DUST_VALUE / MAX_NOTE_OUTPUTS
#include <script/interpreter.h>   // SIGHASH_ALL
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <txmempool.h>
#include <utilstrencodings.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <functional>

// Contextual bill-op validator (validation.cpp, external linkage; not in a public header) - UR1-6's tests drive it.
bool CheckBillOperation(const CTransaction& tx, CValidationState& state, int nHeight, const CAmount& nTxFee,
                        const std::function<bool(uint32_t, CBill&)>& fnGetBill,
                        const std::function<bool(const uint256&)>& fnHaveBillHash,
                        const std::function<bool(uint32_t, CHouse&)>& fnGetHouse,
                        const std::function<bool(const COutPoint&, Coin&)>& fnGetProofCoin,
                        const std::function<bool(uint32_t, uint256&)>& fnGetBlockHash,
                        CBill& billOut, CHouse& houseOut, bool& fHouseChanged, bool fMempool);

BOOST_FIXTURE_TEST_SUITE(bill_tests, BasicTestingSetup)

// Stage 0 C1 shim for the digest tests: the payload goes into a bill tx whose input is hp and whose output pays a script
// made from ho, and the digest is taken over that tx (C1 digests take the whole transaction).
template <typename P>
static CTransaction C1BillTx(uint8_t nOp, const P& p, const uint256& hp, const uint256& ho)
{
    CMutableTransaction m;
    m.nVersion = TRANSACTION_BILL_VERSION;
    m.nBillOp = nOp;
    m.vin.push_back(CTxIn(COutPoint(hp, 0)));
    m.vout.push_back(CTxOut(1000, CScript() << std::vector<unsigned char>(ho.begin(), ho.end())));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    m.vchBillPayload.assign(ss.begin(), ss.end());
    return CTransaction(m);
}

static std::vector<unsigned char> TestBody()
{
    const std::string str = "test-bill-encrypted-body";
    return std::vector<unsigned char>(str.begin(), str.end());
}

static const CAmount TEST_BILL_ESCROW = 75 * COIN / 10;   // 7.5

// Build a fully valid ISSUE transaction with fresh keys
static CMutableTransaction MakeIssueTx(BillIssue& issueOut, CKey& keyDrawer, CKey& keyAcceptor, CKey& keyHolder)
{
    keyDrawer.MakeNewKey(true);
    keyAcceptor.MakeNewKey(true);
    keyHolder.MakeNewKey(true);

    BillIssue issue;
    issue.vchEncryptedBody = TestBody();
    issue.amount = 10 * COIN;
    issue.nMaturityHeight = 500;
    issue.nGraceBlocks = DEFAULT_BILL_GRACE_BLOCKS;
    CPubKey pubDrawer = keyDrawer.GetPubKey();
    CPubKey pubAcceptor = keyAcceptor.GetPubKey();
    CPubKey pubHolder = keyHolder.GetPubKey();
    issue.vchDrawerPubKey = std::vector<unsigned char>(pubDrawer.begin(), pubDrawer.end());
    issue.vchAcceptorPubKey = std::vector<unsigned char>(pubAcceptor.begin(), pubAcceptor.end());
    issue.vchHolderPubKey = std::vector<unsigned char>(pubHolder.begin(), pubHolder.end());

    issue.nRefHouseID = 1;   // Gold B: the reference house (the fixtures' house 1)
    const uint256 billID = BillIDFromBody(issue.vchEncryptedBody);
    const uint256 sighash = BillIssueSigHash(billID, issue.amount, TEST_BILL_ESCROW,
            issue.nMaturityHeight, issue.nGraceBlocks, issue.vchDrawerPubKey,
            issue.vchAcceptorPubKey, issue.vchHolderPubKey, issue.nRefHouseID);
    BOOST_REQUIRE(keyDrawer.Sign(sighash, issue.vchDrawerSig));
    BOOST_REQUIRE(keyAcceptor.Sign(sighash, issue.vchAcceptorSig));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_ISSUE;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << issue;
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());

    // funding input placeholder (prevout must be non-null for CheckTransaction)
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));

    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, GetScriptForDestination(pubHolder.GetID())));
    mtx.vout.push_back(CTxOut(TEST_BILL_ESCROW, BillEscrowScript(billID)));

    issueOut = issue;
    return mtx;
}

BOOST_AUTO_TEST_CASE(bill_id_derivation)
{
    // Single SHA256 of the body (NOT double-SHA)
    std::vector<unsigned char> vchBody = TestBody();
    uint256 id = BillIDFromBody(vchBody);
    BOOST_CHECK(!id.IsNull());

    // Deterministic + sensitive to body changes
    BOOST_CHECK(id == BillIDFromBody(TestBody()));
    vchBody[0] ^= 1;
    BOOST_CHECK(id != BillIDFromBody(vchBody));
}

BOOST_AUTO_TEST_CASE(bill_sighash_domain_separation)
{
    const uint256 billID = BillIDFromBody(TestBody());
    const uint256 hashOutputs = uint256S("02");

    // Stage 0 C1: retire and claim digests take the whole tx (and the bill's canonical id); over one tx they differ,
    // the outputs, the inputs and the lock time matter, and op 3 / 7 and op 4 / 8 each have their own domain.
    const uint256 bind = uint256S("05");
    const CTransaction tx0 = C1BillTx(BILL_OP_RETIRE, BillRetire(), bind, hashOutputs);
    BOOST_CHECK(BillRetireSigHash(tx0, billID, false) != BillClaimSigHash(tx0, billID, false));
    BOOST_CHECK(BillClaimSigHash(tx0, billID, false) !=
                BillClaimSigHash(C1BillTx(BILL_OP_RETIRE, BillRetire(), bind, uint256S("03")), billID, false));
    BOOST_CHECK(BillClaimSigHash(tx0, billID, false) !=
                BillClaimSigHash(C1BillTx(BILL_OP_RETIRE, BillRetire(), uint256S("06"), hashOutputs), billID, false));
    BOOST_CHECK(BillClaimSigHash(tx0, billID, false) != BillClaimSigHash(tx0, billID, true));
    BOOST_CHECK(BillRetireSigHash(tx0, billID, false) != BillRetireSigHash(tx0, billID, true));
    BOOST_CHECK(BillRetireSigHash(tx0, billID, false) != BillRetireSigHash(tx0, uint256S("0b"), false));   // canonical id
    // BillTxBindingHash moves with nLockTime, an nSequence, or an added input
    CMutableTransaction m;
    m.vin.push_back(CTxIn(COutPoint(uint256S("07"), 0)));
    const uint256 b0 = BillTxBindingHash(CTransaction(m));
    m.nLockTime = 1;
    BOOST_CHECK(BillTxBindingHash(CTransaction(m)) != b0);
    m.nLockTime = 0;
    m.vin[0].nSequence = 5;
    BOOST_CHECK(BillTxBindingHash(CTransaction(m)) != b0);
    m.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    BOOST_CHECK(BillTxBindingHash(CTransaction(m)) == b0);
    m.vin.push_back(CTxIn(COutPoint(uint256S("08"), 0)));
    BOOST_CHECK(BillTxBindingHash(CTransaction(m)) != b0);
}

BOOST_AUTO_TEST_CASE(bill_escrow_script)
{
    const uint256 billID = BillIDFromBody(TestBody());
    CScript script = BillEscrowScript(billID);
    BOOST_CHECK(IsBillEscrowScript(script));
    BOOST_CHECK(!IsBillEscrowScript(CScript() << OP_TRUE));
    BOOST_CHECK(!IsBillEscrowScript(GetScriptForDestination(CKeyID())));
}

BOOST_AUTO_TEST_CASE(bill_endorse_fee_floor)
{
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(1), 0);
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(BILL_ENDORSE_SOFT_CAP), 0);
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(BILL_ENDORSE_SOFT_CAP + 1), BILL_ENDORSE_BASE_FEE * 2);
    BOOST_CHECK_EQUAL(BillEndorseFeeFloor(BILL_ENDORSE_SOFT_CAP + 4), BILL_ENDORSE_BASE_FEE * 16);
}

BOOST_AUTO_TEST_CASE(bill_payload_roundtrip)
{
    BillIssue issue;
    CKey k1, k2, k3;
    CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);

    BillIssue decoded;
    BOOST_REQUIRE(DecodeBillPayload(mtx.vchBillPayload, decoded));
    BOOST_CHECK(decoded.vchEncryptedBody == issue.vchEncryptedBody);
    BOOST_CHECK_EQUAL(decoded.amount, issue.amount);
    BOOST_CHECK_EQUAL(decoded.nMaturityHeight, issue.nMaturityHeight);
    BOOST_CHECK(decoded.vchDrawerSig == issue.vchDrawerSig);

    // Trailing bytes are rejected
    std::vector<unsigned char> vchPadded = mtx.vchBillPayload;
    vchPadded.push_back(0x00);
    BOOST_CHECK(!DecodeBillPayload(vchPadded, decoded));
}

BOOST_AUTO_TEST_CASE(bill_tx_serialization_roundtrip)
{
    BillIssue issue;
    CKey k1, k2, k3;
    CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);

    // v11 trailer fields must survive tx serialization
    CTransaction tx(mtx);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    CTransaction tx2(deserialize, ss);

    BOOST_CHECK_EQUAL(tx2.nVersion, TRANSACTION_BILL_VERSION);
    BOOST_CHECK_EQUAL(tx2.nBillOp, BILL_OP_ISSUE);
    BOOST_CHECK(tx2.vchBillPayload == tx.vchBillPayload);
    BOOST_CHECK(tx2.GetHash() == tx.GetHash());
}

BOOST_AUTO_TEST_CASE(bill_issue_shape_valid)
{
    BillIssue issue;
    CKey k1, k2, k3;
    CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);

    CValidationState state;
    BOOST_CHECK(CheckBillTransactionShape(CTransaction(mtx), state));
}

// The drawer/acceptor signatures are verified contextually (CheckBillOperation),
// not in the context-free shape check, so exercise the binding directly: any
// change to a signed field — including the posted escrow bond — must break the
// signature. This is the anti-front-run guarantee (bond bound into the sighash).
BOOST_AUTO_TEST_CASE(bill_issue_sig_binding)
{
    CKey keyDrawer;
    keyDrawer.MakeNewKey(true);
    CPubKey pub = keyDrawer.GetPubKey();
    std::vector<unsigned char> vchPub(pub.begin(), pub.end());

    const uint256 billID = BillIDFromBody(TestBody());
    const CAmount amount = 10 * COIN;
    const CAmount escrow = 75 * COIN / 10;

    const uint256 sighash = BillIssueSigHash(billID, amount, escrow, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub, 1);
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyDrawer.Sign(sighash, vchSig));
    BOOST_CHECK(pub.Verify(sighash, vchSig));

    // Front-run with a token escrow bond -> different sighash -> sig invalid
    const uint256 sighashCheapBond = BillIssueSigHash(billID, amount, 1, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub, 1);
    BOOST_CHECK(sighash != sighashCheapBond);
    BOOST_CHECK(!pub.Verify(sighashCheapBond, vchSig));

    // Tampered face amount -> sig invalid
    BOOST_CHECK(!pub.Verify(BillIssueSigHash(billID, amount + 1, escrow, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub, 1), vchSig));
}

BOOST_AUTO_TEST_CASE(bill_issue_shape_rejections)
{
    BillIssue issue;
    CKey k1, k2, k3;

    // Escrow output must commit to the body's bill_id
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        mtx.vout[1].scriptPubKey = BillEscrowScript(uint256S("04"));

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }

    // Title output must pay the holder exactly BILL_TITLE_VALUE
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        mtx.vout[0].nValue = BILL_TITLE_VALUE + 1;

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }

    // Unknown op
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        mtx.nBillOp = 99;

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }

    // Oversize body
    {
        CMutableTransaction mtx = MakeIssueTx(issue, k1, k2, k3);
        BillIssue big = issue;
        big.vchEncryptedBody.assign(MAX_BILL_BODY_BYTES + 1, 0x42);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << big;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());

        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
    }
}

BOOST_AUTO_TEST_CASE(bill_endorsement_sig)
{
    CKey keyFrom;
    keyFrom.MakeNewKey(true);
    CKey keyTo;
    keyTo.MakeNewKey(true);
    CPubKey pubFrom = keyFrom.GetPubKey();
    CPubKey pubTo = keyTo.GetPubKey();

    const uint256 billID = BillIDFromBody(TestBody());
    std::vector<unsigned char> vchTo(pubTo.begin(), pubTo.end());
    std::vector<unsigned char> vchFrom(pubFrom.begin(), pubFrom.end());

    const uint256 sighash = BillEndorseSigHash(billID, vchFrom, vchTo, 100, 2);
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyFrom.Sign(sighash, vchSig));

    BOOST_CHECK(pubFrom.Verify(sighash, vchSig));
    // Signature does not verify for a different height or endorsee
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchFrom, vchTo, 101, 2), vchSig));
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchFrom, vchFrom, 100, 2), vchSig));
    // S1X-34: nor for another endorser or another place in the chain (a replay after RECOURSE lands one link later)
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchTo, vchTo, 100, 2), vchSig));
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchFrom, vchTo, 100, 3), vchSig));
}

BOOST_AUTO_TEST_CASE(bill_record_serialization)
{
    CBill bill;
    bill.nBillID = 7;
    bill.billID = BillIDFromBody(TestBody());
    bill.vchEncryptedBody = TestBody();
    bill.amount = 10 * COIN;
    bill.amountEscrow = 75 * COIN / 10;
    bill.nIssuedHeight = 10;
    bill.nMaturityHeight = 500;
    bill.nGraceBlocks = DEFAULT_BILL_GRACE_BLOCKS;
    bill.status = BILL_STATUS_ACTIVE;
    bill.outEscrow = COutPoint(uint256S("05"), 1);
    bill.outTitle = COutPoint(uint256S("05"), 0);

    BillEndorsement e;
    e.nAtHeight = 42;
    bill.vEndorsement.push_back(e);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << bill;
    CBill bill2;
    ss >> bill2;

    BOOST_CHECK_EQUAL(bill2.nBillID, bill.nBillID);
    BOOST_CHECK(bill2.billID == bill.billID);
    BOOST_CHECK_EQUAL(bill2.amount, bill.amount);
    BOOST_CHECK_EQUAL(bill2.status, bill.status);
    BOOST_CHECK_EQUAL(bill2.vEndorsement.size(), 1);
    BOOST_CHECK_EQUAL(bill2.vEndorsement[0].nAtHeight, 42);
    BOOST_CHECK(bill2.outTitle == bill.outTitle);
}

//
// Phase 3.9 (B1) primitives - T-d1 gate.
//

/** A fully-populated legacy-shaped bill (no post-legacy state). */
static CBill TestLegacyBill()
{
    CBill bill;
    bill.nBillID = 7;
    bill.billID = uint256S("0a0b");
    bill.vchEncryptedBody = TestBody();
    bill.amount = 40000000;
    bill.amountEscrow = 8000000;
    bill.nIssuedHeight = 100;
    bill.nMaturityHeight = 8740;
    bill.nGraceBlocks = DEFAULT_BILL_GRACE_BLOCKS;
    bill.vchDrawerPubKey = std::vector<unsigned char>(33, 0x02);
    bill.vchAcceptorPubKey = std::vector<unsigned char>(33, 0x03);
    bill.vchHolderPubKey = std::vector<unsigned char>(33, 0x02);
    bill.status = BILL_STATUS_ACTIVE;
    bill.txidIssue = uint256S("0c0d");
    bill.outEscrow = COutPoint(uint256S("0c0d"), 1);
    bill.outTitle = COutPoint(uint256S("0c0d"), 0);
    return bill;
}

BOOST_AUTO_TEST_CASE(bill_ser_canonical_minimal)
{
    // The whole point of the canonical-minimal discriminator (B1 OD-6): a record
    // that carries no post-legacy state must serialize to the EXACT legacy bytes,
    // so an upgraded node, a reorged node and a fresh-synced node hold identical
    // records and the deep-reorg gate stays a STRICT byte compare.
    const CBill bill = TestLegacyBill();
    BOOST_CHECK_EQUAL(bill.nOwnerHouseID, 0);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << bill;
    const std::vector<unsigned char> vchNew(ss.begin(), ss.end());

    // The legacy layout begins with nBillID, NOT the sentinel.
    uint32_t nFirst = 0;
    memcpy(&nFirst, vchNew.data(), 4);
    BOOST_CHECK_EQUAL(nFirst, 7U);
    BOOST_CHECK(nFirst != BILL_SER_SENTINEL);

    // Legacy bytes -> read -> re-write -> byte-compare (the migration gate).
    CBill back;
    CDataStream ssIn(vchNew, SER_NETWORK, PROTOCOL_VERSION);
    ssIn >> back;
    BOOST_CHECK_EQUAL(back.nOwnerHouseID, 0);
    BOOST_CHECK_EQUAL(back.nBillID, bill.nBillID);
    BOOST_CHECK_EQUAL(back.amount, bill.amount);
    CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
    ssOut << back;
    BOOST_CHECK(std::vector<unsigned char>(ssOut.begin(), ssOut.end()) == vchNew);
}

BOOST_AUTO_TEST_CASE(bill_ser_house_held_roundtrip)
{
    CBill bill = TestLegacyBill();
    bill.nOwnerHouseID = 3;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << bill;
    const std::vector<unsigned char> vch(ss.begin(), ss.end());

    // A house-held record takes the versioned layout: sentinel, then version.
    uint32_t nFirst = 0;
    memcpy(&nFirst, vch.data(), 4);
    BOOST_CHECK_EQUAL(nFirst, BILL_SER_SENTINEL);
    BOOST_CHECK_EQUAL(vch[4], BILL_SER_VERSION);

    CBill back;
    CDataStream ssIn(vch, SER_NETWORK, PROTOCOL_VERSION);
    ssIn >> back;
    BOOST_CHECK_EQUAL(back.nBillID, bill.nBillID);
    BOOST_CHECK_EQUAL(back.nOwnerHouseID, 3);
    BOOST_CHECK(back.outTitle == bill.outTitle);
    BOOST_CHECK_EQUAL(back.vEndorsement.size(), bill.vEndorsement.size());

    // And it is stable: re-writing the record reproduces the same bytes.
    CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
    ssOut << back;
    BOOST_CHECK(std::vector<unsigned char>(ssOut.begin(), ssOut.end()) == vch);

    // Clearing the owner (what HRETIRE/HCLAIM do) returns the record to the
    // legacy bytes exactly - so a bill that passes through a house leaves no
    // byte-level trace once it is out of the book.
    back.nOwnerHouseID = 0;
    CDataStream ssPlain(SER_NETWORK, PROTOCOL_VERSION);
    ssPlain << back;
    CDataStream ssLegacy(SER_NETWORK, PROTOCOL_VERSION);
    ssLegacy << TestLegacyBill();
    BOOST_CHECK(std::vector<unsigned char>(ssPlain.begin(), ssPlain.end()) ==
                std::vector<unsigned char>(ssLegacy.begin(), ssLegacy.end()));
}

// S1X-25: version 4 carries nEscrowHouseID (the failed house whose escrow took the bill). It round-trips, it alone
// selects the versioned layout, and a version-3 record reads it as 0.
BOOST_AUTO_TEST_CASE(bill_ser_escrow_house_roundtrip)
{
    CBill bill = TestLegacyBill();
    bill.status = BILL_STATUS_DEFAULTED;
    bill.nEscrowHouseID = 7;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << bill;
    const std::vector<unsigned char> vch(ss.begin(), ss.end());
    uint32_t nFirst = 0;
    memcpy(&nFirst, vch.data(), 4);
    BOOST_CHECK_EQUAL(nFirst, BILL_SER_SENTINEL);
    BOOST_CHECK_EQUAL(vch[4], 4);
    CBill back;
    CDataStream ssIn(vch, SER_NETWORK, PROTOCOL_VERSION);
    ssIn >> back;
    BOOST_CHECK_EQUAL(back.nEscrowHouseID, 7u);
    BOOST_CHECK_EQUAL(back.nOwnerHouseID, 0u);
    CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
    ssOut << back;
    BOOST_CHECK(std::vector<unsigned char>(ssOut.begin(), ssOut.end()) == vch);

    // A version-3 record (no trailing field): the same bytes as a v4 one with 0, version byte 3, last 4 bytes dropped.
    CBill held = TestLegacyBill();
    held.nOwnerHouseID = 3;
    CDataStream ss4(SER_NETWORK, PROTOCOL_VERSION);
    ss4 << held;
    std::vector<unsigned char> v3(ss4.begin(), ss4.end());
    v3[4] = 3;
    v3.resize(v3.size() - 4);
    CBill back3;
    CDataStream ssIn3(v3, SER_NETWORK, PROTOCOL_VERSION);
    ssIn3 >> back3;
    BOOST_CHECK_EQUAL(back3.nOwnerHouseID, 3u);
    BOOST_CHECK_EQUAL(back3.nEscrowHouseID, 0u);
}

BOOST_AUTO_TEST_CASE(bill_ser_unknown_version_is_hard_failure)
{
    // Consensus state is never silently defaulted: an unknown version must throw.
    CBill bill = TestLegacyBill();
    bill.nOwnerHouseID = 3;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << bill;
    std::vector<unsigned char> vch(ss.begin(), ss.end());
    vch[4] = BILL_SER_VERSION + 1;           // a FUTURE version
    CBill back;
    CDataStream ssIn(vch, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_THROW(ssIn >> back, std::ios_base::failure);

    vch[4] = 1;                              // and a version the sentinel may not carry
    CBill back2;
    CDataStream ssIn2(vch, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_THROW(ssIn2 >> back2, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(bill_b1_payload_roundtrip_and_exact_decode)
{
    // Every B1 payload must round-trip and must reject trailing bytes: decode is
    // EXACT (DecodeBillPayload discipline).
    BillDiscount d;
    d.nBillID = 7;
    d.nHouseID = 3;
    d.amountPrice = 39500000;
    d.amountFace = 40000000;
    d.nBillMaturityHeight = 8740;
    d.nNoteOutputs = 1;
    d.vUnits.push_back(39500000);
    d.vchCustodyPubKey = std::vector<unsigned char>(33, 0x02);
    d.nExpiryHeight = 172;
    d.nAsOfHeight = 99;
    AttestProof p;
    p.outpoint = COutPoint(uint256S("aa"), 0);
    p.vchPubKey = std::vector<unsigned char>(33, 0x03);
    p.vchSig = std::vector<unsigned char>(70, 0x30);
    d.vReserveProofs.push_back(p);
    d.nPrevMintedUnits = 90000000;
    d.nPrevLoanBookFace = 0;
    d.nPrevLoanWtMatHi = 0;
    d.nPrevLoanWtMatLo = 0;
    d.endorsement.vchFrom = std::vector<unsigned char>(33, 0x02);
    d.endorsement.vchTo = std::vector<unsigned char>(33, 0x02);
    d.endorsement.nAtHeight = 100;
    d.endorsement.vchSig = std::vector<unsigned char>(70, 0x30);
    d.vchSellerSig = std::vector<unsigned char>(70, 0x30);
    d.vApproverIndex.push_back(0);
    d.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << d;
    std::vector<unsigned char> vch(ss.begin(), ss.end());
    BOOST_CHECK(vch.size() <= MAX_BILL_DISCOUNT_PAYLOAD);

    BillDiscount d2;
    BOOST_CHECK(DecodeBillPayload(vch, d2));
    BOOST_CHECK_EQUAL(d2.nBillID, d.nBillID);
    BOOST_CHECK_EQUAL(d2.nHouseID, d.nHouseID);
    BOOST_CHECK_EQUAL(d2.amountPrice, d.amountPrice);
    BOOST_CHECK_EQUAL(d2.amountFace, d.amountFace);
    BOOST_CHECK_EQUAL(d2.nBillMaturityHeight, d.nBillMaturityHeight);
    BOOST_CHECK_EQUAL(d2.vUnits.size(), 1);
    BOOST_CHECK_EQUAL(d2.vUnits[0], d.vUnits[0]);
    BOOST_CHECK_EQUAL(d2.vReserveProofs.size(), 1);
    BOOST_CHECK_EQUAL(d2.nPrevMintedUnits, d.nPrevMintedUnits);
    BOOST_CHECK_EQUAL(d2.endorsement.nAtHeight, 100);
    BOOST_CHECK_EQUAL(d2.vApproverSig.size(), 1);

    // Trailing byte -> reject.
    std::vector<unsigned char> vchTrail = vch;
    vchTrail.push_back(0x00);
    BillDiscount d3;
    BOOST_CHECK(!DecodeBillPayload(vchTrail, d3));
    // Truncated -> reject.
    std::vector<unsigned char> vchShort(vch.begin(), vch.end() - 1);
    BillDiscount d4;
    BOOST_CHECK(!DecodeBillPayload(vchShort, d4));

    // The three smaller payloads.
    BillRecourse r;
    r.nBillID = 7;
    r.vchPayerPubKey = std::vector<unsigned char>(33, 0x02);
    r.vchPrevHolderPubKey = std::vector<unsigned char>(33, 0x03);
    r.vchPayerSig = std::vector<unsigned char>(70, 0x30);
    CDataStream ssR(SER_NETWORK, PROTOCOL_VERSION);
    ssR << r;
    std::vector<unsigned char> vchR(ssR.begin(), ssR.end());
    BillRecourse r2;
    BOOST_CHECK(DecodeBillPayload(vchR, r2));
    BOOST_CHECK(r2.vchPayerPubKey == r.vchPayerPubKey);
    vchR.push_back(0x00);
    BillRecourse r3;
    BOOST_CHECK(!DecodeBillPayload(vchR, r3));

    BillHRetire hr;
    hr.nBillID = 7;
    hr.nOwnerHouseID = 3;
    hr.amountFace = 40000000;
    hr.nBillMaturityHeight = 8740;
    hr.nPrevLoanBookFace = 40000000;
    hr.vchAcceptorSig = std::vector<unsigned char>(70, 0x30);
    CDataStream ssH(SER_NETWORK, PROTOCOL_VERSION);
    ssH << hr;
    BillHRetire hr2;
    BOOST_CHECK(DecodeBillPayload(std::vector<unsigned char>(ssH.begin(), ssH.end()), hr2));
    BOOST_CHECK_EQUAL(hr2.nOwnerHouseID, 3);
    BOOST_CHECK_EQUAL(hr2.amountFace, 40000000);

    BillHClaim hc;
    hc.nBillID = 7;
    hc.nOwnerHouseID = 3;
    hc.amountFace = 40000000;
    hc.nBillMaturityHeight = 8740;
    hc.vApproverIndex.push_back(0);
    hc.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
    CDataStream ssC(SER_NETWORK, PROTOCOL_VERSION);
    ssC << hc;
    BillHClaim hc2;
    BOOST_CHECK(DecodeBillPayload(std::vector<unsigned char>(ssC.begin(), ssC.end()), hc2));
    BOOST_CHECK_EQUAL(hc2.vApproverIndex.size(), 1);

    // The leading-8 slot contract: GetHouseSlotIDs reads the house id straight
    // out of payload bytes 4..8 without decoding, so those bytes MUST be the
    // house id for every house-mutating op.
    uint32_t nSlot = 0;
    memcpy(&nSlot, vch.data() + 4, 4);
    BOOST_CHECK_EQUAL(nSlot, 3U);
    CDataStream ssH2(SER_NETWORK, PROTOCOL_VERSION);
    ssH2 << hr;
    std::vector<unsigned char> vchH(ssH2.begin(), ssH2.end());
    memcpy(&nSlot, vchH.data() + 4, 4);
    BOOST_CHECK_EQUAL(nSlot, 3U);
    memcpy(&nSlot, vchH.data(), 4);
    BOOST_CHECK_EQUAL(nSlot, 7U);   // and bytes 0..4 stay the bill id
}

BOOST_AUTO_TEST_CASE(bill_b1_digests_bind_every_value_field)
{
    // Each digest must change when ANY value field changes, and must NOT change
    // when a signature field changes (signatures land after tx assembly).
    BillDiscount d;
    d.nBillID = 7;
    d.nHouseID = 3;
    d.amountPrice = 39500000;
    d.amountFace = 40000000;
    d.nBillMaturityHeight = 8740;
    d.nNoteOutputs = 1;
    d.vUnits.push_back(39500000);
    d.vchCustodyPubKey = std::vector<unsigned char>(33, 0x02);
    d.nExpiryHeight = 172;
    d.nAsOfHeight = 99;

    const uint256 billID = uint256S("0a0b");
    const uint256 hp = uint256S("1111");
    const uint256 ho = uint256S("2222");
    const uint256 base = BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, d, hp, ho), billID);

    // Same inputs -> same digest.
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, d, hp, ho), billID) == base);

    // Every value field is bound.
    BillDiscount m = d; m.amountPrice += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.amountFace += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nBillMaturityHeight += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nHouseID += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.vUnits[0] += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.vchCustodyPubKey[0] = 0x03;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nExpiryHeight += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nAsOfHeight += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nPrevMintedUnits += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nPrevLoanBookFace += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nPrevLoanWtMatHi += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);
    m = d; m.nPrevLoanWtMatLo += 1;
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) != base);

    // The tx context is bound.
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, d, hp, ho), uint256S("0a0c")) != base);
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, d, uint256S("1112"), ho), billID) != base);
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, d, hp, uint256S("2223")), billID) != base);

    // Signature and approver-index fields are EXCLUDED, so the seller's payload
    // signature survives the house adding its quorum (and vice versa).
    m = d;
    m.vchSellerSig = std::vector<unsigned char>(70, 0x30);
    m.vApproverIndex.push_back(0);
    m.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
    BOOST_CHECK(BillDiscountSigHash(C1BillTx(BILL_OP_DISCOUNT, m, hp, ho), billID) == base);

    // Domain separation: the two B1 digests never collide.
    BillRecourse r;
    r.nBillID = 7;
    r.vchPayerPubKey = std::vector<unsigned char>(33, 0x02);
    r.vchPrevHolderPubKey = std::vector<unsigned char>(33, 0x03);
    const uint256 rbase = BillRecourseSigHash(C1BillTx(BILL_OP_RECOURSE, r, hp, ho), billID);
    BOOST_CHECK(rbase != base);
    BillRecourse rm = r; rm.vchPayerPubKey[0] = 0x03;
    BOOST_CHECK(BillRecourseSigHash(C1BillTx(BILL_OP_RECOURSE, rm, hp, ho), billID) != rbase);
    rm = r; rm.vchPrevHolderPubKey[0] = 0x02;
    BOOST_CHECK(BillRecourseSigHash(C1BillTx(BILL_OP_RECOURSE, rm, hp, ho), billID) != rbase);
    rm = r; rm.vchPayerSig = std::vector<unsigned char>(70, 0x30);
    BOOST_CHECK(BillRecourseSigHash(C1BillTx(BILL_OP_RECOURSE, rm, hp, ho), billID) == rbase);   // sig excluded
}

// ===========================================================================
// B1 T-d2: shape layer (ops 5-8) and input layer
// ===========================================================================

static std::vector<unsigned char> PubBytes(const CKey& key)
{
    const CPubKey pub = key.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

/** A real low-S strict-DER signature. WHICH digest a signature commits to is
 * contextual (T-d3); the shape layer checks encoding only, so every builder
 * here signs one placeholder digest. */
static std::vector<unsigned char> RealSig(const CKey& key)
{
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(key.Sign(uint256S("f00d"), vchSig));
    return vchSig;
}

// The three malleability vectors, all of which a raw-DER payload signature must
// be refused for. Each is a real signature shape that ECDSA verification alone
// would happily accept.
//
//   high-S       - S above n/2; flip it and you get a second valid signature
//                  over the same message, hence a second txid.
//   DER-padded   - R carries an unnecessary leading 0x00.
//   sighash-byte - a script-form signature (trailing SIGHASH_ALL). Payload sigs
//                  are RAW DER; accepting the script form would leave one free
//                  malleable byte on every op.
static std::vector<unsigned char> HighSSig()
{
    // 30 25 02 01 01 02 20 7f ff..ff  -> R = 1, S = 0x7fff..ff (> n/2, < n)
    std::vector<unsigned char> sig = {0x30, 0x25, 0x02, 0x01, 0x01, 0x02, 0x20, 0x7f};
    sig.insert(sig.end(), 31, 0xff);
    return sig;
}

static std::vector<unsigned char> PaddedDERSig()
{
    // 30 07 02 02 00 01 02 01 01  -> R = 0x0001, an over-long encoding of 1
    return {0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01};
}

static std::vector<unsigned char> ScriptFormSig(const CKey& key)
{
    std::vector<unsigned char> sig = RealSig(key);
    sig.push_back(SIGHASH_ALL);
    return sig;
}

BOOST_AUTO_TEST_CASE(bill_strict_der_predicate)
{
    // CheckStrictDER is the raw-DER form of BIP66's encoding rule: same R/S
    // minimality, three length relations shifted by the absent sighash byte.
    CKey key; key.MakeNewKey(true);
    const std::vector<unsigned char> good = RealSig(key);
    BOOST_CHECK(CPubKey::CheckStrictDER(good));
    BOOST_CHECK(CPubKey::CheckLowS(good));          // CKey::Sign normalizes

    // High-S passes the encoding rule and fails low-S: BOTH predicates needed.
    BOOST_CHECK(CPubKey::CheckStrictDER(HighSSig()));
    BOOST_CHECK(!CPubKey::CheckLowS(HighSSig()));

    // Padding fails the encoding rule.
    BOOST_CHECK(!CPubKey::CheckStrictDER(PaddedDERSig()));

    // The script form (trailing sighash byte) is NOT a valid payload signature.
    BOOST_CHECK(!CPubKey::CheckStrictDER(ScriptFormSig(key)));

    // Structural rejects.
    BOOST_CHECK(!CPubKey::CheckStrictDER(std::vector<unsigned char>()));
    BOOST_CHECK(!CPubKey::CheckStrictDER(std::vector<unsigned char>(7, 0x30)));    // under 8
    BOOST_CHECK(!CPubKey::CheckStrictDER(std::vector<unsigned char>(73, 0x30)));   // over 72
    BOOST_CHECK(!CPubKey::CheckStrictDER(std::vector<unsigned char>(70, 0x30)));   // the dummy
    std::vector<unsigned char> truncated = good;
    truncated.pop_back();
    BOOST_CHECK(!CPubKey::CheckStrictDER(truncated));
    std::vector<unsigned char> wrongType = good;
    wrongType[0] = 0x31;
    BOOST_CHECK(!CPubKey::CheckStrictDER(wrongType));
}

struct DiscountKeys {
    CKey seller;
    CKey custody;
    CKey partner;
    CKey proof;
    CKey stranger;
};

static void SetDiscountPayload(CMutableTransaction& mtx, const BillDiscount& d)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << d;
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
}

/** A shape-valid DISCOUNT: house 3 buys bill 7 (face 40 M) at 39.5 M, paying the
 * seller in one freshly minted note coin. The spec's worked example (S 2.6). */
static CMutableTransaction MakeDiscountTx(BillDiscount& dOut, DiscountKeys& k)
{
    k.seller.MakeNewKey(true);
    k.custody.MakeNewKey(true);
    k.partner.MakeNewKey(true);
    k.proof.MakeNewKey(true);
    k.stranger.MakeNewKey(true);

    BillDiscount d;
    d.nBillID = 7;
    d.nHouseID = 3;
    d.amountFace = 40000000;
    d.amountPrice = 39500000;
    d.nBillMaturityHeight = 8740;
    d.nNoteOutputs = 1;
    d.vUnits.push_back(39500000);
    d.vchCustodyPubKey = PubBytes(k.custody);
    d.nExpiryHeight = 172;
    d.nAsOfHeight = 99;

    AttestProof p;
    p.outpoint = COutPoint(uint256S("aa"), 0);
    p.vchPubKey = PubBytes(k.proof);
    p.vchSig = RealSig(k.proof);
    d.vReserveProofs.push_back(p);

    d.endorsement.vchFrom = PubBytes(k.seller);
    d.endorsement.vchTo = PubBytes(k.custody);
    d.endorsement.nAtHeight = 100;
    d.endorsement.vchSig = RealSig(k.seller);
    d.vchSellerSig = RealSig(k.seller);
    d.vApproverIndex.push_back(0);
    d.vApproverSig.push_back(RealSig(k.partner));

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_DISCOUNT;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));       // the title coin
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, BillScriptForPubKey(d.vchCustodyPubKey)));
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, GetScriptForDestination(k.seller.GetPubKey().GetID())));
    SetDiscountPayload(mtx, d);

    dOut = d;
    return mtx;
}

BOOST_AUTO_TEST_CASE(bill_op_range_and_payload_caps)
{
    // The op range widens to 1..11 (v0.2.27: op 9 repay in kind; v0.2.28: ops 10/11 into escrow) and no further.
    BillDiscount d; DiscountKeys k;
    CMutableTransaction mtx = MakeDiscountTx(d, k);
    {
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(mtx), state));
    }
    for (uint8_t op : {(uint8_t)0, (uint8_t)(BILL_OP_TITLE_RELEASE + 1), (uint8_t)255}) {   // S1X-29: op 12 exists now
        CMutableTransaction bad = mtx;
        bad.nBillOp = op;
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(bad), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-op");
    }
    // A v11 coinbase stays banned at every op.
    {
        CMutableTransaction cb = mtx;
        cb.vin.clear();
        cb.vin.push_back(CTxIn(COutPoint(), CScript() << OP_0 << OP_0));
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(cb), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-coinbase");
    }

    // Per-op payload ceilings: 16384 for a discount, 4096 for ops 6-11, and ops
    // 1-4 unchanged at MAX_BILL_BODY_BYTES + 1024.
    {
        CMutableTransaction bad = mtx;
        bad.vchBillPayload.resize(MAX_BILL_DISCOUNT_PAYLOAD + 1, 0x00);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(bad), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-payload-oversize");
    }
    for (uint8_t op : {BILL_OP_RECOURSE, BILL_OP_HRETIRE, BILL_OP_HCLAIM, BILL_OP_HRETIRE_NOTES,
                       BILL_OP_HRETIRE_ESCROW, BILL_OP_HCLAIM_ESCROW}) {
        CMutableTransaction bad = mtx;
        bad.nBillOp = op;
        bad.vchBillPayload.resize(MAX_BILL_OP_PAYLOAD + 1, 0x00);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(bad), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-payload-oversize");
        // One byte under the cap gets past the size gate and dies on the
        // payload decode instead - proving the cap is where it is claimed.
        CMutableTransaction atCap = mtx;
        atCap.nBillOp = op;
        atCap.vchBillPayload.resize(MAX_BILL_OP_PAYLOAD, 0x00);
        CValidationState stateAt;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(atCap), stateAt));
        BOOST_CHECK(stateAt.GetRejectReason() != "bad-bill-payload-oversize");
    }
    {
        // An ISSUE is unaffected by the new caps.
        BillIssue issue; CKey a, b, c;
        CMutableTransaction issueTx = MakeIssueTx(issue, a, b, c);
        issueTx.vchBillPayload.resize(MAX_BILL_BODY_BYTES + 1024, 0x00);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(issueTx), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-issue-payload");
        issueTx.vchBillPayload.resize(MAX_BILL_BODY_BYTES + 1025, 0x00);
        CValidationState state2;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(issueTx), state2));
        BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-bill-payload-oversize");
    }
}

BOOST_AUTO_TEST_CASE(bill_discount_shape_rejections)
{
    BillDiscount base; DiscountKeys k;
    const CMutableTransaction mtxBase = MakeDiscountTx(base, k);
    {
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(mtxBase), state));
    }

    // Every vector must reject for EXACTLY its stated reason: a gate that
    // rejects for the wrong reason is a gate that is not testing what it claims.
    auto reject = [&](std::function<void(BillDiscount&, CMutableTransaction&)> mutate,
                      const std::string& reason) {
        BillDiscount d = base;
        CMutableTransaction mtx = mtxBase;
        mutate(d, mtx);
        SetDiscountPayload(mtx, d);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(mtx), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    };

    // -- ids -------------------------------------------------------------
    reject([](BillDiscount& d, CMutableTransaction&) { d.nBillID = 0; }, "bad-bill-discount-ids");
    reject([](BillDiscount& d, CMutableTransaction&) { d.nHouseID = 0; }, "bad-bill-discount-ids");

    // -- price / face ----------------------------------------------------
    reject([](BillDiscount& d, CMutableTransaction&) { d.amountPrice = 0; },
           "bad-bill-discount-price-range");
    reject([](BillDiscount& d, CMutableTransaction&) { d.amountPrice = -1; },
           "bad-bill-discount-price-range");
    // Above face: booking a bill for more than it will ever pay.
    reject([](BillDiscount& d, CMutableTransaction&) { d.amountPrice = d.amountFace + 1; },
           "bad-bill-discount-price-range");
    reject([](BillDiscount& d, CMutableTransaction&) { d.amountFace = MAX_MONEY + 1; },
           "bad-bill-discount-price-range");
    reject([](BillDiscount& d, CMutableTransaction&) { d.amountFace = 0; },
           "bad-bill-discount-price-range");
    reject([](BillDiscount& d, CMutableTransaction&) { d.nBillMaturityHeight = 0; },
           "bad-bill-discount-maturity");
    // Exactly at face is LEGAL (a discount at par).
    {
        BillDiscount d = base;
        CMutableTransaction mtx = mtxBase;
        d.amountPrice = d.amountFace;
        d.vUnits[0] = (uint64_t)d.amountFace;
        SetDiscountPayload(mtx, d);
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(mtx), state));
    }

    // -- the note leg ----------------------------------------------------
    reject([](BillDiscount& d, CMutableTransaction&) { d.vUnits.clear(); d.nNoteOutputs = 0; },
           "bad-bill-discount-units");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vUnits[0] = 0; },
           "bad-bill-discount-units");
    // Sum below the price: the seller is short-changed relative to what both
    // parties signed.
    reject([](BillDiscount& d, CMutableTransaction&) { d.vUnits[0] -= 1; },
           "bad-bill-discount-units");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vUnits[0] += 1; },
           "bad-bill-discount-units");
    reject([](BillDiscount& d, CMutableTransaction&) { d.nNoteOutputs = 2; },
           "bad-bill-discount-units");
    reject([](BillDiscount& d, CMutableTransaction& mtx) {
               d.vUnits.assign(MAX_NOTE_OUTPUTS + 1, 1);
               d.vUnits[0] = (uint64_t)d.amountPrice - MAX_NOTE_OUTPUTS;
               d.nNoteOutputs = (uint16_t)d.vUnits.size();
               for (size_t i = 1; i < d.vUnits.size(); i++)
                   mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, mtx.vout[1].scriptPubKey));
           }, "bad-bill-discount-units");

    // -- keys ------------------------------------------------------------
    reject([](BillDiscount& d, CMutableTransaction&) { d.vchCustodyPubKey.resize(32); },
           "bad-bill-discount-custody-shape");
    // Right length, invalid prefix: IsFullyValid, not merely a size check.
    reject([](BillDiscount& d, CMutableTransaction&) { d.vchCustodyPubKey.assign(33, 0xff); },
           "bad-bill-discount-custody-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.nExpiryHeight = 0; },
           "bad-bill-discount-no-expiry");
    reject([&](BillDiscount& d, CMutableTransaction&) { d.endorsement.vchTo = PubBytes(k.stranger); },
           "bad-bill-discount-link-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.endorsement.vchFrom.resize(32); },
           "bad-bill-discount-link-shape");
    // Self-purchase: the custody key on BOTH sides of the link would mint notes
    // against paper the house already holds, paying nobody.
    reject([](BillDiscount& d, CMutableTransaction&) { d.endorsement.vchFrom = d.vchCustodyPubKey; },
           "bad-bill-discount-self-purchase");

    // -- approvers -------------------------------------------------------
    reject([](BillDiscount& d, CMutableTransaction&) { d.vApproverIndex.clear(); d.vApproverSig.clear(); },
           "bad-bill-discount-approver-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vApproverSig.clear(); },
           "bad-bill-discount-approver-shape");
    reject([&](BillDiscount& d, CMutableTransaction&) {
               d.vApproverIndex.push_back(0);                       // not ascending
               d.vApproverSig.push_back(RealSig(k.partner));
           }, "bad-bill-discount-approver-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vApproverSig[0].clear(); },
           "bad-bill-discount-approver-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vApproverSig[0].assign(81, 0x30); },
           "bad-bill-discount-approver-shape");

    // -- reserve proofs (R-i7): gram-notes release - the set may be empty (the gold till caps a discount); a proof
    //    present must still be well formed.
    reject([](BillDiscount& d, CMutableTransaction&) {
               d.vReserveProofs.push_back(d.vReserveProofs[0]);     // duplicate outpoint
           }, "bad-bill-discount-proofs-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vReserveProofs[0].outpoint = COutPoint(); },
           "bad-bill-discount-proofs-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vReserveProofs[0].vchPubKey.resize(32); },
           "bad-bill-discount-proofs-shape");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vReserveProofs[0].vchSig.clear(); },
           "bad-bill-discount-proofs-shape");

    // -- born strict: all four signature sites on this op -----------------
    reject([](BillDiscount& d, CMutableTransaction&) { d.vchSellerSig = HighSSig(); },
           "bad-bill-discount-sig-encoding");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vchSellerSig = PaddedDERSig(); },
           "bad-bill-discount-sig-encoding");
    reject([&](BillDiscount& d, CMutableTransaction&) { d.vchSellerSig = ScriptFormSig(k.seller); },
           "bad-bill-discount-sig-encoding");
    reject([](BillDiscount& d, CMutableTransaction&) { d.endorsement.vchSig = HighSSig(); },
           "bad-bill-discount-sig-encoding");
    reject([](BillDiscount& d, CMutableTransaction&) { d.endorsement.vchSig = PaddedDERSig(); },
           "bad-bill-discount-sig-encoding");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vApproverSig[0] = HighSSig(); },
           "bad-bill-discount-sig-encoding");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vApproverSig[0] = PaddedDERSig(); },
           "bad-bill-discount-sig-encoding");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vReserveProofs[0].vchSig = HighSSig(); },
           "bad-bill-discount-sig-encoding");
    reject([](BillDiscount& d, CMutableTransaction&) { d.vReserveProofs[0].vchSig.assign(70, 0x30); },
           "bad-bill-discount-sig-encoding");

    // -- outputs ---------------------------------------------------------
    reject([](BillDiscount&, CMutableTransaction& mtx) { mtx.vout.resize(1); },
           "bad-bill-discount-vout-size");
    reject([](BillDiscount&, CMutableTransaction& mtx) { mtx.vout[0].nValue = BILL_TITLE_VALUE + 1; },
           "bad-bill-discount-title-out");
    // The title must go to the PINNED custody key, not merely to some key.
    reject([&](BillDiscount&, CMutableTransaction& mtx) {
               mtx.vout[0].scriptPubKey = BillScriptForPubKey(PubBytes(k.stranger));
           }, "bad-bill-discount-title-out");
    reject([](BillDiscount&, CMutableTransaction& mtx) { mtx.vout[1].nValue = NOTE_DUST_VALUE + 1; },
           "bad-bill-discount-note-out");
    reject([](BillDiscount&, CMutableTransaction& mtx) { mtx.vout[1].scriptPubKey = CScript() << OP_TRUE; },
           "bad-bill-discount-note-out");

    // Free change past the note leg is fine.
    {
        CMutableTransaction mtx = mtxBase;
        mtx.vout.push_back(CTxOut(49000, CScript() << OP_TRUE));
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(mtx), state));
    }
}

BOOST_AUTO_TEST_CASE(bill_recourse_hretire_hclaim_shape_rejections)
{
    CKey payer, holder, acceptor, partner;
    payer.MakeNewKey(true);
    holder.MakeNewKey(true);
    acceptor.MakeNewKey(true);
    partner.MakeNewKey(true);

    // ---- RECOURSE -------------------------------------------------------
    BillRecourse rBase;
    rBase.nBillID = 7;
    rBase.vchPayerPubKey = PubBytes(payer);
    rBase.vchPrevHolderPubKey = PubBytes(holder);
    rBase.vchPayerSig = RealSig(payer);

    auto recourseTx = [](const BillRecourse& r) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_RECOURSE;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(40000000, BillScriptForPubKey(r.vchPrevHolderPubKey)));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << r;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        return mtx;
    };
    {
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(recourseTx(rBase)), state));
    }
    auto rejectR = [&](std::function<void(BillRecourse&)> mutate, const std::string& reason) {
        BillRecourse r = rBase;
        mutate(r);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(recourseTx(r)), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    };
    rejectR([](BillRecourse& r) { r.nBillID = 0; }, "bad-bill-recourse-fields");
    rejectR([](BillRecourse& r) { r.vchPayerPubKey.resize(32); }, "bad-bill-recourse-fields");
    rejectR([](BillRecourse& r) { r.vchPrevHolderPubKey.assign(33, 0xff); }, "bad-bill-recourse-fields");
    // One key paying itself is not a cure. On a house-held bill this was the
    // rogue-custody-key path that HCLAIM's quorum exists to close; the
    // house-held rejection itself is contextual (T-d3).
    rejectR([](BillRecourse& r) { r.vchPayerPubKey = r.vchPrevHolderPubKey; },
            "bad-bill-recourse-self");
    rejectR([](BillRecourse& r) { r.vchPayerSig = HighSSig(); }, "bad-bill-recourse-sig-encoding");
    rejectR([](BillRecourse& r) { r.vchPayerSig = PaddedDERSig(); }, "bad-bill-recourse-sig-encoding");
    rejectR([&](BillRecourse& r) { r.vchPayerSig = ScriptFormSig(payer); },
            "bad-bill-recourse-sig-encoding");
    rejectR([](BillRecourse& r) { r.vchPayerSig.assign(70, 0x30); }, "bad-bill-recourse-sig-encoding");

    // ---- HRETIRE --------------------------------------------------------
    BillHRetire hrBase;
    hrBase.nBillID = 7;
    hrBase.nOwnerHouseID = 3;
    hrBase.amountFace = 40000000;
    hrBase.nBillMaturityHeight = 8740;
    hrBase.nPrevLoanBookFace = 40000000;
    hrBase.vchAcceptorSig = RealSig(acceptor);

    auto hretireTx = [](const BillHRetire& h) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_HRETIRE;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(h.amountFace, CScript() << OP_TRUE));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << h;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        return mtx;
    };
    {
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(hretireTx(hrBase)), state));
    }
    auto rejectH = [&](std::function<void(BillHRetire&)> mutate, const std::string& reason) {
        BillHRetire h = hrBase;
        mutate(h);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(hretireTx(h)), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    };
    rejectH([](BillHRetire& h) { h.nBillID = 0; }, "bad-bill-hretire-fields");
    // Zero owner house would make the leading-8 slot key meaningless, and the
    // op is defined only on house-held paper.
    rejectH([](BillHRetire& h) { h.nOwnerHouseID = 0; }, "bad-bill-hretire-fields");
    rejectH([](BillHRetire& h) { h.amountFace = 0; }, "bad-bill-hretire-fields");
    rejectH([](BillHRetire& h) { h.amountFace = MAX_MONEY + 1; }, "bad-bill-hretire-fields");
    rejectH([](BillHRetire& h) { h.nBillMaturityHeight = 0; }, "bad-bill-hretire-fields");
    rejectH([](BillHRetire& h) { h.vchAcceptorSig = HighSSig(); }, "bad-bill-hretire-sig-encoding");
    rejectH([](BillHRetire& h) { h.vchAcceptorSig = PaddedDERSig(); }, "bad-bill-hretire-sig-encoding");
    rejectH([&](BillHRetire& h) { h.vchAcceptorSig = ScriptFormSig(acceptor); },
            "bad-bill-hretire-sig-encoding");

    // ---- HCLAIM ---------------------------------------------------------
    BillHClaim hcBase;
    hcBase.nBillID = 7;
    hcBase.nOwnerHouseID = 3;
    hcBase.amountFace = 40000000;
    hcBase.nBillMaturityHeight = 8740;
    hcBase.vApproverIndex.push_back(0);
    hcBase.vApproverSig.push_back(RealSig(partner));

    auto hclaimTx = [](const BillHClaim& h) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_HCLAIM;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0)));
        mtx.vout.push_back(CTxOut(8000000, CScript() << OP_TRUE));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << h;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        return mtx;
    };
    {
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(hclaimTx(hcBase)), state));
    }
    auto rejectC = [&](std::function<void(BillHClaim&)> mutate, const std::string& reason) {
        BillHClaim h = hcBase;
        mutate(h);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(hclaimTx(h)), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    };
    rejectC([](BillHClaim& h) { h.nBillID = 0; }, "bad-bill-hclaim-fields");
    rejectC([](BillHClaim& h) { h.nOwnerHouseID = 0; }, "bad-bill-hclaim-fields");
    rejectC([](BillHClaim& h) { h.amountFace = MAX_MONEY + 1; }, "bad-bill-hclaim-fields");
    rejectC([](BillHClaim& h) { h.nBillMaturityHeight = 0; }, "bad-bill-hclaim-fields");
    // The quorum REPLACES the holder signature here, so an empty approver set is
    // an op with no authority at all behind it.
    rejectC([](BillHClaim& h) { h.vApproverIndex.clear(); h.vApproverSig.clear(); },
            "bad-bill-hclaim-approver-shape");
    rejectC([&](BillHClaim& h) {
                h.vApproverIndex.push_back(0);
                h.vApproverSig.push_back(RealSig(partner));
            }, "bad-bill-hclaim-approver-shape");
    rejectC([](BillHClaim& h) { h.vApproverSig[0] = HighSSig(); }, "bad-bill-hclaim-sig-encoding");
    rejectC([](BillHClaim& h) { h.vApproverSig[0] = PaddedDERSig(); }, "bad-bill-hclaim-sig-encoding");
    rejectC([&](BillHClaim& h) { h.vApproverSig[0] = ScriptFormSig(partner); },
            "bad-bill-hclaim-sig-encoding");
}

// ---------------------------------------------------------------------------
// Input layer (Consensus::CheckTxInputs)
// ---------------------------------------------------------------------------

static COutPoint AddBillCoin(CCoinsViewCache& cache, bool fEscrow, uint32_t nBillID,
                             const uint256& txid, uint32_t n = 0)
{
    Coin coin(CTxOut(BILL_TITLE_VALUE, CScript() << OP_TRUE), 100, false, false, false, uint256());
    coin.SetBill(fEscrow, nBillID);
    COutPoint op(txid, n);
    cache.AddCoin(op, std::move(coin), false);
    return op;
}

static COutPoint AddPlainCoin(CCoinsViewCache& cache, CAmount nValue, const uint256& txid, uint32_t n = 0)
{
    Coin coin(CTxOut(nValue, CScript() << OP_TRUE), 100, false, false, false, uint256());
    COutPoint op(txid, n);
    cache.AddCoin(op, std::move(coin), false);
    return op;
}

/** A minimal v11 tx of `op` carrying `payload`, spending `vin`, paying dust. */
template <typename T>
static CMutableTransaction MakeOpTx(uint8_t op, const T& payload, const std::vector<COutPoint>& vin)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = op;
    for (const COutPoint& o : vin)
        mtx.vin.push_back(CTxIn(o));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    return mtx;
}

BOOST_AUTO_TEST_CASE(bill_b1_input_layer_structure)
{
    BillDiscount d; DiscountKeys k;
    MakeDiscountTx(d, k);                       // payload only; inputs vary below

    BillHRetire hr;
    hr.nBillID = 7; hr.nOwnerHouseID = 3; hr.amountFace = 40000000;
    hr.nBillMaturityHeight = 8740; hr.vchAcceptorSig = RealSig(k.seller);

    BillHClaim hc;
    hc.nBillID = 7; hc.nOwnerHouseID = 3; hc.amountFace = 40000000;
    hc.nBillMaturityHeight = 8740;
    hc.vApproverIndex.push_back(0);
    hc.vApproverSig.push_back(RealSig(k.partner));

    BillRecourse r;
    r.nBillID = 7;
    r.vchPayerPubKey = PubBytes(k.partner);
    r.vchPrevHolderPubKey = PubBytes(k.seller);
    r.vchPayerSig = RealSig(k.partner);

    // -- DISCOUNT: exactly one title, no escrow --------------------------
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint title = AddBillCoin(cache, false, 7, uint256S("aa"));
        const COutPoint fund = AddPlainCoin(cache, 100000, uint256S("bb"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_DISCOUNT, d, {title, fund});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
    }
    {
        // No title at all: a discount that buys nothing but still mints.
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint fund = AddPlainCoin(cache, 100000, uint256S("bb"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_DISCOUNT, d, {fund});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-inputs");
    }
    {
        // The escrow bond is NOT the discount's to take.
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint title = AddBillCoin(cache, false, 7, uint256S("aa"));
        const COutPoint escrow = AddBillCoin(cache, true, 7, uint256S("cc"));
        const COutPoint fund = AddPlainCoin(cache, 100000, uint256S("bb"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_DISCOUNT, d, {title, escrow, fund});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-inputs");
    }
    {
        // Two titles of the SAME bill (double-spend shaped) - and titles of two
        // different bills die earlier still, on the mixed-id guard.
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint t1 = AddBillCoin(cache, false, 7, uint256S("aa"));
        const COutPoint t2 = AddBillCoin(cache, false, 7, uint256S("dd"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_DISCOUNT, d, {t1, t2});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-discount-inputs");
    }
    {
        // The payload's bill id must match the tag on the title actually spent.
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint title = AddBillCoin(cache, false, 9, uint256S("aa"));
        const COutPoint fund = AddPlainCoin(cache, 100000, uint256S("bb"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_DISCOUNT, d, {title, fund});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-input-id-mismatch");
    }

    // -- RECOURSE: no tagged input, and the id-match must stay VACUOUS ----
    {
        // The whole point: a recourse spends plain value only, so nBillIDIn is
        // 0. If the implementation set nBillIDPayload from the payload, the
        // shared id-match below would reject EVERY recourse ever made.
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint fund = AddPlainCoin(cache, 100000, uint256S("bb"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_RECOURSE, r, {fund});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
    }
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint title = AddBillCoin(cache, false, 7, uint256S("aa"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_RECOURSE, r, {title});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-inputs");
    }
    {
        CCoinsView base; CCoinsViewCache cache(&base);
        const COutPoint escrow = AddBillCoin(cache, true, 7, uint256S("cc"));
        CMutableTransaction mtx = MakeOpTx(BILL_OP_RECOURSE, r, {escrow});
        CValidationState state; CAmount fee = 0;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-recourse-inputs");
    }

    // -- HRETIRE / HCLAIM: exactly one escrow, no title -------------------
    for (int i = 0; i < 2; i++) {
        const bool fRetire = (i == 0);
        const uint8_t op = fRetire ? BILL_OP_HRETIRE : BILL_OP_HCLAIM;
        const std::string reason = fRetire ? "bad-bill-hretire-inputs" : "bad-bill-hclaim-inputs";
        {
            CCoinsView base; CCoinsViewCache cache(&base);
            const COutPoint escrow = AddBillCoin(cache, true, 7, uint256S("cc"));
            CMutableTransaction mtx = fRetire ? MakeOpTx(op, hr, {escrow}) : MakeOpTx(op, hc, {escrow});
            CValidationState state; CAmount fee = 0;
            BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
        }
        {
            CCoinsView base; CCoinsViewCache cache(&base);
            const COutPoint fund = AddPlainCoin(cache, 100000, uint256S("bb"));
            CMutableTransaction mtx = fRetire ? MakeOpTx(op, hr, {fund}) : MakeOpTx(op, hc, {fund});
            CValidationState state; CAmount fee = 0;
            BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
        }
        {
            // Taking the title along with the escrow would strip the bill out
            // of the book without the record ever being consulted.
            CCoinsView base; CCoinsViewCache cache(&base);
            const COutPoint escrow = AddBillCoin(cache, true, 7, uint256S("cc"));
            const COutPoint title = AddBillCoin(cache, false, 7, uint256S("aa"));
            CMutableTransaction mtx = fRetire ? MakeOpTx(op, hr, {escrow, title})
                                              : MakeOpTx(op, hc, {escrow, title});
            CValidationState state; CAmount fee = 0;
            BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
        }
        {
            CCoinsView base; CCoinsViewCache cache(&base);
            const COutPoint escrow = AddBillCoin(cache, true, 9, uint256S("cc"));
            CMutableTransaction mtx = fRetire ? MakeOpTx(op, hr, {escrow}) : MakeOpTx(op, hc, {escrow});
            CValidationState state; CAmount fee = 0;
            BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-input-id-mismatch");
        }
    }
}

BOOST_AUTO_TEST_CASE(bill_b1_colored_input_classes)
{
    // B1 widens NO cross-family input guard. Every coloured class is already
    // refused to a v11 transaction by its own family's guard - including fNote,
    // which is why "the consideration is minted, never spent" costs nothing at
    // this layer. Each op is checked against each class.
    BillDiscount d; DiscountKeys k;
    MakeDiscountTx(d, k);

    BillRecourse r;
    r.nBillID = 7;
    r.vchPayerPubKey = PubBytes(k.partner);
    r.vchPrevHolderPubKey = PubBytes(k.seller);
    r.vchPayerSig = RealSig(k.partner);

    BillHRetire hr;
    hr.nBillID = 7; hr.nOwnerHouseID = 3; hr.amountFace = 40000000;
    hr.nBillMaturityHeight = 8740; hr.vchAcceptorSig = RealSig(k.seller);

    enum Colour { COL_NOTE, COL_HOUSE, COL_DEPOSIT, COL_POOL, COL_LP, COL_BOND, COL_ASSET };
    const struct { Colour colour; const char* reason; } kClasses[] = {
        { COL_NOTE,    "bad-txns-spend-note-coin" },
        { COL_HOUSE,   "bad-txns-spend-house-coin" },
        { COL_DEPOSIT, "bad-txns-spend-deposit-coin" },
        { COL_POOL,    "bad-txns-spend-pool-coin" },
        { COL_LP,      "bad-txns-spend-lp-coin" },
        { COL_BOND,    "bad-txns-spend-custody" },
        { COL_ASSET,   "bad-bill-asset-input" },
    };

    for (const auto& cls : kClasses) {
        for (int op = 0; op < 3; op++) {
            CCoinsView base; CCoinsViewCache cache(&base);
            Coin coin(CTxOut(100000, CScript() << OP_TRUE), 100, false, false, false,
                      cls.colour == COL_ASSET ? uint256S("2a") : uint256());
            switch (cls.colour) {
            case COL_NOTE:    coin.SetNote(3, 1000); break;
            case COL_HOUSE:   coin.SetHouseEscrow(3); break;
            case COL_DEPOSIT: coin.SetDeposit(3, 1000, 500, 120000, 50); break;
            case COL_POOL:    coin.SetPoolEscrow(3); break;
            case COL_LP:      coin.SetLpShare(3, 1000); break;
            case COL_BOND:    coin.SetCustody(); break;
            case COL_ASSET:   break;   // nAssetID set through the constructor
            }
            const COutPoint tainted(uint256S("ee"), 0);
            cache.AddCoin(tainted, std::move(coin), false);
            const COutPoint title = AddBillCoin(cache, false, 7, uint256S("aa"));

            CMutableTransaction mtx;
            if (op == 0)      mtx = MakeOpTx(BILL_OP_DISCOUNT, d, {title, tainted});
            else if (op == 1) mtx = MakeOpTx(BILL_OP_RECOURSE, r, {tainted});
            else              mtx = MakeOpTx(BILL_OP_HRETIRE, hr, {tainted});

            CValidationState state; CAmount fee = 0;
            BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 200, fee));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), cls.reason);
        }
    }
}

//
// THE PAYLOAD-LEADING CONTRACT THE PER-BILL MEMPOOL GUARD RESTS ON.
//
// ATMP's per-bill exclusivity guard keys pooled ops 2-8 by a raw memcpy of the
// leading four payload bytes, and keys ISSUE separately on its encrypted body.
// Both halves of that split are assumptions about the wire format, and if
// either drifts the guard does not fail loudly - it silently stops matching,
// and every same-bill brick pair re-opens with no other test able to see it
// (a policy guard that declines to fire looks exactly like one that had
// nothing to do).
//
// So this pins the format itself, in the same raw form the guard reads:
//   - ops 2..8 lead with nBillID as a bare little-endian u32 at bytes 0..4;
//   - ISSUE does NOT, and must never be read that way. Its first field is a
//     length-prefixed vector, so bytes 0..4 are a CompactSize byte followed by
//     ATTACKER-CHOSEN body content. A guard reading them would both miss the
//     real duplicate-ISSUE collision and let a crafted body impersonate any
//     live bill id, censoring every op on it for one transaction fee.
//
// C++11: no generic lambdas, so the serializer is a file-scope template.
template <typename T>
static std::vector<unsigned char> SerPayload(const T& payload)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

BOOST_AUTO_TEST_CASE(bill_payload_leading_id_contract)
{
    auto lead4 = [](const std::vector<unsigned char>& vch) {
        BOOST_REQUIRE(vch.size() >= 4);
        uint32_t n = 0;
        memcpy(&n, vch.data(), 4);
        return n;
    };
    const uint32_t nID = 0x0d15c007;   // distinctive, and not a valid CompactSize lead

    // --- ops 2..8: the leading u32 IS the bill id, byte-exact ---
    {
        BillEndorse e;  e.nBillID = nID;  BOOST_CHECK_EQUAL(lead4(SerPayload(e)),  nID);
        BillRetire  r;  r.nBillID = nID;  BOOST_CHECK_EQUAL(lead4(SerPayload(r)),  nID);
        BillClaim   c;  c.nBillID = nID;  BOOST_CHECK_EQUAL(lead4(SerPayload(c)),  nID);
        BillDiscount d; d.nBillID = nID;  BOOST_CHECK_EQUAL(lead4(SerPayload(d)),  nID);
        BillRecourse rc; rc.nBillID = nID; BOOST_CHECK_EQUAL(lead4(SerPayload(rc)), nID);
        BillHRetire hr; hr.nBillID = nID; BOOST_CHECK_EQUAL(lead4(SerPayload(hr)), nID);
        BillHClaim  hc; hc.nBillID = nID; BOOST_CHECK_EQUAL(lead4(SerPayload(hc)), nID);
    }

    // --- the three house-slot ops additionally carry the house id at 4..8,
    // which is what keeps GetHouseSlotIDs a pure memcpy. Bill payloads are the
    // ONE family where the house id is not at bytes 0..4, so a guard that
    // copies the other families' idiom matches house-id against BILL-id: it
    // blocks the wrong house and lets the real collision through.
    {
        auto lead8second = [](const std::vector<unsigned char>& vch) {
            BOOST_REQUIRE(vch.size() >= 8);
            uint32_t n = 0;
            memcpy(&n, vch.data() + 4, 4);
            return n;
        };
        const uint32_t nHouse = 0xa11cea51;
        BillDiscount d; d.nBillID = nID; d.nHouseID = nHouse;
        BOOST_CHECK_EQUAL(lead8second(SerPayload(d)), nHouse);
        BillHRetire hr; hr.nBillID = nID; hr.nOwnerHouseID = nHouse;
        BOOST_CHECK_EQUAL(lead8second(SerPayload(hr)), nHouse);
        BillHClaim hc; hc.nBillID = nID; hc.nOwnerHouseID = nHouse;
        BOOST_CHECK_EQUAL(lead8second(SerPayload(hc)), nHouse);
    }

    // --- ISSUE: the exception, and the reason the guard branches on it ---
    {
        BillIssue i;
        // A body whose first four bytes spell a live bill id - the crafted case.
        i.vchEncryptedBody.resize(64, 0x00);
        memcpy(i.vchEncryptedBody.data(), &nID, 4);
        const std::vector<unsigned char> vch = SerPayload(i);

        // The payload leads with the body's CompactSize length, NOT an id.
        BOOST_CHECK_EQUAL((unsigned)vch[0], 64u);

        // And the four bytes a naive guard would read are attacker-chosen: they
        // are the body's own leading bytes, shifted one past the length prefix.
        // If this ever equals nID, the guard has been fooled - assert it does
        // NOT, which is the whole point of keying ISSUE on the body instead.
        BOOST_CHECK(lead4(vch) != nID);

        // Two ISSUEs with the SAME body are the collision the guard must catch;
        // differing bodies are not. Identity is the body, not the payload
        // bytes, so this holds even as other fields of the issue differ.
        BillIssue j = i;
        j.amount = 999;                       // a different transaction entirely
        BOOST_CHECK(j.vchEncryptedBody == i.vchEncryptedBody);
        BillIssue k = i;
        k.vchEncryptedBody[7] ^= 0xff;
        BOOST_CHECK(k.vchEncryptedBody != i.vchEncryptedBody);
    }
}

// ===========================================================================
// testing (2026-11-10): UR1-6 (ultra s1 #6; Michael signed it off 2026-11-10, freebank
// docs-local/CONSENSUS_SIGNOFF_2026-11-10.md item 6). nRateNamed - the rate a bill payer names - is in no signature on
// ops 3 RETIRE, 6 RECOURSE, 7 HRETIRE, 9 HRETIRE_NOTES and 10 HRETIRE_ESCROW. An ask can be named high (BoundHouseRate
// takes any rate at or above the 30-day ask), so when the payment has headroom, a relayer or miner can rewrite
// nRateNamed anywhere in [ask, rate the payment covers] under the same signature: same effects, a new txid, and any
// unconfirmed child orphaned. The fix binds nRateNamed into each digest; ops 3 and 7 share BillRetireSigHash, which
// gains it as BillRetireSigHash(billID, nRateNamed, hashOutputs) (agreed with freebankd 2026-11-10).
// FAILS on master a00fb05; passes once the fix lands. UR16RetireDigest uses the new three-argument form when it exists
// and falls back to master's two-argument form, so this file builds before and after the fix.
// ===========================================================================

namespace {
// S1X-17: the retire digest also binds the transaction (BillTxBindingHash) and tells op 3 from op 7.
uint256 UR16RetireDigest(const uint256& billID, uint64_t nRate, const CTransaction& tx, bool fHouseHeld)
{
    return BillRetireSigHash(tx, billID, fHouseHeld);
}

std::vector<unsigned char> UR16Pub(const CKey& key)
{
    const CPubKey pub = key.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

const int UR16_HEIGHT = 5000;

// Runs one bill op against a single bill and (optionally) a single house; returns "" on accept, else the reason.
std::string UR16Run(const CMutableTransaction& mtx, const CBill& bill, const CHouse* pHouse)
{
    const CBill b = bill;
    const CHouse h = pHouse ? *pHouse : CHouse();
    const bool fHouse = pHouse != nullptr;
    std::function<bool(uint32_t, CBill&)> getBill = [b](uint32_t id, CBill& out) {
        if (id != b.nBillID) return false;
        out = b; return true;
    };
    std::function<bool(const uint256&)> haveHash = [b](const uint256& x) { return x == b.billID; };
    std::function<bool(uint32_t, CHouse&)> getHouse = [h, fHouse](uint32_t id, CHouse& out) {
        if (!fHouse || id != h.nHouseID) return false;
        out = h; return true;
    };
    std::function<bool(const COutPoint&, Coin&)> noCoin = [](const COutPoint&, Coin&) { return false; };
    std::function<bool(uint32_t, uint256&)> noBlock = [](uint32_t, uint256&) { return false; };
    CValidationState state;
    CBill billOut;
    CHouse houseOut;
    bool fHouseChanged = false;
    if (CheckBillOperation(CTransaction(mtx), state, UR16_HEIGHT, 100000, getBill, haveHash, getHouse, noCoin, noBlock,
                           billOut, houseOut, fHouseChanged, false))
        return std::string();
    return state.GetRejectReason().empty() ? std::string("(refused, no reason)") : state.GetRejectReason();
}

template <typename T>
CMutableTransaction UR16Tx(uint8_t nOp, const T& payload, const std::vector<unsigned char>& vchPayee, CAmount nPaid)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = nOp;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("16"), 0)));
    mtx.vout.push_back(CTxOut(nPaid, BillScriptForPubKey(vchPayee)));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.vchBillPayload.assign(ss.begin(), ss.end());
    return mtx;
}
} // namespace

// The digests themselves: two payloads differing only in nRateNamed must not share a digest.
BOOST_AUTO_TEST_CASE(ur1_6_bill_digests_bind_nratenamed)
{
    const uint256 billID = uint256S("0a0b");
    const uint256 hp = uint256S("1111");
    const uint256 ho = uint256S("2222");

    // Stage 0 C1: nRateNamed is a payload field, bound through the binding form.
    BillRetire rt;
    rt.nBillID = 7;
    rt.nRateNamed = 1000;
    BillRetire rt2 = rt;
    rt2.nRateNamed = 1400;
    BOOST_CHECK_MESSAGE(BillRetireSigHash(C1BillTx(BILL_OP_RETIRE, rt, hp, ho), billID, false) !=
                        BillRetireSigHash(C1BillTx(BILL_OP_RETIRE, rt2, hp, ho), billID, false),
                        "UR1-6: the retire digest that ops 3 RETIRE and 7 HRETIRE sign does not bind nRateNamed");

    BillRecourse r;
    r.nBillID = 7;
    r.vchPayerPubKey = std::vector<unsigned char>(33, 0x02);
    r.vchPrevHolderPubKey = std::vector<unsigned char>(33, 0x03);
    r.nRateNamed = 1000;
    BillRecourse r2 = r;
    r2.nRateNamed = 1400;
    BOOST_CHECK_MESSAGE(BillRecourseSigHash(C1BillTx(BILL_OP_RECOURSE, r, hp, ho), billID) != BillRecourseSigHash(C1BillTx(BILL_OP_RECOURSE, r2, hp, ho), billID),
                        "UR1-6: op 6 RECOURSE's digest does not bind nRateNamed");

    BillHRetireNotes hn;
    hn.nBillID = 7;
    hn.nOwnerHouseID = 3;
    hn.amountFace = 10000;
    hn.nBillMaturityHeight = 8000;
    hn.nUnitsBurned = 4000;
    hn.nRateNamed = 1000;
    BillHRetireNotes hn2 = hn;
    hn2.nRateNamed = 1400;
    BOOST_CHECK_MESSAGE(BillHRetireNotesSigHash(C1BillTx(BILL_OP_HRETIRE_NOTES, hn, hp, ho), billID) != BillHRetireNotesSigHash(C1BillTx(BILL_OP_HRETIRE_NOTES, hn2, hp, ho), billID),
                        "UR1-6: op 9 HRETIRE_NOTES's digest does not bind nRateNamed");
    BOOST_CHECK_MESSAGE(BillHRetireEscrowSigHash(C1BillTx(BILL_OP_HRETIRE_ESCROW, hn, hp, ho), billID) != BillHRetireEscrowSigHash(C1BillTx(BILL_OP_HRETIRE_ESCROW, hn2, hp, ho), billID),
                        "UR1-6: op 10 HRETIRE_ESCROW's digest does not bind nRateNamed");
}

// The malleability itself, through the contextual check: op 3 (holder-held) and op 7 (house-held). The rate is 1000
// sats per gram in unit tests; the payer pays 15,000 sats for a 10,000 mg face, which covers any named rate up to 1,500.
BOOST_AUTO_TEST_CASE(ur1_6_retire_rate_rewrite_breaks_the_signature)
{
    CKey keyAcceptor, keyHolder;
    keyAcceptor.MakeNewKey(true);
    keyHolder.MakeNewKey(true);
    const CAmount nFaceMg = 10000;
    const CAmount nPaid = 15000;

    // ---- op 3 RETIRE: a holder-held bill (no owner house), repaid at the reference house's 30-day ask.
    {
        CBill bill;
        bill.nBillID = 1;
        bill.billID = uint256S("ab01");
        bill.amount = nFaceMg;
        bill.nIssuedHeight = 4000;
        bill.nMaturityHeight = 8000;
        bill.vchAcceptorPubKey = UR16Pub(keyAcceptor);
        bill.vchHolderPubKey = UR16Pub(keyHolder);
        bill.nRefHouseID = 5;
        bill.nOwnerHouseID = 0;
        bill.status = BILL_STATUS_ACTIVE;

        BillRetire retire;
        retire.nBillID = 1;
        retire.nRateNamed = 1000;
        CMutableTransaction mtx = UR16Tx(BILL_OP_RETIRE, retire, bill.vchHolderPubKey, nPaid);
        BOOST_REQUIRE(keyAcceptor.Sign(UR16RetireDigest(bill.billID, 1000, CTransaction(mtx), false),
                                       retire.vchAcceptorSig));
        mtx = UR16Tx(BILL_OP_RETIRE, retire, bill.vchHolderPubKey, nPaid);
        const std::string strHonest = UR16Run(mtx, bill, nullptr);
        BOOST_CHECK_MESSAGE(strHonest.empty(), "UR1-6 control: the signed op 3 RETIRE was refused: " + strHonest);

        BillRetire rewritten = retire;   // a third party rewrites the rate, keeping the acceptor's signature
        rewritten.nRateNamed = 1400;
        const CMutableTransaction mtx2 = UR16Tx(BILL_OP_RETIRE, rewritten, bill.vchHolderPubKey, nPaid);
        BOOST_CHECK(CTransaction(mtx2).GetHash() != CTransaction(mtx).GetHash());
        const std::string strRewritten = UR16Run(mtx2, bill, nullptr);
        BOOST_CHECK_MESSAGE(strRewritten == "bad-bill-retire-sig",
                            "UR1-6: op 3 RETIRE with nRateNamed rewritten 1000 -> 1400 under the acceptor's signature "
                            "was " + (strRewritten.empty() ? std::string("ACCEPTED (a new txid, no new signature)")
                                                           : "refused for another reason: " + strRewritten));

        // A payer who really names 1400 and signs it is still accepted (1400 >= the ask, and the payment covers it).
        BillRetire named = rewritten;
        named.vchAcceptorSig.clear();
        CMutableTransaction mtx3 = UR16Tx(BILL_OP_RETIRE, named, bill.vchHolderPubKey, nPaid);
        BOOST_REQUIRE(keyAcceptor.Sign(UR16RetireDigest(bill.billID, 1400, CTransaction(mtx3), false),
                                       named.vchAcceptorSig));
        mtx3 = UR16Tx(BILL_OP_RETIRE, named, bill.vchHolderPubKey, nPaid);
        const std::string strNamed = UR16Run(mtx3, bill, nullptr);
        BOOST_CHECK_MESSAGE(strNamed.empty(), "UR1-6 control: op 3 RETIRE signed at 1400 was refused: " + strNamed);
    }

    // ---- op 7 HRETIRE: the same bill held by house 3 (its custody key is the holder), repaid at the house's ask.
    {
        CHouse house;
        house.nHouseID = 3;
        house.status = HOUSE_STATUS_OPEN;
        house.nLoanBookFace = (uint64_t)nFaceMg;
        house.SetLoanWtMaturity((unsigned __int128)(uint64_t)nFaceMg * 8000u);

        CBill bill;
        bill.nBillID = 2;
        bill.billID = uint256S("ab02");
        bill.amount = nFaceMg;
        bill.nIssuedHeight = 4000;
        bill.nMaturityHeight = 8000;
        bill.vchAcceptorPubKey = UR16Pub(keyAcceptor);
        bill.vchHolderPubKey = UR16Pub(keyHolder);   // the custody key the discount pinned
        bill.nRefHouseID = 3;
        bill.nOwnerHouseID = 3;
        bill.status = BILL_STATUS_ACTIVE;

        BillHRetire hr;
        hr.nBillID = 2;
        hr.nOwnerHouseID = 3;
        hr.amountFace = nFaceMg;
        hr.nBillMaturityHeight = 8000;
        hr.nPrevLoanBookFace = house.nLoanBookFace;
        hr.nPrevLoanWtMatHi = house.nLoanWtMatHi;
        hr.nPrevLoanWtMatLo = house.nLoanWtMatLo;
        hr.nRateNamed = 1000;
        CMutableTransaction mtx = UR16Tx(BILL_OP_HRETIRE, hr, bill.vchHolderPubKey, nPaid);
        BOOST_REQUIRE(keyAcceptor.Sign(UR16RetireDigest(bill.billID, 1000, CTransaction(mtx), true),
                                       hr.vchAcceptorSig));
        mtx = UR16Tx(BILL_OP_HRETIRE, hr, bill.vchHolderPubKey, nPaid);
        const std::string strHonest = UR16Run(mtx, bill, &house);
        BOOST_CHECK_MESSAGE(strHonest.empty(), "UR1-6 control: the signed op 7 HRETIRE was refused: " + strHonest);

        BillHRetire rewritten = hr;
        rewritten.nRateNamed = 1400;
        const CMutableTransaction mtx2 = UR16Tx(BILL_OP_HRETIRE, rewritten, bill.vchHolderPubKey, nPaid);
        const std::string strRewritten = UR16Run(mtx2, bill, &house);
        BOOST_CHECK_MESSAGE(strRewritten == "bad-bill-hretire-sig",
                            "UR1-6: op 7 HRETIRE with nRateNamed rewritten 1000 -> 1400 under the acceptor's signature "
                            "was " + (strRewritten.empty() ? std::string("ACCEPTED (a new txid, no new signature)")
                                                           : "refused for another reason: " + strRewritten));
    }
}

// ===========================================================================
// testing (2026-11-11): SA-N2 (security stage A, Medium). Operator's decision D-2026-11-11-2 rule 1 (Michael, "Yes, all
// three (Recommended)", design session): a RETIRE of a privately held bill (op 3) pays the holder at least
// max(face at the reference house's 30-day highest ask, the bill's bond) - the floor RECOURSE already uses. Today it
// pays only the face at the reference's ask, so a drawee who controls the reference house posts a first rate of 1 sat
// per gram (a first post has no bound) and retires the bill for almost nothing - and its bond comes back to it too.
// FAILS on master 33f2e72; passes once freebankd's commit for the three rules lands. The refusal is the existing
// "bad-bill-retire-payment" (the rule is the payment floor of that check).
// ===========================================================================
namespace {
// One op 3 RETIRE of a 10 g holder-held bill bonded nEscrow sats, naming nRate, paying the holder nPaid; "" = accepted.
std::string SAN2Retire(CAmount nEscrow, uint64_t nRate, CAmount nPaid)
{
    static CKey keyAcceptor, keyHolder;
    if (!keyAcceptor.IsValid()) { keyAcceptor.MakeNewKey(true); keyHolder.MakeNewKey(true); }
    CBill bill;
    bill.nBillID = 1;
    bill.billID = uint256S("a2b1");
    bill.amount = 10000;                       // 10 g of face (mg)
    bill.amountEscrow = nEscrow;               // the bond the drawee posted (sats)
    bill.nIssuedHeight = 4000;
    bill.nMaturityHeight = 8000;
    bill.vchAcceptorPubKey = UR16Pub(keyAcceptor);
    bill.vchHolderPubKey = UR16Pub(keyHolder);
    bill.nRefHouseID = 5;
    bill.nOwnerHouseID = 0;
    bill.status = BILL_STATUS_ACTIVE;
    BillRetire retire;
    retire.nBillID = 1;
    retire.nRateNamed = nRate;
    CMutableTransaction mtx = UR16Tx(BILL_OP_RETIRE, retire, bill.vchHolderPubKey, nPaid);
    BOOST_REQUIRE(keyAcceptor.Sign(UR16RetireDigest(bill.billID, nRate, CTransaction(mtx), false),
                                   retire.vchAcceptorSig));
    mtx = UR16Tx(BILL_OP_RETIRE, retire, bill.vchHolderPubKey, nPaid);
    return UR16Run(mtx, bill, nullptr);
}
std::string SAN2Said(const std::string& r) { return r.empty() ? std::string("ACCEPTED") : "refused (" + r + ")"; }
} // namespace

// At the suite's rate (every house 1000 sats per gram), the bill's face is 10,000 sats.
BOOST_AUTO_TEST_CASE(sa_n2_retire_pays_at_least_the_bond)
{
    // The bond above the face's value: the bond is the floor.
    std::string r = SAN2Retire(50000, 1000, 50000);
    BOOST_CHECK_MESSAGE(r.empty(), "SA-N2 control: a RETIRE paying the 50,000-sat bond was " + SAN2Said(r));
    r = SAN2Retire(50000, 1000, 49999);
    BOOST_CHECK_MESSAGE(r == "bad-bill-retire-payment",
                        "SA-N2: a RETIRE paying 49,999 sats on a bill bonded 50,000 (face 10,000 sats at the ask) was " +
                        SAN2Said(r));
    r = SAN2Retire(50000, 1000, 10000);
    BOOST_CHECK_MESSAGE(r == "bad-bill-retire-payment",
                        "SA-N2: a RETIRE paying only the face (10,000 sats) on a bill bonded 50,000 was " + SAN2Said(r));
    // The bond below the face's value: the face at the 30-day ask stays the floor (unchanged).
    r = SAN2Retire(4000, 1000, 10000);
    BOOST_CHECK_MESSAGE(r.empty(), "SA-N2 control: a RETIRE paying the face on a bill bonded 4,000 was " + SAN2Said(r));
    r = SAN2Retire(4000, 1000, 9999);
    BOOST_CHECK_MESSAGE(r == "bad-bill-retire-payment",
                        "SA-N2 control: a RETIRE paying under the face on a bill bonded 4,000 was " + SAN2Said(r));
}

// The attack itself: the reference house is the drawee's own, new, with a first rate of bid = ask = 1 sat per gram.
// Its 30-day high ask is 1, so the face is 10 sats. Paying 10 sats must not discharge a bill bonded 50,000.
BOOST_AUTO_TEST_CASE(sa_n2_rigged_reference_house_gains_nothing)
{
    const int64_t DAYSECS = RATE_DAY_SECONDS;
    Consensus::GramParams gp;
    CUnitsView units(nullptr);
    std::string strReject;
    const int64_t T = 400 * DAYSECS;
    AdvanceChainClock(units, UR16_HEIGHT - 20, T - 2000, gp);
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, 5, 1, 1, UR16_HEIGHT - 10, T - 1000, gp, strReject),
                          "SA-N2 setup: the reference house's first post of 1 sat per gram was refused: " + strReject);
    AdvanceChainClock(units, UR16_HEIGHT - 1, T, gp);
    const uint64_t nOverridePrev = g_nHouseRateTestOverride;
    g_nHouseRateTestOverride = 0;              // the reference's real (rigged) rate
    {
        UnitsCheckScope scope(&units);
        uint64_t nMaxBid = 0, nMaxAsk = 0;
        BOOST_REQUIRE(HouseRateMaxForChecks(5, UR16_HEIGHT, 30, nMaxBid, nMaxAsk));
        BOOST_REQUIRE_EQUAL(nMaxAsk, 1u);      // the 30-day high ask is the rigged 1 sat per gram
        std::string r = SAN2Retire(50000, 1, 10);
        BOOST_CHECK_MESSAGE(r == "bad-bill-retire-payment",
                            "SA-N2: with the drawee's own reference house at 1 sat per gram, a RETIRE paying 10 sats on "
                            "a bill bonded 50,000 was " + SAN2Said(r) + " (the drawee discharges for nothing and keeps "
                            "its bond)");
        r = SAN2Retire(50000, 1, 50000);
        BOOST_CHECK_MESSAGE(r.empty(), "SA-N2 control: at the rigged rate, a RETIRE paying the bond was " + SAN2Said(r));
    }
    g_nHouseRateTestOverride = nOverridePrev;
}

// ===========================================================================
// testing (2026-11-20): S1X-1 (external review of s1 at v1.2.2, GPT-6.1; security: Medium, a launch blocker under
// D-2026-11-19-2). A house-held bill repays at the OWNER house's 30-day highest ask (op 7 HRETIRE),
// and D-2026-11-11-2 rule 1's floor covers op 3 only. DISCOUNT needs the holder and the buying house's quorum, not the
// drawee, and a house's first rate post has no rise bound. So the holder discounts the bill into its own puppet house
// with a first ask far above the reference house's, and the drawee must pay that ask or default.
// These cases encode freebankd's proposed rule (2026-11-20, with design; consensus, so it needs Michael's yes before it
// is final): HRETIRE pays what op 3 pays, max(face x the REFERENCE house's 30-day highest ask, the bond). If the agreed
// rule differs, these assertions change with it. FAIL on master 457a538 (HRETIRE at the reference price is refused
// "bad-bill-hretire-rate"); pass once the fix lands.
// ===========================================================================
namespace {
const uint32_t S1X1_REF = 5;      // the reference house the drawee named at ISSUE
const uint32_t S1X1_PUPPET = 3;   // the holder's own house, which bought the bill at DISCOUNT
// One op 7 HRETIRE of a 10 g bill bonded nEscrow sats, held by the puppet, naming nRate, paying the custody key nPaid.
std::string S1X1HRetire(CAmount nEscrow, uint64_t nRate, CAmount nPaid)
{
    static CKey keyAcceptor, keyCustody;
    if (!keyAcceptor.IsValid()) { keyAcceptor.MakeNewKey(true); keyCustody.MakeNewKey(true); }
    const CAmount nFaceMg = 10000;
    CHouse house;
    house.nHouseID = S1X1_PUPPET;
    house.status = HOUSE_STATUS_OPEN;
    house.nLoanBookFace = (uint64_t)nFaceMg;
    house.SetLoanWtMaturity((unsigned __int128)(uint64_t)nFaceMg * 8000u);
    CBill bill;
    bill.nBillID = 3;
    bill.billID = uint256S("a3c1");
    bill.amount = nFaceMg;
    bill.amountEscrow = nEscrow;
    bill.nIssuedHeight = 4000;
    bill.nMaturityHeight = 8000;
    bill.vchAcceptorPubKey = UR16Pub(keyAcceptor);
    bill.vchHolderPubKey = UR16Pub(keyCustody);   // the custody key the discount pinned
    bill.nRefHouseID = S1X1_REF;
    bill.nOwnerHouseID = S1X1_PUPPET;
    bill.status = BILL_STATUS_ACTIVE;
    BillHRetire hr;
    hr.nBillID = bill.nBillID;
    hr.nOwnerHouseID = S1X1_PUPPET;
    hr.amountFace = nFaceMg;
    hr.nBillMaturityHeight = 8000;
    hr.nPrevLoanBookFace = house.nLoanBookFace;
    hr.nPrevLoanWtMatHi = house.nLoanWtMatHi;
    hr.nPrevLoanWtMatLo = house.nLoanWtMatLo;
    hr.nRateNamed = nRate;
    CMutableTransaction mtx = UR16Tx(BILL_OP_HRETIRE, hr, bill.vchHolderPubKey, nPaid);
    BOOST_REQUIRE(keyAcceptor.Sign(UR16RetireDigest(bill.billID, nRate, CTransaction(mtx), true),
                                   hr.vchAcceptorSig));
    mtx = UR16Tx(BILL_OP_HRETIRE, hr, bill.vchHolderPubKey, nPaid);
    return UR16Run(mtx, bill, &house);
}
// A units view where the reference house posts nRefRate and the puppet nPuppetRate (bid = ask, first posts).
void S1X1Rates(CUnitsView& units, uint64_t nRefRate, uint64_t nPuppetRate)
{
    const int64_t T = 400 * RATE_DAY_SECONDS;
    Consensus::GramParams gp;
    std::string strReject;
    AdvanceChainClock(units, UR16_HEIGHT - 20, T - 2000, gp);
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, S1X1_REF, nRefRate, nRefRate, UR16_HEIGHT - 10, T - 1000, gp, strReject),
                          "S1X-1 setup: the reference house's post was refused: " + strReject);
    BOOST_REQUIRE_MESSAGE(ApplyHouseRatePost(units, S1X1_PUPPET, nPuppetRate, nPuppetRate, UR16_HEIGHT - 10, T - 1000, gp,
                                             strReject),
                          "S1X-1 setup: the puppet's first post was refused: " + strReject);
    AdvanceChainClock(units, UR16_HEIGHT - 1, T, gp);
}
} // namespace

// The attack: reference 1,000 sats per gram (the face is 10,000 sats); the puppet's first post 1,000,000 (1000x, no
// rise bound on a first post). The drawee repays at the reference price, never at the puppet's.
BOOST_AUTO_TEST_CASE(s1x_1_puppet_owner_house_cannot_set_the_drawee_price)
{
    CUnitsView units(nullptr);
    S1X1Rates(units, 1000, 1000000);
    const uint64_t nOverridePrev = g_nHouseRateTestOverride;
    g_nHouseRateTestOverride = 0;   // the houses' real rates
    {
        UnitsCheckScope scope(&units);
        uint64_t nBid = 0, nAsk = 0;
        BOOST_REQUIRE(HouseRateMaxForChecks(S1X1_PUPPET, UR16_HEIGHT, 30, nBid, nAsk));
        BOOST_REQUIRE_EQUAL(nAsk, 1000000u);   // the puppet's first post is in effect, unbounded
        // Bond below the face's value at the reference: the face at the reference ask is what the drawee pays.
        std::string r = S1X1HRetire(5000, 1000, 10000);
        BOOST_CHECK_MESSAGE(r.empty(), "S1X-1: an HRETIRE paying the face at the reference house's ask (10,000 sats) on a "
                                       "bill held by a puppet house posting 1000x was " + SAN2Said(r) +
                                       " (the drawee must pay the puppet's ask, 10,000,000 sats, or default)");
        r = S1X1HRetire(5000, 1000, 9999);
        BOOST_CHECK_MESSAGE(!r.empty(), "S1X-1 control: an HRETIRE paying under the face at the reference ask was " +
                                        SAN2Said(r));
        // Bond above the face's value: the bond is the floor, as for op 3 (rule 1).
        r = S1X1HRetire(50000, 1000, 50000);
        BOOST_CHECK_MESSAGE(r.empty(), "S1X-1: an HRETIRE paying the 50,000-sat bond (above the face at the reference "
                                       "ask) on a puppet-held bill was " + SAN2Said(r));
        r = S1X1HRetire(50000, 1000, 49999);
        BOOST_CHECK_MESSAGE(!r.empty(), "S1X-1 control: an HRETIRE paying under the bond was " + SAN2Said(r));
    }
    g_nHouseRateTestOverride = nOverridePrev;
}

// The other direction stays shut: a drawee who rigs the REFERENCE house at 1 sat per gram still repays at least the
// bond on a house-held bill (the owner house here is honest, 1,000).
BOOST_AUTO_TEST_CASE(s1x_1_rigged_reference_still_pays_the_bond_on_hretire)
{
    CUnitsView units(nullptr);
    S1X1Rates(units, 1, 1000);
    const uint64_t nOverridePrev = g_nHouseRateTestOverride;
    g_nHouseRateTestOverride = 0;
    {
        UnitsCheckScope scope(&units);
        std::string r = S1X1HRetire(50000, 1, 10);
        BOOST_CHECK_MESSAGE(!r.empty(), "S1X-1: with the reference rigged at 1 sat per gram, an HRETIRE paying 10 sats on "
                                        "a bill bonded 50,000 was " + SAN2Said(r));
        r = S1X1HRetire(50000, 1000, 50000);
        BOOST_CHECK_MESSAGE(r.empty(), "S1X-1 control: an HRETIRE naming the owner's ask and paying the bond was " +
                                       SAN2Said(r));
    }
    g_nHouseRateTestOverride = nOverridePrev;
}


// S1X-27 (Claude max run 3 #20; security 11-25: Medium): the pool's identity index replaces the scan that decoded every
// pooled ISSUE for each incoming one. The keys must equal for the same bill (a re-wrapped ISSUE, two ops on one id) and
// differ across bills and across kinds; the pool must hold a key exactly while a tx carrying it is pooled.
BOOST_AUTO_TEST_CASE(s1x_27_pooled_identity_keys_bills)
{
    BillIssue issue;
    CKey kD, kA, kH;
    const CMutableTransaction mtxIssue = MakeIssueTx(issue, kD, kA, kH);
    std::vector<uint256> vA, vB;
    PooledIdentityKeys(CTransaction(mtxIssue), vA);
    BOOST_REQUIRE_EQUAL(vA.size(), 1u);

    // A re-wrap (other funding, other nLockTime) of the same signed payload: the same key.
    CMutableTransaction mtxRewrap = mtxIssue;
    mtxRewrap.vin[0].prevout = COutPoint(uint256S("02"), 1);
    mtxRewrap.nLockTime = 7;
    PooledIdentityKeys(CTransaction(mtxRewrap), vB);
    BOOST_REQUIRE_EQUAL(vB.size(), 1u);
    BOOST_CHECK(vA[0] == vB[0]);

    // Another body: another key.
    BillIssue issue2 = issue;
    issue2.vchEncryptedBody.push_back('x');
    CMutableTransaction mtxOther = mtxIssue;
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << issue2;
        mtxOther.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
    }
    PooledIdentityKeys(CTransaction(mtxOther), vB);
    BOOST_REQUIRE_EQUAL(vB.size(), 1u);
    BOOST_CHECK(vA[0] != vB[0]);

    // Ops 2-8 key by the raw 4 leading bytes: equal ids share a key, other ids don't, and no op key equals an ISSUE's.
    auto fnOp = [](uint8_t nOp, uint32_t nBillID) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = nOp;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << nBillID << std::string("rest of the payload");
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("03"), 0)));
        return mtx;
    };
    std::vector<uint256> vOp1, vOp2, vOp3;
    PooledIdentityKeys(CTransaction(fnOp(BILL_OP_ENDORSE, 42)), vOp1);
    PooledIdentityKeys(CTransaction(fnOp(BILL_OP_RETIRE, 42)), vOp2);
    PooledIdentityKeys(CTransaction(fnOp(BILL_OP_RETIRE, 43)), vOp3);
    BOOST_REQUIRE_EQUAL(vOp1.size(), 1u);
    BOOST_REQUIRE_EQUAL(vOp2.size(), 1u);
    BOOST_REQUIRE_EQUAL(vOp3.size(), 1u);
    BOOST_CHECK(vOp1[0] == vOp2[0]);
    BOOST_CHECK(vOp1[0] != vOp3[0]);
    BOOST_CHECK(vOp1[0] != vA[0]);

    // The pool holds a key exactly while a tx carrying it is pooled (counted).
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    const CTransaction txIssue(mtxIssue), txRewrap(mtxRewrap);
    BOOST_CHECK(!pool.HaveIdentityKey(vA));
    {
        LOCK(pool.cs);
        pool.addUnchecked(txIssue.GetHash(), entry.FromTx(txIssue));
    }
    BOOST_CHECK(pool.HaveIdentityKey(vA));
    std::vector<uint256> vRe;
    PooledIdentityKeys(txRewrap, vRe);
    BOOST_CHECK(pool.HaveIdentityKey(vRe));   // the re-wrap is refused as bill-op-in-mempool
    BOOST_CHECK(!pool.HaveIdentityKey(vOp1));
    pool.removeRecursive(txIssue);
    BOOST_CHECK(!pool.HaveIdentityKey(vA));
}


// S1X-29 (security: Low; Michael 11-25 yes): op 12 TITLE_RELEASE. Shape: the bill id and plain outputs only (no escrow
// shape). Inputs: exactly one title, of the payload's bill. Context: the bill has ended and no failed house's escrow
// took it.
BOOST_AUTO_TEST_CASE(s1x_29_title_release)
{
    BillTitleRelease rel;
    rel.nBillID = 7;
    auto fnTx = [&](const CScript& scriptOut) {
        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_BILL_VERSION;
        mtx.nBillOp = BILL_OP_TITLE_RELEASE;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << rel;
        mtx.vchBillPayload = std::vector<unsigned char>(ss.begin(), ss.end());
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0c"), 0)));
        mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE - 1000, scriptOut));
        return mtx;
    };
    CKey key;
    key.MakeNewKey(true);
    const CScript scriptPlain = GetScriptForDestination(key.GetPubKey().GetID());
    {
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(fnTx(scriptPlain)), state));
    }
    {
        CValidationState state;   // an escrow-shaped output would enter the UTXO set untagged
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(fnTx(BillEscrowScript(uint256S("0d")))), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-titlerelease-stray-escrow");
    }
    {
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(fnTx(HouseEscrowScript(uint256S("0e")))), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-titlerelease-stray-escrow");
    }

    // Context, through CheckBillOperation: a bill record served by id.
    CBill bill;
    bill.nBillID = 7;
    bill.billID = uint256S("0f");
    auto fnRun = [&](const CBill& b) {
        auto fnGetBill = [&](uint32_t nID, CBill& out) { if (nID != b.nBillID) return false; out = b; return true; };
        auto fnHaveBillHash = [](const uint256&) { return false; };
        auto fnGetHouse = [](uint32_t, CHouse&) { return false; };
        auto fnGetCoin = [](const COutPoint&, Coin&) { return false; };
        auto fnGetBlockHash = [](uint32_t, uint256&) { return false; };
        CBill billOut;
        CHouse houseOut;
        bool fHouseChanged = false;
        CValidationState state;
        const bool fOk = CheckBillOperation(CTransaction(fnTx(scriptPlain)), state, 1000, 1000, fnGetBill, fnHaveBillHash,
                                            fnGetHouse, fnGetCoin, fnGetBlockHash, billOut, houseOut, fHouseChanged, false);
        BOOST_CHECK(!fHouseChanged);
        return fOk ? std::string() : state.GetRejectReason();
    };
    bill.status = BILL_STATUS_ACTIVE;
    BOOST_CHECK_EQUAL(fnRun(bill), "bad-bill-titlerelease-active");
    bill.status = BILL_STATUS_RETIRED;
    BOOST_CHECK_EQUAL(fnRun(bill), "");
    bill.status = BILL_STATUS_DEFAULTED;
    BOOST_CHECK_EQUAL(fnRun(bill), "");
    bill.nEscrowHouseID = 3;   // op 11 at a failed house: its title stays put
    BOOST_CHECK_EQUAL(fnRun(bill), "bad-bill-titlerelease-escrowed");
}

// ===========================================================================
// testing (2026-11-26): S1X-34 (Claude max run 4 #2; security 11-26 Medium; fixed in consensus batch 2, Michael
// 2026-11-26 "Yes, build all 6"). P endorses its bill to X; after the grace deadline P pays X by RECOURSE, so P is the
// holder again while the title coin stays with X. Within BILL_ENDORSE_HEIGHT_SLACK of P's endorsement, X replays P's
// link (P's own signature, public on chain) and takes the bill back: P paid and keeps nothing. Driven through
// CheckBillOperation op by op (ENDORSE, RECOURSE, the replay), each op's effects feeding the next. The endorse digest
// changes with the fix (it binds the endorser and the link's index), so Run4EndorseDigest uses the fix's form when it
// exists and master's otherwise: this file builds before and after the fix.
// FAILS on master 7f65d2e (the replay is accepted); passes on mb/consensus-batch-2 (refused bad-bill-endorse-sig; a
// fresh link P signs at the new index is accepted).
// ===========================================================================
namespace {
template <typename V>
auto Run4EndorseDigestImpl(const uint256& id, const V& from, const V& to, uint32_t h, uint32_t idx, int)
    -> decltype(BillEndorseSigHash(id, from, to, h, idx))
{
    return BillEndorseSigHash(id, from, to, h, idx);
}
template <typename V>
auto Run4EndorseDigestImpl(const uint256& id, const V& from, const V& to, uint32_t h, uint32_t idx, long)
    -> decltype(BillEndorseSigHash(id, to, h))
{
    (void)from; (void)idx;
    return BillEndorseSigHash(id, to, h);
}
uint256 Run4EndorseDigest(const uint256& id, const std::vector<unsigned char>& from,
                          const std::vector<unsigned char>& to, uint32_t h, uint32_t idx)
{
    return Run4EndorseDigestImpl(id, from, to, h, idx, 0);
}

// One bill op at nHeight against `bill`; "" on accept (billOut = the effects), else the reason.
std::string Run4BillOp(const CMutableTransaction& mtx, const CBill& bill, int nHeight, CBill& billOut)
{
    const CBill b = bill;
    std::function<bool(uint32_t, CBill&)> getBill = [b](uint32_t id, CBill& out) {
        if (id != b.nBillID) return false;
        out = b; return true;
    };
    std::function<bool(const uint256&)> haveHash = [b](const uint256& x) { return x == b.billID; };
    std::function<bool(uint32_t, CHouse&)> getHouse = [](uint32_t, CHouse&) { return false; };
    std::function<bool(const COutPoint&, Coin&)> noCoin = [](const COutPoint&, Coin&) { return false; };
    std::function<bool(uint32_t, uint256&)> noBlock = [](uint32_t, uint256&) { return false; };
    CValidationState state;
    CHouse houseOut;
    bool fHouseChanged = false;
    billOut = CBill();
    if (CheckBillOperation(CTransaction(mtx), state, nHeight, 10 * COIN, getBill, haveHash, getHouse, noCoin, noBlock,
                           billOut, houseOut, fHouseChanged, false))
        return std::string();
    return state.GetRejectReason().empty() ? std::string("(refused, no reason)") : state.GetRejectReason();
}

CMutableTransaction Run4EndorseTx(uint32_t nBillID, const BillEndorsement& e)
{
    BillEndorse en;
    en.nBillID = nBillID;
    en.endorsement = e;
    return UR16Tx(BILL_OP_ENDORSE, en, e.vchTo, BILL_TITLE_VALUE);
}
} // namespace

BOOST_AUTO_TEST_CASE(s1x_34_a_paid_endorser_keeps_the_bill_after_recourse)
{
    CKey keyDrawer, keyAcceptor, keyP, keyX, keyY;
    keyDrawer.MakeNewKey(true); keyAcceptor.MakeNewKey(true);
    keyP.MakeNewKey(true); keyX.MakeNewKey(true); keyY.MakeNewKey(true);
    const std::vector<unsigned char> vP = UR16Pub(keyP), vX = UR16Pub(keyX), vY = UR16Pub(keyY);

    CBill bill;
    bill.nBillID = 34;
    bill.billID = uint256S("b134");
    bill.amount = 10000;                 // 10 g of face (mg): 10,000 sats at the suite's 1,000 sats per gram
    bill.amountEscrow = 4000;            // the drawee's bond, below the face's value
    bill.nIssuedHeight = 4000;
    bill.nMaturityHeight = 4600;
    bill.nGraceBlocks = 10;
    bill.vchDrawerPubKey = UR16Pub(keyDrawer);
    bill.vchAcceptorPubKey = UR16Pub(keyAcceptor);
    bill.vchHolderPubKey = vP;
    bill.nRefHouseID = 5;
    bill.nOwnerHouseID = 0;
    bill.status = BILL_STATUS_ACTIVE;

    // 1. P endorses the overdue bill to X at 4980: link 0.
    const uint32_t hEndorse = 4980;
    BillEndorsement link0;
    link0.vchFrom = vP;
    link0.vchTo = vX;
    link0.nAtHeight = hEndorse;
    BOOST_REQUIRE(keyP.Sign(Run4EndorseDigest(bill.billID, vP, vX, hEndorse, 0), link0.vchSig));
    CBill billEndorsed;
    std::string r = Run4BillOp(Run4EndorseTx(bill.nBillID, link0), bill, (int)hEndorse, billEndorsed);
    BOOST_REQUIRE_MESSAGE(r.empty(), "S1X-34 setup: P's ENDORSE to X was refused: " + r);
    BOOST_REQUIRE(billEndorsed.vchHolderPubKey == vX);
    BOOST_REQUIRE_EQUAL(billEndorsed.vEndorsement.size(), 1u);

    // 2. Past the grace deadline P, the endorser liable to X, pays X max(face at the ask, bond) = 10,000 sats by RECOURSE.
    BillRecourse rec;
    rec.nBillID = bill.nBillID;
    rec.vchPayerPubKey = vP;
    rec.vchPrevHolderPubKey = vX;
    rec.nRateNamed = 1000;
    CMutableTransaction mtxRec = UR16Tx(BILL_OP_RECOURSE, rec, vX, 10000);
    BOOST_REQUIRE(keyP.Sign(BillRecourseSigHash(CTransaction(mtxRec), bill.billID), rec.vchPayerSig));
    mtxRec = UR16Tx(BILL_OP_RECOURSE, rec, vX, 10000);
    CBill billRecoursed;
    r = Run4BillOp(mtxRec, billEndorsed, 4990, billRecoursed);
    BOOST_REQUIRE_MESSAGE(r.empty(), "S1X-34 setup: P's RECOURSE paying X 10,000 sats was refused: " + r);
    BOOST_REQUIRE(billRecoursed.vchHolderPubKey == vP);
    BOOST_REQUIRE(billRecoursed.status == BILL_STATUS_ACTIVE);
    BOOST_REQUIRE_EQUAL(billRecoursed.vEndorsement.size(), 1u);   // recourse appends no link

    // 3. At 5000 (20 blocks after P signed link 0, inside the 64-block slack) X replays link 0.
    CBill billReplayed;
    r = Run4BillOp(Run4EndorseTx(bill.nBillID, link0), billRecoursed, 5000, billReplayed);
    BOOST_CHECK_MESSAGE(r == "bad-bill-endorse-sig",
                        "S1X-34: X's replay of P's old endorsement, after P paid X by recourse, was " +
                        (r.empty() ? std::string("ACCEPTED: the holder is ") +
                                         (billReplayed.vchHolderPubKey == vX ? "X again" : "not X") +
                                         ", so P paid 10,000 sats and keeps nothing"
                                   : "refused for another reason: " + r));

    // Control: P can still endorse onward with a fresh link (link 1).
    BillEndorsement link1;
    link1.vchFrom = vP;
    link1.vchTo = vY;
    link1.nAtHeight = 5000;
    BOOST_REQUIRE(keyP.Sign(Run4EndorseDigest(bill.billID, vP, vY, 5000, 1), link1.vchSig));
    CBill billOnward;
    r = Run4BillOp(Run4EndorseTx(bill.nBillID, link1), billRecoursed, 5000, billOnward);
    BOOST_CHECK_MESSAGE(r.empty(), "S1X-34 control: P's fresh endorsement to Y after the recourse was refused: " + r);
}

BOOST_AUTO_TEST_SUITE_END()
