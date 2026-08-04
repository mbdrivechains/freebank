// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>

#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <key.h>
#include <note.h>             // NOTE_DUST_VALUE / MAX_NOTE_OUTPUTS
#include <script/interpreter.h>   // SIGHASH_ALL
#include <script/standard.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <utilstrencodings.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <functional>

BOOST_FIXTURE_TEST_SUITE(bill_tests, BasicTestingSetup)

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

    const uint256 billID = BillIDFromBody(issue.vchEncryptedBody);
    const uint256 sighash = BillIssueSigHash(billID, issue.amount, TEST_BILL_ESCROW,
            issue.nMaturityHeight, issue.nGraceBlocks, issue.vchDrawerPubKey,
            issue.vchAcceptorPubKey, issue.vchHolderPubKey);
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

    // Retire and claim messages over identical inputs must differ
    BOOST_CHECK(BillRetireSigHash(billID, hashOutputs) != BillClaimSigHash(billID, hashOutputs));

    // hashOutputs must matter (anti-replay: the signature pins the outputs)
    BOOST_CHECK(BillClaimSigHash(billID, hashOutputs) != BillClaimSigHash(billID, uint256S("03")));
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
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub);
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyDrawer.Sign(sighash, vchSig));
    BOOST_CHECK(pub.Verify(sighash, vchSig));

    // Front-run with a token escrow bond -> different sighash -> sig invalid
    const uint256 sighashCheapBond = BillIssueSigHash(billID, amount, 1, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub);
    BOOST_CHECK(sighash != sighashCheapBond);
    BOOST_CHECK(!pub.Verify(sighashCheapBond, vchSig));

    // Tampered face amount -> sig invalid
    BOOST_CHECK(!pub.Verify(BillIssueSigHash(billID, amount + 1, escrow, 500,
            DEFAULT_BILL_GRACE_BLOCKS, vchPub, vchPub, vchPub), vchSig));
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

    const uint256 sighash = BillEndorseSigHash(billID, vchTo, 100);
    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(keyFrom.Sign(sighash, vchSig));

    BOOST_CHECK(pubFrom.Verify(sighash, vchSig));
    // Signature does not verify for a different height or endorsee
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchTo, 101), vchSig));
    std::vector<unsigned char> vchFrom(pubFrom.begin(), pubFrom.end());
    BOOST_CHECK(!pubFrom.Verify(BillEndorseSigHash(billID, vchFrom, 100), vchSig));
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
    const uint256 base = BillDiscountSigHash(d, billID, hp, ho);

    // Same inputs -> same digest.
    BOOST_CHECK(BillDiscountSigHash(d, billID, hp, ho) == base);

    // Every value field is bound.
    BillDiscount m = d; m.amountPrice += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.amountFace += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nBillMaturityHeight += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nHouseID += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.vUnits[0] += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.vchCustodyPubKey[0] = 0x03;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nExpiryHeight += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nAsOfHeight += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nPrevMintedUnits += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nPrevLoanBookFace += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nPrevLoanWtMatHi += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);
    m = d; m.nPrevLoanWtMatLo += 1;
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) != base);

    // The tx context is bound.
    BOOST_CHECK(BillDiscountSigHash(d, uint256S("0a0c"), hp, ho) != base);
    BOOST_CHECK(BillDiscountSigHash(d, billID, uint256S("1112"), ho) != base);
    BOOST_CHECK(BillDiscountSigHash(d, billID, hp, uint256S("2223")) != base);

    // Signature and approver-index fields are EXCLUDED, so the seller's payload
    // signature survives the house adding its quorum (and vice versa).
    m = d;
    m.vchSellerSig = std::vector<unsigned char>(70, 0x30);
    m.vApproverIndex.push_back(0);
    m.vApproverSig.push_back(std::vector<unsigned char>(70, 0x30));
    BOOST_CHECK(BillDiscountSigHash(m, billID, hp, ho) == base);

    // Domain separation: the two B1 digests never collide.
    BillRecourse r;
    r.nBillID = 7;
    r.vchPayerPubKey = std::vector<unsigned char>(33, 0x02);
    r.vchPrevHolderPubKey = std::vector<unsigned char>(33, 0x03);
    const uint256 rbase = BillRecourseSigHash(r, billID, hp, ho);
    BOOST_CHECK(rbase != base);
    BillRecourse rm = r; rm.vchPayerPubKey[0] = 0x03;
    BOOST_CHECK(BillRecourseSigHash(rm, billID, hp, ho) != rbase);
    rm = r; rm.vchPrevHolderPubKey[0] = 0x02;
    BOOST_CHECK(BillRecourseSigHash(rm, billID, hp, ho) != rbase);
    rm = r; rm.vchPayerSig = std::vector<unsigned char>(70, 0x30);
    BOOST_CHECK(BillRecourseSigHash(rm, billID, hp, ho) == rbase);   // sig excluded
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
    // The op range widens to 1..8 and no further.
    BillDiscount d; DiscountKeys k;
    CMutableTransaction mtx = MakeDiscountTx(d, k);
    {
        CValidationState state;
        BOOST_CHECK(CheckBillTransactionShape(CTransaction(mtx), state));
    }
    for (uint8_t op : {(uint8_t)0, (uint8_t)9, (uint8_t)255}) {
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

    // Per-op payload ceilings: 16384 for a discount, 4096 for ops 6-8, and ops
    // 1-4 unchanged at MAX_BILL_BODY_BYTES + 1024.
    {
        CMutableTransaction bad = mtx;
        bad.vchBillPayload.resize(MAX_BILL_DISCOUNT_PAYLOAD + 1, 0x00);
        CValidationState state;
        BOOST_CHECK(!CheckBillTransactionShape(CTransaction(bad), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bill-payload-oversize");
    }
    for (uint8_t op : {BILL_OP_RECOURSE, BILL_OP_HRETIRE, BILL_OP_HCLAIM}) {
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

    // -- reserve proofs (R-i7): every discount MINTS, so an empty set is
    //    unconditionally invalid, and it costs no DB read to say so.
    reject([](BillDiscount& d, CMutableTransaction&) { d.vReserveProofs.clear(); },
           "bad-bill-discount-proofs-shape");
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
    Coin coin(CTxOut(BILL_TITLE_VALUE, CScript() << OP_TRUE), 100, false, false, false, 0);
    coin.SetBill(fEscrow, nBillID);
    COutPoint op(txid, n);
    cache.AddCoin(op, std::move(coin), false);
    return op;
}

static COutPoint AddPlainCoin(CCoinsViewCache& cache, CAmount nValue, const uint256& txid, uint32_t n = 0)
{
    Coin coin(CTxOut(nValue, CScript() << OP_TRUE), 100, false, false, false, 0);
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
        { COL_BOND,    "bad-txns-spend-oracle-bond" },
        { COL_ASSET,   "bad-bill-asset-input" },
    };

    for (const auto& cls : kClasses) {
        for (int op = 0; op < 3; op++) {
            CCoinsView base; CCoinsViewCache cache(&base);
            Coin coin(CTxOut(100000, CScript() << OP_TRUE), 100, false, false, false,
                      cls.colour == COL_ASSET ? 42 : 0);
            switch (cls.colour) {
            case COL_NOTE:    coin.SetNote(3, 1000); break;
            case COL_HOUSE:   coin.SetHouseEscrow(3); break;
            case COL_DEPOSIT: coin.SetDeposit(3, 1000, 500, 120000, 50); break;
            case COL_POOL:    coin.SetPoolEscrow(3); break;
            case COL_LP:      coin.SetLpShare(3, 1000); break;
            case COL_BOND:    coin.SetOracleBond(); break;
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

BOOST_AUTO_TEST_SUITE_END()
