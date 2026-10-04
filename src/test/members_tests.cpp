// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <house.h>

#include <consensus/validation.h>
#include <hash.h>
#include <key.h>
#include <streams.h>
#include <test/test_bitcoin.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

// v0.2.19 members-only houses (spec gateway docs/design/members/MEMBERS_ONLY_HOUSES.md): the data model and the
// context-free rules. The contextual rules run in the gate members_roundtrip.

BOOST_FIXTURE_TEST_SUITE(members_tests, BasicTestingSetup)

static std::vector<unsigned char> NewPubKey()
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    return std::vector<unsigned char>(pub.begin(), pub.end());
}

static HouseRegister SoloDeclaration()
{
    HouseRegister reg;
    reg.nTier = HOUSE_TIER_BONDED_SOLO;
    reg.nThresholdM = 1;
    reg.strClassID = "coop";
    reg.nDenomMgGold = 1000;
    reg.vchRedemptionDestPK = NewPubKey();
    reg.vPartnerPubKey.push_back(NewPubKey());
    reg.vPledgeAmount.push_back(HOUSE_MIN_PLEDGE);
    reg.vPartnerSig.push_back(std::vector<unsigned char>(71, 0x30));   // not checked by the shape rules
    return reg;
}

// A REGISTER (nFlags 0) or REGISTER_MO tx whose escrow output binds the house id computed with idFlags.
static CMutableTransaction RegisterTx(const HouseRegister& reg, uint8_t nFlags, uint8_t idFlags)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = nFlags ? HOUSE_OP_REGISTER_MO : HOUSE_OP_REGISTER;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    if (nFlags) {
        HouseRegisterMO mo;
        mo.reg = reg;
        mo.nFlags = nFlags;
        ss << mo;
    } else {
        ss << reg;
    }
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("03"), 0)));
    mtx.vout.push_back(CTxOut(reg.vPledgeAmount[0], HouseEscrowScript(HouseIDFromDeclaration(reg, idFlags))));
    return mtx;
}

static std::string ShapeReject(const CMutableTransaction& mtx)
{
    CValidationState state;
    if (CheckHouseTransactionShape(CTransaction(mtx), state))
        return "";
    return state.GetRejectReason();
}

BOOST_AUTO_TEST_CASE(members_register_mo_decodes_and_binds_flags)
{
    const HouseRegister reg = SoloDeclaration();

    // An open house's digest is exactly the pre-v0.2.19 formula (its id must not change)
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankHouse/declaration") << reg.nTier << reg.nThresholdM << reg.strClassID
       << reg.nDenomMgGold << reg.vchRedemptionDestPK << reg.vPartnerPubKey << reg.vPledgeAmount;
    const uint256 hashOld = ss.GetHash();   // GetHash finalizes: once
    BOOST_CHECK(HouseDeclarationDigest(reg) == hashOld);
    BOOST_CHECK(HouseIDFromDeclaration(reg, 0) == hashOld);
    // The flags change the id, and each flag set gives its own
    BOOST_CHECK(HouseIDFromDeclaration(reg, HOUSE_FLAG_MEMBERS_ONLY) != HouseIDFromDeclaration(reg, 0));
    BOOST_CHECK(HouseIDFromDeclaration(reg, HOUSE_FLAG_MEMBERS_ONLY | HOUSE_FLAG_REDEEM_ONLY) !=
                HouseIDFromDeclaration(reg, HOUSE_FLAG_MEMBERS_ONLY));

    // Both register ops decode through DecodeHouseRegisterAny, with their flags
    for (uint8_t nFlags : {(uint8_t)0, HOUSE_FLAG_MEMBERS_ONLY, (uint8_t)(HOUSE_FLAG_MEMBERS_ONLY | HOUSE_FLAG_REDEEM_ONLY)}) {
        const CMutableTransaction mtx = RegisterTx(reg, nFlags, nFlags);
        HouseRegister got;
        uint8_t nGot = 0xff;
        BOOST_CHECK(DecodeHouseRegisterAny(CTransaction(mtx), got, nGot));
        BOOST_CHECK_EQUAL(nGot, nFlags);
        BOOST_CHECK(got.strClassID == reg.strClassID && got.vPartnerPubKey == reg.vPartnerPubKey);
        BOOST_CHECK_EQUAL(ShapeReject(mtx), "");
        BOOST_CHECK(IsHouseRegisterOp(mtx.nHouseOp));
    }
    // The escrow must bind the id WITH the flags: an MO registration escrowed to the open id is refused
    BOOST_CHECK_EQUAL(ShapeReject(RegisterTx(reg, HOUSE_FLAG_MEMBERS_ONLY, 0)), "bad-house-register-escrow");
    // A REGISTER_MO payload under the old op does not decode (and vice versa)
    CMutableTransaction swapped = RegisterTx(reg, HOUSE_FLAG_MEMBERS_ONLY, HOUSE_FLAG_MEMBERS_ONLY);
    swapped.nHouseOp = HOUSE_OP_REGISTER;
    BOOST_CHECK_EQUAL(ShapeReject(swapped), "bad-house-register-payload");
}

BOOST_AUTO_TEST_CASE(members_register_mo_flag_rules)
{
    const HouseRegister reg = SoloDeclaration();
    // REGISTER_MO needs MEMBERS_ONLY; REDEEM_ONLY only with it; no unknown bits
    CMutableTransaction mtx = RegisterTx(reg, HOUSE_FLAG_REDEEM_ONLY, HOUSE_FLAG_REDEEM_ONLY);
    BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-house-register-flags");
    mtx = RegisterTx(reg, HOUSE_FLAG_MEMBERS_ONLY | 4, HOUSE_FLAG_MEMBERS_ONLY | 4);
    BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-house-register-flags");
    // An MO payload with flags 0 under the MO op
    HouseRegisterMO mo;
    mo.reg = reg;
    mo.nFlags = 0;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << mo;
    mtx = RegisterTx(reg, HOUSE_FLAG_MEMBERS_ONLY, 0);
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-house-register-flags");
}

BOOST_AUTO_TEST_CASE(members_chouse_v10_and_v9)
{
    CHouse house;
    house.nHouseID = 7;
    house.strClassID = "coop";
    house.nFlags = HOUSE_FLAG_MEMBERS_ONLY | HOUSE_FLAG_REDEEM_ONLY;
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << house;
    CHouse back;
    CDataStream ss2(ss);
    ss2 >> back;
    BOOST_CHECK_EQUAL(back.nFlags, house.nFlags);
    BOOST_CHECK(back.IsMembersOnly() && back.IsRedeemOnly());

    // A v9 record: version byte 9, no flags byte at the end -> an open house
    std::vector<unsigned char> v(ss.begin(), ss.end());
    BOOST_REQUIRE_EQUAL(v[0], HOUSE_SER_VERSION);
    v[0] = 9;
    v.pop_back();
    CDataStream ss9(v, SER_DISK, CLIENT_VERSION);
    CHouse old;
    ss9 >> old;
    BOOST_CHECK(ss9.empty());
    BOOST_CHECK_EQUAL(old.nFlags, 0);
    BOOST_CHECK(!old.IsMembersOnly());
    BOOST_CHECK_EQUAL(old.nHouseID, 7U);
}

BOOST_AUTO_TEST_CASE(members_active_rule)
{
    const CHouseMember added(10, 0);
    BOOST_CHECK(!added.IsActiveAt(10));   // from the block after the add
    BOOST_CHECK(added.IsActiveAt(11));
    BOOST_CHECK(added.IsActiveAt(1000000));
    const CHouseMember removing(10, 20);
    BOOST_CHECK(removing.IsActiveAt(19));
    BOOST_CHECK(!removing.IsActiveAt(20));
    BOOST_CHECK(!removing.IsActiveAt(21));
    // a house with one partner
    CHouse house;
    HousePartner p;
    p.vchPubKey = NewPubKey();
    house.vPartner.push_back(p);
    house.vchRedemptionDestPK = NewPubKey();
    // own keys: only the redemption destination (a partner's key is not an implicit member, review F1/F2)
    const std::vector<uint160> vOwn = HouseOwnKeyIDs(house);
    BOOST_REQUIRE_EQUAL(vOwn.size(), 1U);
    BOOST_CHECK(vOwn[0] == uint160(CPubKey(house.vchRedemptionDestPK).GetID()));
}

static CMutableTransaction MemberTx(uint8_t nOp, const HouseMemberOp& op)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = nOp;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << op;
    mtx.vchHousePayload = std::vector<unsigned char>(ss.begin(), ss.end());
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("04"), 0)));
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    return mtx;
}

static HouseMemberOp ValidMemberOp(size_t nKeys)
{
    HouseMemberOp op;
    op.nHouseID = 7;
    for (size_t i = 0; i < nKeys; i++) {
        op.vKeyID.push_back(uint160(CPubKey(NewPubKey()).GetID()));
        op.vPrior.push_back(HouseMemberPrior());
    }
    op.vApproverIndex.push_back(0);
    op.vApproverSig.push_back(std::vector<unsigned char>(71, 0x30));
    return op;
}

BOOST_AUTO_TEST_CASE(members_op_shape)
{
    for (uint8_t nOp : {HOUSE_OP_MEMBER_ADD, HOUSE_OP_MEMBER_REMOVE, HOUSE_OP_MEMBER_PURGE}) {
        BOOST_CHECK(IsHouseMemberOp(nOp) && !IsHouseRegisterOp(nOp));
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, ValidMemberOp(1))), "");
        // A full batch with priors and one approver fits the payload cap
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, ValidMemberOp(MAX_HOUSE_MEMBER_BATCH))), "");
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, ValidMemberOp(MAX_HOUSE_MEMBER_BATCH + 1))), "bad-house-member-count");
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, ValidMemberOp(0))), "bad-house-member-count");

        HouseMemberOp op = ValidMemberOp(2);
        op.vKeyID[1] = op.vKeyID[0];
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, op)), "bad-house-member-dup-key");
        op = ValidMemberOp(2);
        op.vPrior.pop_back();
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, op)), "bad-house-member-count");
        op = ValidMemberOp(1);
        op.vPrior[0].fPresent = 2;
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, op)), "bad-house-member-prior");
        op = ValidMemberOp(1);
        op.vApproverIndex.clear();
        op.vApproverSig.clear();
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, op)), "bad-house-member-approvers");
        op = ValidMemberOp(1);
        op.nHouseID = 0;
        BOOST_CHECK_EQUAL(ShapeReject(MemberTx(nOp, op)), "bad-house-member-house");
    }
    // Op codes past the last member op are refused
    CMutableTransaction mtx = MemberTx(HOUSE_OP_MEMBER_PURGE, ValidMemberOp(1));
    mtx.nHouseOp = HOUSE_OP_MEMBER_PURGE + 1;
    BOOST_CHECK_EQUAL(ShapeReject(mtx), "bad-house-op");
}

BOOST_AUTO_TEST_SUITE_END()
