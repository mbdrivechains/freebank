// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// v1.0.2 credit binding (NEXT 40, docs-local/CREDIT_SIGHASH_SPEC.md): a credit transaction's input signatures bind its
// op and its payload minus the payload's own signature fields.

#include <creditbind.h>

#include <bill.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <coins.h>
#include <consensus/validation.h>
#include <deposit.h>
#include <hash.h>
#include <house.h>
#include <key.h>
#include <miner.h>
#include <note.h>
#include <oracle.h>
#include <issued.h>
#include <policy/policy.h>
#include <pool.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <settle.h>
#include <streams.h>
#include <token.h>
#include <txmempool.h>
#include <validation.h>
#include <version.h>

#include <test/test_bitcoin.h>

#include <functional>
#include <limits>
#include <string.h>

#include <boost/test/unit_test.hpp>

namespace {

/** Reads an endless run of 0x01 bytes: every integer non-zero, every vector and string one element long, so a struct
 *  decoded from it has every field set, and a binding form that drops a field the test did not list shows. */
class OnesReader
{
public:
    int GetType() const { return SER_NETWORK; }
    int GetVersion() const { return PROTOCOL_VERSION; }
    void read(char* dst, size_t n) { memset(dst, 0x01, n); }
    template <typename T>
    OnesReader& operator>>(T& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }
};

template <typename T>
T Populated()
{
    T p;
    OnesReader r;
    r >> p;
    return p;
}

template <typename T>
std::vector<unsigned char> Enc(const T& p)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CMutableTransaction Credit(int32_t nVersion, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    CMutableTransaction m;
    m.nVersion = nVersion;
    switch (nVersion) {
    case TRANSACTION_BILL_VERSION: m.nBillOp = nOp; m.vchBillPayload = vch; break;
    case TRANSACTION_HOUSE_VERSION: m.nHouseOp = nOp; m.vchHousePayload = vch; break;
    case TRANSACTION_NOTE_VERSION: m.nNoteOp = nOp; m.vchNotePayload = vch; break;
    case TRANSACTION_DEPOSIT_VERSION: m.nDepositOp = nOp; m.vchDepositPayload = vch; break;
    case TRANSACTION_POOL_VERSION: m.nPoolOp = nOp; m.vchPoolPayload = vch; break;
    case TRANSACTION_SETTLE_VERSION: m.nSettleOp = nOp; m.vchSettlePayload = vch; break;
    case TRANSACTION_ORACLE_VERSION: m.nOracleOp = nOp; m.vchOraclePayload = vch; break;
    case TRANSACTION_TOKEN_VERSION: m.nIssuedOp = nOp; m.vchIssuedPayload = vch; break;
    }
    m.vin.push_back(CTxIn(COutPoint(uint256S("0a"), 0)));
    m.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    return m;
}

uint256 Bind(const CMutableTransaction& m) { return CreditBindingHash(CTransaction(m)); }

uint256 Expected(uint8_t nOp, uint8_t nTag, const std::vector<unsigned char>& vchForm)
{
    // The consensus encoding: op, tag (1 = decoded, 0 = raw), then the form; a decoded form is the struct's own
    // serialization, appended as is.
    CHashWriter ss(SER_GETHASH, 0);
    ss << nOp << nTag;
    if (nTag == 1)
        ss.write((const char*)vchForm.data(), vchForm.size());
    else
        ss << vchForm;
    ss << std::vector<CIssuedOut>();   // gram-notes release: every credit version binds its (here empty) annex
    ss << std::vector<CVaultMove>();   // and its (here empty) vault moves
    return ss.GetHash();
}

/** The spec's s3 row for one op: the binding form is the payload with EXACTLY these fields emptied. The list lives
 *  here, apart from creditbind.cpp, so the two must agree. nSize pins the populated payload's size: a payload field
 *  added later changes it, and this fails until the field is classified (bound, or a signature field listed in both
 *  places). */
template <typename T>
void CheckOp(int32_t nVersion, uint8_t nOp, size_t nSize, const std::function<void(T&)>& fnClear, const char* name)
{
    const T p = Populated<T>();
    const std::vector<unsigned char> vch = Enc(p);
    BOOST_CHECK_MESSAGE(vch.size() == nSize, strprintf("%s: populated payload is %u bytes, pinned %u - classify the "
                                                       "new field in creditbind.cpp and here", name, vch.size(), nSize));
    T form = p;
    fnClear(form);
    const uint256 h = Bind(Credit(nVersion, nOp, vch));
    BOOST_CHECK_MESSAGE(h == Expected(nOp, 1, Enc(form)), strprintf("%s: binding form != payload minus its listed signature fields", name));
    // The op is bound: the same bytes under the next op number hash differently.
    BOOST_CHECK_MESSAGE(Bind(Credit(nVersion, nOp + 1, vch)) != h, strprintf("%s: op not bound", name));
    // Refilling every listed field differently moves nothing.
    T q = p;
    fnClear(q);
    BOOST_CHECK_MESSAGE(Bind(Credit(nVersion, nOp, Enc(q))) == h, strprintf("%s: a listed field is bound", name));
}

template <typename T>
void ClearApprovers(T& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }

void ClearProofs(std::vector<AttestProof>& v) { for (AttestProof& a : v) a.vchSig.clear(); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(creditbind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(binding_form_per_op)
{
    const int B = TRANSACTION_BILL_VERSION, H = TRANSACTION_HOUSE_VERSION, N = TRANSACTION_NOTE_VERSION,
              D = TRANSACTION_DEPOSIT_VERSION, P = TRANSACTION_POOL_VERSION, S = TRANSACTION_SETTLE_VERSION,
              O = TRANSACTION_ORACLE_VERSION;

    CheckOp<BillIssue>(B, BILL_OP_ISSUE, 28, [](BillIssue& p) { p.vchDrawerSig.clear(); p.vchAcceptorSig.clear(); }, "BILL ISSUE");
    // ENDORSE keeps its height bound: only the discount's link height is the seller's to set late.
    CheckOp<BillEndorse>(B, BILL_OP_ENDORSE, 14, [](BillEndorse& p) { p.endorsement.vchSig.clear(); }, "BILL ENDORSE");
    CheckOp<BillRetire>(B, BILL_OP_RETIRE, 10, [](BillRetire& p) { p.vchAcceptorSig.clear(); }, "BILL RETIRE");
    CheckOp<BillClaim>(B, BILL_OP_CLAIM, 6, [](BillClaim& p) { p.vchHolderSig.clear(); }, "BILL CLAIM");
    CheckOp<BillDiscount>(B, BILL_OP_DISCOUNT, 142, [](BillDiscount& p) {
        ClearProofs(p.vReserveProofs);
        p.endorsement.nAtHeight = 0;
        p.endorsement.vchSig.clear();
        p.vchSellerSig.clear();
        ClearApprovers(p);
    }, "BILL DISCOUNT");
    CheckOp<BillRecourse>(B, BILL_OP_RECOURSE, 14, [](BillRecourse& p) { p.vchPayerSig.clear(); }, "BILL RECOURSE");
    CheckOp<BillHRetire>(B, BILL_OP_HRETIRE, 50, [](BillHRetire& p) { p.vchAcceptorSig.clear(); }, "BILL HRETIRE");
    CheckOp<BillHClaim>(B, BILL_OP_HCLAIM, 52, [](BillHClaim& p) { ClearApprovers(p); }, "BILL HCLAIM");
    CheckOp<BillHRetireNotes>(B, BILL_OP_HRETIRE_NOTES, 66, [](BillHRetireNotes& p) { p.vchAcceptorSig.clear(); }, "BILL HRETIRE_NOTES");
    CheckOp<BillHRetireNotes>(B, BILL_OP_HRETIRE_ESCROW, 66, [](BillHRetireNotes& p) { p.vchAcceptorSig.clear(); }, "BILL HRETIRE_ESCROW");
    CheckOp<BillHClaimEscrow>(B, BILL_OP_HCLAIM_ESCROW, 44, [](BillHClaimEscrow&) {}, "BILL HCLAIM_ESCROW");

    CheckOp<HouseRegister>(H, HOUSE_OP_REGISTER, 32, [](HouseRegister& p) { p.vPartnerSig.clear(); }, "HOUSE REGISTER");
    CheckOp<HouseTopup>(H, HOUSE_OP_TOPUP, 10, [](HouseTopup& p) { p.vchSig.clear(); }, "HOUSE TOPUP");
    CheckOp<HouseAdmit>(H, HOUSE_OP_ADMIT, 16, [](HouseAdmit& p) { p.vchNewSig.clear(); ClearApprovers(p); }, "HOUSE ADMIT");
    CheckOp<HouseExit>(H, HOUSE_OP_EXIT, 18, [](HouseExit& p) { p.vchPartnerSig.clear(); ClearApprovers(p); }, "HOUSE EXIT");
    CheckOp<HouseWinddown>(H, HOUSE_OP_WINDDOWN, 12, [](HouseWinddown& p) { ClearApprovers(p); }, "HOUSE WINDDOWN");
    CheckOp<HouseReclaim>(H, HOUSE_OP_RECLAIM, 10, [](HouseReclaim& p) { p.vchSig.clear(); }, "HOUSE RECLAIM");
    CheckOp<HouseAttest>(H, HOUSE_OP_ATTEST, 98, [](HouseAttest& p) { ClearProofs(p.vProofs); ClearApprovers(p); }, "HOUSE ATTEST");
    CheckOp<HouseDefer>(H, HOUSE_OP_DEFER, 16, [](HouseDefer& p) { ClearApprovers(p); }, "HOUSE DEFER");
    CheckOp<HouseRenew>(H, HOUSE_OP_RENEW, 12, [](HouseRenew& p) { ClearApprovers(p); }, "HOUSE RENEW");
    CheckOp<HouseRelease>(H, HOUSE_OP_RELEASE, 12, [](HouseRelease& p) { ClearApprovers(p); }, "HOUSE RELEASE");
    // Members-only registration: its founders sign in the inner REGISTER (the open item in the spec's s3).
    CheckOp<HouseRegisterMO>(H, HOUSE_OP_REGISTER_MO, 33, [](HouseRegisterMO& p) { p.reg.vPartnerSig.clear(); }, "HOUSE REGISTER_MO");
    CheckOp<HouseMemberOp>(H, HOUSE_OP_MEMBER_ADD, 47, [](HouseMemberOp& p) { ClearApprovers(p); }, "HOUSE MEMBER_ADD");
    CheckOp<HouseMemberOp>(H, HOUSE_OP_MEMBER_REMOVE, 47, [](HouseMemberOp& p) { ClearApprovers(p); }, "HOUSE MEMBER_REMOVE");
    CheckOp<HouseMemberOp>(H, HOUSE_OP_MEMBER_PURGE, 47, [](HouseMemberOp& p) { ClearApprovers(p); }, "HOUSE MEMBER_PURGE");
    CheckOp<HouseClose>(H, HOUSE_OP_CLOSE, 4, [](HouseClose&) {}, "HOUSE CLOSE");

    CheckOp<NoteMint>(N, NOTE_OP_MINT, 66, [](NoteMint& p) { ClearProofs(p.vReserveProofs); ClearApprovers(p); }, "NOTE MINT");
    CheckOp<NoteTransfer>(N, NOTE_OP_TRANSFER, 21, [](NoteTransfer& p) { p.vchSenderSig.clear(); }, "NOTE TRANSFER");
    CheckOp<NoteRedeem>(N, NOTE_OP_REDEEM, 35, [](NoteRedeem& p) { p.vchHolderSig.clear(); p.vchPreAuthSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }, "NOTE REDEEM");
    CheckOp<NoteLock>(N, NOTE_OP_LOCK, 33, [](NoteLock& p) { p.vchHolderSig.clear(); ClearApprovers(p); }, "NOTE LOCK");
    CheckOp<NoteUnlock>(N, NOTE_OP_UNLOCK, 21, [](NoteUnlock& p) { ClearApprovers(p); }, "NOTE UNLOCK");
    CheckOp<NoteClaim>(N, NOTE_OP_CLAIM, 9, [](NoteClaim& p) { p.vchHolderSig.clear(); }, "NOTE CLAIM");
    CheckOp<NoteDemand>(N, NOTE_OP_DEMAND, 26, [](NoteDemand& p) { p.vchHolderSig.clear(); p.vchPreAuthSig.clear(); }, "NOTE DEMAND");
    CheckOp<NoteProtest>(N, NOTE_OP_PROTEST, 33, [](NoteProtest& p) { p.vchHolderSig.clear(); }, "NOTE PROTEST");
    CheckOp<NoteTokenKeyset>(N, NOTE_OP_TOKEN_KEYSET, 18, [](NoteTokenKeyset& p) { ClearApprovers(p); }, "NOTE TOKEN_KEYSET");
    CheckOp<NoteTokenPost>(N, NOTE_OP_TOKEN_POST, 58, [](NoteTokenPost& p) { p.vchSig.clear(); }, "NOTE TOKEN_POST");
    CheckOp<NoteTokenClaim>(N, NOTE_OP_TOKEN_CLAIM, 39, [](NoteTokenClaim& p) { for (TokenClaimEntry& e : p.vEntry) e.vchSig.clear(); }, "NOTE TOKEN_CLAIM");
    CheckOp<NoteTokenCollect>(N, NOTE_OP_TOKEN_COLLECT, 38, [](NoteTokenCollect&) {}, "NOTE TOKEN_COLLECT");

    CheckOp<DepositOriginate>(D, DEPOSIT_OP_ORIGINATE, 31, [](DepositOriginate& p) { ClearApprovers(p); }, "DEPOSIT ORIGINATE");
    CheckOp<DepositTransfer>(D, DEPOSIT_OP_TRANSFER, 28, [](DepositTransfer& p) { p.vchSenderSig.clear(); }, "DEPOSIT TRANSFER");
    CheckOp<DepositWithdraw>(D, DEPOSIT_OP_WITHDRAW, 12, [](DepositWithdraw& p) { p.vchHolderSig.clear(); }, "DEPOSIT WITHDRAW");
    CheckOp<DepositClaim>(D, DEPOSIT_OP_CLAIM, 9, [](DepositClaim& p) { p.vchHolderSig.clear(); }, "DEPOSIT CLAIM");
    CheckOp<DepositDemand>(D, DEPOSIT_OP_DEMAND, 30, [](DepositDemand& p) { p.vchPreAuthSig.clear(); }, "DEPOSIT DEMAND");
    CheckOp<DepositProtest>(D, DEPOSIT_OP_PROTEST, 48, [](DepositProtest& p) { p.vchPreAuthSig.clear(); p.vchHolderSig.clear(); }, "DEPOSIT PROTEST");
    CheckOp<DepositDischarge>(D, DEPOSIT_OP_DISCHARGE, 18, [](DepositDischarge& p) { p.vchPreAuthSig.clear(); }, "DEPOSIT DISCHARGE");

    CheckOp<PoolCreate>(P, POOL_OP_CREATE, 44, [](PoolCreate& p) { p.vchCreatorSig.clear(); ClearApprovers(p); }, "POOL CREATE");
    CheckOp<PoolAddLiq>(P, POOL_OP_ADD_LIQ, 64, [](PoolAddLiq& p) { p.vchProviderSig.clear(); }, "POOL ADD_LIQ");
    CheckOp<PoolRemoveLiq>(P, POOL_OP_REMOVE_LIQ, 64, [](PoolRemoveLiq& p) { p.vchProviderSig.clear(); }, "POOL REMOVE_LIQ");
    CheckOp<PoolSwap>(P, POOL_OP_SWAP, 65, [](PoolSwap& p) { p.vchTraderSig.clear(); }, "POOL SWAP");
    CheckOp<PoolRetire>(P, POOL_OP_RETIRE, 50, [](PoolRetire& p) { p.vchTriggerSig.clear(); ClearApprovers(p); }, "POOL RETIRE");

    CheckOp<SettleExchange>(S, SETTLE_OP_EXCHANGE, 93, [](SettleExchange& p) {
        p.vchPresentSigOfANotes.clear();
        p.vchPresentSigOfBNotes.clear();
        p.vApproverIndexA.clear();
        p.vApproverSigA.clear();
        p.vApproverIndexB.clear();
        p.vApproverSigB.clear();
    }, "SETTLE EXCHANGE");
    CheckOp<SettleNet>(S, SETTLE_OP_NET, 71, [](SettleNet& p) { p.vPresentSig.clear(); ClearApprovers(p); }, "SETTLE NET");

    CheckOp<OracleBond>(O, ORACLE_OP_BOND, 60, [](OracleBond& p) { p.vchSig.clear(); }, "ORACLE BOND");
    CheckOp<OracleSubmit>(O, ORACLE_OP_SUBMIT, 104, [](OracleSubmit& p) { p.vchSig.clear(); }, "ORACLE SUBMIT");

    // Gram-notes release: the issued-token ops (issued.h).
    const int32_t T = TRANSACTION_TOKEN_VERSION;
    CheckOp<IssuedCreate>(T, ISSUED_OP_CREATE, 19, [](IssuedCreate& p) { p.vchIssuerSig.clear(); }, "TOKEN CREATE");
    CheckOp<IssuedMint>(T, ISSUED_OP_MINT, 42, [](IssuedMint& p) { p.vchIssuerSig.clear(); }, "TOKEN MINT");
    CheckOp<IssuedBurn>(T, ISSUED_OP_BURN, 42, [](IssuedBurn&) {}, "TOKEN BURN");
    // 5b: + vVault (the house targets), a bound field
    CheckOp<IssuedFreeze>(T, ISSUED_OP_FREEZE, 93, [](IssuedFreeze& p) { p.vchFreezeSig.clear(); }, "TOKEN FREEZE");
}

BOOST_AUTO_TEST_CASE(binding_covers_the_issued_annex)
{
    // Gram-notes release: which outputs carry which issued units is bound whole, in every credit version.
    for (int32_t nVersion = TRANSACTION_BILL_VERSION; nVersion <= TRANSACTION_TOKEN_VERSION; nVersion++) {
        CMutableTransaction m = Credit(nVersion, 1, std::vector<unsigned char>());
        m.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
        CIssuedOut o;
        o.tokenID = uint256S("aa");
        o.nUnits = 5;
        m.vIssuedOut = {o};
        const uint256 h = Bind(m);
        m.vIssuedOut[0].nOut = 1;
        BOOST_CHECK_MESSAGE(Bind(m) != h, strprintf("v%d: annex output not bound", nVersion));
        m.vIssuedOut[0].nFrozen = 5;
        const uint256 h2 = Bind(m);
        m.vIssuedOut[0].nFrozen = 0;
        BOOST_CHECK_MESSAGE(Bind(m) != h2, strprintf("v%d: annex frozen units not bound", nVersion));
    }
}

BOOST_AUTO_TEST_CASE(binding_raw_payloads)
{
    // Undecodable, trailing bytes, an unknown op: bound as the raw bytes, tag 0.
    const std::vector<unsigned char> vchJunk = {0xde, 0xad};
    BOOST_CHECK(Bind(Credit(TRANSACTION_BILL_VERSION, BILL_OP_DISCOUNT, vchJunk)) == Expected(BILL_OP_DISCOUNT, 0, vchJunk));
    std::vector<unsigned char> vchTrail = Enc(Populated<BillEndorse>());
    vchTrail.push_back(0x00);
    BOOST_CHECK(Bind(Credit(TRANSACTION_BILL_VERSION, BILL_OP_ENDORSE, vchTrail)) == Expected(BILL_OP_ENDORSE, 0, vchTrail));
    const std::vector<unsigned char> vchClose = Enc(Populated<HouseClose>());
    BOOST_CHECK(Bind(Credit(TRANSACTION_HOUSE_VERSION, 200, vchClose)) == Expected(200, 0, vchClose));
    // A raw form never equals a decoded one of the same bytes.
    BOOST_CHECK(Bind(Credit(TRANSACTION_HOUSE_VERSION, HOUSE_OP_CLOSE, vchClose)) != Expected(HOUSE_OP_CLOSE, 0, vchClose));
}

BOOST_AUTO_TEST_CASE(binding_versions)
{
    for (int32_t v = -1; v <= 20; v++)
        BOOST_CHECK_EQUAL(IsCreditBindingVersion(v), v >= TRANSACTION_BILL_VERSION && v <= TRANSACTION_TOKEN_VERSION);
    // Outside the credit versions the flag changes nothing (v10 keeps its A2 metadata binding as before).
    const CScript code = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 7) << OP_EQUALVERIFY << OP_CHECKSIG;
    for (int32_t v : {1, 2, 3, TRANSACTION_BITASSET_CREATE_VERSION}) {
        CMutableTransaction m;
        m.nVersion = v;
        m.vin.push_back(CTxIn(COutPoint(uint256S("0a"), 0)));
        m.vout.push_back(CTxOut(1000, code));
        const CTransaction tx(m);
        for (SigVersion sv : {SIGVERSION_BASE, SIGVERSION_WITNESS_V0})
            BOOST_CHECK(SignatureHash(code, tx, 0, SIGHASH_ALL, 1000, sv, nullptr, true) ==
                        SignatureHash(code, tx, 0, SIGHASH_ALL, 1000, sv, nullptr, false));
    }
}

namespace {

/** One credit transaction with a P2PKH input (vin[0]) and a P2WPKH input (vin[1]), signed with the given binding. */
struct SignedCredit {
    CKey keyA, keyB;
    CScript spkA, spkB, codeB;
    CAmount AMOUNT = 50000;
    CMutableTransaction mtx;

    SignedCredit(int32_t nVersion, uint8_t nOp, const std::vector<unsigned char>& vch)
    {
        keyA.MakeNewKey(true);
        keyB.MakeNewKey(true);
        spkA = GetScriptForDestination(keyA.GetPubKey().GetID());
        codeB = GetScriptForDestination(keyB.GetPubKey().GetID());
        spkB = CScript() << OP_0 << ToByteVector(keyB.GetPubKey().GetID());
        mtx = Credit(nVersion, nOp, vch);
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0b"), 1)));
    }

    void Sign(bool fBinding, int nHashType = SIGHASH_ALL)
    {
        const CTransaction tx(mtx);
        std::vector<unsigned char> sigA, sigB;
        BOOST_REQUIRE(keyA.Sign(SignatureHash(spkA, tx, 0, nHashType, AMOUNT, SIGVERSION_BASE, nullptr, fBinding), sigA));
        BOOST_REQUIRE(keyB.Sign(SignatureHash(codeB, tx, 1, nHashType, AMOUNT, SIGVERSION_WITNESS_V0, nullptr, fBinding), sigB));
        sigA.push_back((unsigned char)nHashType);
        sigB.push_back((unsigned char)nHashType);
        mtx.vin[0].scriptSig = CScript() << sigA << ToByteVector(keyA.GetPubKey());
        mtx.vin[1].scriptWitness.stack = {sigB, ToByteVector(keyB.GetPubKey())};
    }

    /** Both inputs, the way CScriptCheck runs them: the binding comes from the flags. */
    bool Verify(bool fBinding) const
    {
        const CTransaction tx(mtx);
        const PrecomputedTransactionData txdata(tx);
        unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (!fBinding)
            flags &= ~SCRIPT_VERIFY_CREDIT_BINDING;
        ScriptError err;
        return VerifyScript(tx.vin[0].scriptSig, spkA, &tx.vin[0].scriptWitness, flags,
                            TransactionSignatureChecker(&tx, 0, AMOUNT, txdata, fBinding), &err) &&
               VerifyScript(tx.vin[1].scriptSig, spkB, &tx.vin[1].scriptWitness, flags,
                            TransactionSignatureChecker(&tx, 1, AMOUNT, txdata, fBinding), &err);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(input_signatures_bind_op_and_payload)
{
    // A lock: the customer signs its inputs, then the house adds its approvals (note_lock ceremony).
    NoteLock lock = Populated<NoteLock>();
    lock.vApproverIndex.clear();
    lock.vApproverSig.clear();
    SignedCredit c(TRANSACTION_NOTE_VERSION, NOTE_OP_LOCK, Enc(lock));
    c.Sign(true);
    BOOST_CHECK(c.Verify(true));
    // A bound signature is not an unbound one: below the binding height it fails.
    BOOST_CHECK(!c.Verify(false));

    // The house's approvals land after the inputs are signed: still valid.
    NoteLock approved = lock;
    approved.vApproverIndex = {0, 1};
    approved.vApproverSig = {std::vector<unsigned char>(71, 0x31), std::vector<unsigned char>(71, 0x32)};
    approved.vchHolderSig = std::vector<unsigned char>(70, 0x33);
    SignedCredit d = c;
    d.mtx.vchNotePayload = Enc(approved);
    BOOST_CHECK(d.Verify(true));

    // Anything else in the payload, or the op, breaks both inputs.
    NoteLock moved = lock;
    moved.nUnits += 1;
    d = c;
    d.mtx.vchNotePayload = Enc(moved);
    BOOST_CHECK(!d.Verify(true));
    d = c;
    d.mtx.nNoteOp = NOTE_OP_UNLOCK;
    BOOST_CHECK(!d.Verify(true));
    d = c;
    d.mtx.vchNotePayload.push_back(0x00);
    BOOST_CHECK(!d.Verify(true));

    // Whatever the hash type.
    SignedCredit e(TRANSACTION_NOTE_VERSION, NOTE_OP_LOCK, Enc(lock));
    e.Sign(true, SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    BOOST_CHECK(e.Verify(true));
    e.mtx.vchNotePayload = Enc(moved);
    BOOST_CHECK(!e.Verify(true));

    // The precomputed hash and a fresh one agree.
    const CTransaction tx(c.mtx);
    const PrecomputedTransactionData txdata(tx);
    BOOST_CHECK(txdata.fCreditBindingReady && txdata.hashCreditBinding == CreditBindingHash(tx));
}

BOOST_AUTO_TEST_CASE(e1_discount_rewritten_as_endorse)
{
    // The seller's title input and the house's funding input sign a DISCOUNT. A relay rewrites it as a plain ENDORSE
    // carrying the same link: the house's custody key gets the bill, the seller gets dust, no notes are minted.
    BillDiscount disc = Populated<BillDiscount>();
    BillEndorse endorse;
    endorse.nBillID = disc.nBillID;
    endorse.endorsement = disc.endorsement;

    // Before v1.0.2 (or below the binding height) the rewrite kept every input signature.
    SignedCredit before(TRANSACTION_BILL_VERSION, BILL_OP_DISCOUNT, Enc(disc));
    before.Sign(false);
    before.mtx.nBillOp = BILL_OP_ENDORSE;
    before.mtx.vchBillPayload = Enc(endorse);
    BOOST_CHECK(before.Verify(false));

    SignedCredit after(TRANSACTION_BILL_VERSION, BILL_OP_DISCOUNT, Enc(disc));
    after.Sign(true);
    BOOST_CHECK(after.Verify(true));
    after.mtx.nBillOp = BILL_OP_ENDORSE;
    after.mtx.vchBillPayload = Enc(endorse);
    BOOST_CHECK(!after.Verify(true));

    // Round 3 still works: the seller fills the link's height and signature and its own signature last.
    SignedCredit round3(TRANSACTION_BILL_VERSION, BILL_OP_DISCOUNT, Enc(disc));
    round3.Sign(true);
    BillDiscount filled = disc;
    filled.endorsement.nAtHeight += 7;
    filled.endorsement.vchSig = std::vector<unsigned char>(70, 0x44);
    filled.vchSellerSig = std::vector<unsigned char>(70, 0x45);
    round3.mtx.vchBillPayload = Enc(filled);
    BOOST_CHECK(round3.Verify(true));
}

BOOST_AUTO_TEST_CASE(e2_recourse_payer_swap)
{
    // P pays the holder and signs as payer; a second liable party Q swaps in its own key and signature to take the
    // bill P paid for.
    BillRecourse rec = Populated<BillRecourse>();
    BillRecourse swapped = rec;
    swapped.vchPayerPubKey = std::vector<unsigned char>(33, 0x02);
    swapped.vchPayerSig = std::vector<unsigned char>(70, 0x46);

    SignedCredit before(TRANSACTION_BILL_VERSION, BILL_OP_RECOURSE, Enc(rec));
    before.Sign(false);
    before.mtx.vchBillPayload = Enc(swapped);
    BOOST_CHECK(before.Verify(false));

    SignedCredit after(TRANSACTION_BILL_VERSION, BILL_OP_RECOURSE, Enc(rec));
    after.Sign(true);
    after.mtx.vchBillPayload = Enc(swapped);
    BOOST_CHECK(!after.Verify(true));
}

BOOST_AUTO_TEST_CASE(e3_topup_partner_swap)
{
    // Partner 1 funds a top-up; a co-partner swaps the index (and signs) to be credited with it.
    HouseTopup top = Populated<HouseTopup>();
    HouseTopup swapped = top;
    swapped.nPartnerIndex += 1;
    swapped.vchSig = std::vector<unsigned char>(70, 0x47);

    SignedCredit before(TRANSACTION_HOUSE_VERSION, HOUSE_OP_TOPUP, Enc(top));
    before.Sign(false);
    before.mtx.vchHousePayload = Enc(swapped);
    BOOST_CHECK(before.Verify(false));

    SignedCredit after(TRANSACTION_HOUSE_VERSION, HOUSE_OP_TOPUP, Enc(top));
    after.Sign(true);
    after.mtx.vchHousePayload = Enc(swapped);
    BOOST_CHECK(!after.Verify(true));
}

BOOST_AUTO_TEST_CASE(binding_height_per_network)
{
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::MAIN)->GetConsensus().nCreditBindingHeight, 0);
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::REGTEST)->GetConsensus().nCreditBindingHeight, 0);
    // v1.1.0: FreeBank-easynet restarts as a fresh chain (scope 7h), so it binds from genesis too (was 600)
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::EASYNET)->GetConsensus().nCreditBindingHeight, 0);
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::BETA)->GetConsensus().nCreditBindingHeight, 0);
    const std::unique_ptr<CChainParams> easynet = CreateChainParams(CBaseChainParams::EASYNET);
    BOOST_CHECK(easynet->GetConsensus().CreditBindingActive(0));
    // ...and credits treasury changes only from its deposit start (L1 1,100); every other network from the start
    BOOST_CHECK_EQUAL(easynet->GetConsensus().nDepositStartL1Height, 1100);
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::MAIN)->GetConsensus().nDepositStartL1Height, 0);
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::REGTEST)->GetConsensus().nDepositStartL1Height, 0);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

/** Moves the consensus nCreditBindingHeight for one test (never a CLI knob) and restores it however the test exits. */
struct BindingHeightScope {
    Consensus::Params& consensus;
    const int nSaved;
    BindingHeightScope()
        : consensus(const_cast<Consensus::Params&>(Params().GetConsensus())),
          nSaved(consensus.nCreditBindingHeight) {}
    void Set(int nHeight) { consensus.nCreditBindingHeight = nHeight; }
    ~BindingHeightScope() { consensus.nCreditBindingHeight = nSaved; }
};

/** A CLOSE of an unknown house: shape-valid (CheckTransaction passes), never connectable. */
CMutableTransaction CloseTx(const CTransaction& txFunding)
{
    HouseClose cl;
    cl.nHouseID = 7;
    CMutableTransaction m;
    m.nVersion = TRANSACTION_HOUSE_VERSION;
    m.nHouseOp = HOUSE_OP_CLOSE;
    m.vchHousePayload = Enc(cl);
    m.vin.push_back(CTxIn(COutPoint(txFunding.GetHash(), 0)));
    // Standard and not dust, so the mempool reaches the gate; a sidechain coinbase pays 0, so it never connects.
    m.vout.push_back(CTxOut(100000, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 7) << OP_EQUALVERIFY << OP_CHECKSIG));
    return m;
}

} // namespace

bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks);

BOOST_FIXTURE_TEST_SUITE(creditbind_chain_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(mempool_refuses_credit_below_binding_height)
{
    BindingHeightScope scope;
    const CTransactionRef ptx = MakeTransactionRef(CloseTx(coinbaseTxns[0]));
    LOCK(cs_main);

    scope.Set(chainActive.Height() + 2);
    CValidationState state;
    BOOST_CHECK(!AcceptToMemoryPool(mempool, state, ptx, nullptr, nullptr, true, 0));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "credit-binding-not-active");
    int nDoS = -1;
    BOOST_CHECK(state.IsInvalid(nDoS) && nDoS == 0);

    // From the binding height (the next block binds) the gate is open; this CLOSE then fails on its own merits.
    scope.Set(chainActive.Height() + 1);
    CValidationState state2;
    BOOST_CHECK(!AcceptToMemoryPool(mempool, state2, ptx, nullptr, nullptr, true, 0));
    BOOST_CHECK(state2.GetRejectReason() != "credit-binding-not-active");
}

// The binding is not a soft fork (a bound signature fails without it), so the re-run that tells policy from consensus
// failures keeps it: a bound credit transaction that breaks only a policy rule, or one an older node signed unbound,
// is DoS 0; a signature that holds under neither digest is a ban.
BOOST_AUTO_TEST_CASE(policy_failures_of_credit_txs_are_not_bans)
{
    CKey key;
    key.MakeNewKey(true);
    const CScript spk = GetScriptForDestination(key.GetPubKey().GetID());
    const CAmount nValue = 100000;
    const COutPoint prevout(uint256S("0c"), 0);
    LOCK(cs_main);
    CCoinsViewCache view(pcoinsTip.get());
    view.AddCoin(prevout, Coin(CTxOut(nValue, spk), 1, false, false, false, uint256()), false);

    CMutableTransaction m = Credit(TRANSACTION_NOTE_VERSION, NOTE_OP_LOCK, Enc(Populated<NoteLock>()));
    m.vin[0].prevout = prevout;
    auto Sign = [&](bool fBinding, bool fMinimalPush) {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(SignatureHash(spk, CTransaction(m), 0, SIGHASH_ALL, nValue, SIGVERSION_BASE, nullptr, fBinding), sig));
        sig.push_back(SIGHASH_ALL);
        CScript scriptSig;
        if (fMinimalPush) {
            scriptSig << sig;
        } else {   // OP_PUSHDATA1 where a direct push fits: MINIMALDATA, a policy rule
            scriptSig.push_back(OP_PUSHDATA1);
            scriptSig.push_back((unsigned char)sig.size());
            scriptSig.insert(scriptSig.end(), sig.begin(), sig.end());
        }
        scriptSig << ToByteVector(key.GetPubKey());
        m.vin[0].scriptSig = scriptSig;
    };
    auto Check = [&](std::string& strReason) {
        const CTransaction tx(m);
        PrecomputedTransactionData txdata(tx);
        CValidationState state;
        const bool fOk = CheckInputs(tx, state, view, true, STANDARD_SCRIPT_VERIFY_FLAGS, true, false, txdata, nullptr);
        strReason = state.GetRejectReason();
        int nDoS = 0;
        state.IsInvalid(nDoS);
        return fOk ? -1 : nDoS;
    };
    std::string r;
    Sign(true, true);
    BOOST_CHECK_EQUAL(Check(r), -1);
    Sign(true, false);
    BOOST_CHECK_EQUAL(Check(r), 0);
    BOOST_CHECK_MESSAGE(r.find("non-mandatory-script-verify-flag") == 0, r);
    Sign(false, true);
    BOOST_CHECK_EQUAL(Check(r), 0);
    BOOST_CHECK_MESSAGE(r.find("non-mandatory-script-verify-flag") == 0, r);
    Sign(true, true);
    m.vchNotePayload.push_back(0x00);   // rewritten after signing
    BOOST_CHECK_EQUAL(Check(r), 100);
    BOOST_CHECK_MESSAGE(r.find("mandatory-script-verify-flag-failed") == 0, r);
}

BOOST_AUTO_TEST_CASE(template_skips_credit_below_binding_height)
{
    BindingHeightScope scope;
    const CTransactionRef ptx = MakeTransactionRef(CloseTx(coinbaseTxns[1]));
    {
        LOCK2(cs_main, mempool.cs);
        TestMemPoolEntryHelper entry;
        mempool.addUnchecked(ptx->GetHash(), entry.Fee(10000).Time(GetTime()).SpendsCoinbase(true).FromTx(*ptx));
        scope.Set(chainActive.Height() + 2);
    }
    // Below the binding height the template skips it: not in the block, still pooled.
    CBlock block;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
        std::vector<CMutableTransaction>(), uint256(), CScript() << OP_TRUE), strError);
    for (const CTransactionRef& tx : block.vtx)
        BOOST_CHECK(tx->GetHash() != ptx->GetHash());
    {
        LOCK(mempool.cs);
        BOOST_CHECK(mempool.exists(ptx->GetHash()));
    }
    // From it the template takes the transaction; this one can't connect, so the template drops it from the pool.
    // That it stayed pooled above is the skip.
    {
        LOCK(cs_main);
        scope.Set(chainActive.Height() + 1);
    }
    CBlock block2;
    BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block2, strError, nullptr,
        std::vector<CMutableTransaction>(), uint256(), CScript() << OP_TRUE), strError);
    LOCK(mempool.cs);
    BOOST_CHECK(!mempool.exists(ptx->GetHash()));
    mempool.clear();
}

BOOST_AUTO_TEST_SUITE_END()
