// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <creditbind.h>

#include <bill.h>
#include <deposit.h>
#include <hash.h>
#include <house.h>
#include <issued.h>
#include <note.h>
#include <pool.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <settle.h>
#include <token.h>
#include <version.h>

#include <ios>
#include <string.h>
#include <vector>

namespace {

/** A read stream over a payload. CDataStream would pull memory_cleanse (util) into the consensus library. */
class PayloadReader
{
    const std::vector<unsigned char>& m_data;
    size_t m_pos = 0;

public:
    explicit PayloadReader(const std::vector<unsigned char>& data) : m_data(data) {}

    int GetType() const { return SER_NETWORK; }
    int GetVersion() const { return PROTOCOL_VERSION; }

    void read(char* dst, size_t n)
    {
        if (n > m_data.size() - m_pos)
            throw std::ios_base::failure("PayloadReader::read(): end of data");
        if (n > 0)
            memcpy(dst, m_data.data() + m_pos, n);
        m_pos += n;
    }

    template <typename T>
    PayloadReader& operator>>(T& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

    bool empty() const { return m_pos == m_data.size(); }
};

// The binding form's tag: the payload decoded and re-encoded, or its raw bytes.
const uint8_t BIND_DECODED = 1;
const uint8_t BIND_RAW = 0;

void BindRaw(CHashWriter& ss, const std::vector<unsigned char>& vch)
{
    ss << BIND_RAW << vch;
}

// -- signature fields, per payload (CREDIT_SIGHASH_SPEC s3) ------------------------------------------------------
// An approver's index goes with its signature: settle, netting and note lock add another party's approvers after
// the first party signed its inputs.

void ClearProofSigs(std::vector<AttestProof>& v)
{
    for (AttestProof& p : v)
        p.vchSig.clear();
}

void Strip(BillIssue& p) { p.vchDrawerSig.clear(); p.vchAcceptorSig.clear(); }
void Strip(BillEndorse& p) { p.endorsement.vchSig.clear(); }
void Strip(BillRetire& p) { p.vchAcceptorSig.clear(); }
void Strip(BillClaim& p) { p.vchHolderSig.clear(); }
void Strip(BillDiscount& p)
{
    ClearProofSigs(p.vReserveProofs);
    // The seller sets the link's height in round 3, after the house signed its funding inputs. From, to and the op
    // stay bound, so the link can't be replayed as an ENDORSE.
    p.endorsement.nAtHeight = 0;
    p.endorsement.vchSig.clear();
    p.vchSellerSig.clear();
    p.vApproverIndex.clear();
    p.vApproverSig.clear();
}
void Strip(BillRecourse& p) { p.vchPayerSig.clear(); }
void Strip(BillHRetire& p) { p.vchAcceptorSig.clear(); }
void Strip(BillHRetireNotes& p) { p.vchAcceptorSig.clear(); }
void Strip(BillHClaimEscrow&) {}
void Strip(BillHClaim& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }

void Strip(HouseRegister& p) { p.vPartnerSig.clear(); }
void Strip(HouseRegisterMO& p) { Strip(p.reg); }
void Strip(HouseTopup& p) { p.vchSig.clear(); }
void Strip(HouseAdmit& p) { p.vchNewSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseExit& p) { p.vchPartnerSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseWinddown& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseReclaim& p) { p.vchSig.clear(); }
void Strip(HouseAttest& p) { ClearProofSigs(p.vProofs); p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseDefer& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseRenew& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseRelease& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseMemberOp& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseClose&) {}
void Strip(HouseRate& p) { p.vchRateSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(HouseCharter& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }

void Strip(NoteMint& p) { ClearProofSigs(p.vReserveProofs); p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(NoteTransfer& p) { p.vchSenderSig.clear(); }
void Strip(NoteRedeem& p) { p.vchHolderSig.clear(); p.vchPreAuthSig.clear(); }
void Strip(NoteSwap& p) { p.vchHolderSig.clear(); }
void Strip(NoteSwapDone&) {}
void Strip(NoteSwapPay&) {}
void Strip(NoteSwapProtest&) {}
void Strip(NoteSwapExpire&) {}
void Strip(NoteSwapClaim&) {}
void Strip(NoteLock& p) { p.vchHolderSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(NoteUnlock& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(NoteClaim& p) { p.vchHolderSig.clear(); }
void Strip(NoteDemand& p) { p.vchHolderSig.clear(); p.vchPreAuthSig.clear(); }
void Strip(NoteProtest& p) { p.vchHolderSig.clear(); }
void Strip(NoteTokenKeyset& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(NoteTokenPost& p) { p.vchSig.clear(); }
void Strip(NoteTokenClaim& p)
{
    for (TokenClaimEntry& e : p.vEntry)
        e.vchSig.clear();
}
void Strip(NoteTokenCollect&) {}

void Strip(DepositOriginate& p) { p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(DepositTransfer& p) { p.vchSenderSig.clear(); }
void Strip(DepositWithdraw& p) { p.vchHolderSig.clear(); }
void Strip(DepositClaim& p) { p.vchHolderSig.clear(); }
void Strip(DepositDemand& p) { p.vchPreAuthSig.clear(); }
void Strip(DepositProtest& p) { p.vchPreAuthSig.clear(); p.vchHolderSig.clear(); }
void Strip(DepositDischarge& p) { p.vchPreAuthSig.clear(); }

void Strip(PoolCreate& p) { p.vchCreatorSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }
void Strip(PoolAddLiq& p) { p.vchProviderSig.clear(); }
void Strip(PoolRemoveLiq& p) { p.vchProviderSig.clear(); }
void Strip(PoolSwap& p) { p.vchTraderSig.clear(); }
void Strip(PoolRetire& p) { p.vchTriggerSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }

void Strip(SettleExchange& p)
{
    p.vchPresentSigOfANotes.clear();
    p.vchPresentSigOfBNotes.clear();
    p.vApproverIndexA.clear();
    p.vApproverSigA.clear();
    p.vApproverIndexB.clear();
    p.vApproverSigB.clear();
}
void Strip(SettleNet& p) { p.vPresentSig.clear(); p.vApproverIndex.clear(); p.vApproverSig.clear(); }


void Strip(IssuedCreate& p) { p.vchIssuerSig.clear(); }
void Strip(IssuedMint& p) { p.vchIssuerSig.clear(); }
void Strip(IssuedBurn&) {}
void Strip(IssuedFreeze& p) { p.vchFreezeSig.clear(); }
void Strip(IssuedPoolCreate&) {}
void Strip(IssuedPoolAdd&) {}
void Strip(IssuedPoolRemove&) {}
void Strip(IssuedPoolSwap&) {}

/** Decode exactly as the families do (whole payload, no trailing bytes), strip, re-encode into the hash. */
template <typename T>
void Bind(CHashWriter& ss, const std::vector<unsigned char>& vch)
{
    T payload;
    try {
        PayloadReader r(vch);
        r >> payload;
        if (!r.empty()) {
            BindRaw(ss, vch);
            return;
        }
    } catch (const std::exception&) {
        BindRaw(ss, vch);
        return;
    }
    Strip(payload);
    ss << BIND_DECODED << payload;
}

// -- op -> payload struct, as each family's shape check decodes it -----------------------------------------------

void BindBill(CHashWriter& ss, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    switch (nOp) {
    case BILL_OP_ISSUE: Bind<BillIssue>(ss, vch); break;
    case BILL_OP_ENDORSE: Bind<BillEndorse>(ss, vch); break;
    case BILL_OP_RETIRE: Bind<BillRetire>(ss, vch); break;
    case BILL_OP_CLAIM: Bind<BillClaim>(ss, vch); break;
    case BILL_OP_DISCOUNT: Bind<BillDiscount>(ss, vch); break;
    case BILL_OP_RECOURSE: Bind<BillRecourse>(ss, vch); break;
    case BILL_OP_HRETIRE: Bind<BillHRetire>(ss, vch); break;
    case BILL_OP_HCLAIM: Bind<BillHClaim>(ss, vch); break;
    case BILL_OP_HRETIRE_NOTES: Bind<BillHRetireNotes>(ss, vch); break;
    case BILL_OP_HRETIRE_ESCROW: Bind<BillHRetireNotes>(ss, vch); break;   // the HRETIRE_NOTES payload
    case BILL_OP_HCLAIM_ESCROW: Bind<BillHClaimEscrow>(ss, vch); break;
    default: BindRaw(ss, vch);
    }
}

void BindHouse(CHashWriter& ss, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    switch (nOp) {
    case HOUSE_OP_REGISTER: Bind<HouseRegister>(ss, vch); break;
    case HOUSE_OP_TOPUP: Bind<HouseTopup>(ss, vch); break;
    case HOUSE_OP_ADMIT: Bind<HouseAdmit>(ss, vch); break;
    case HOUSE_OP_EXIT: Bind<HouseExit>(ss, vch); break;
    case HOUSE_OP_WINDDOWN: Bind<HouseWinddown>(ss, vch); break;
    case HOUSE_OP_RECLAIM: Bind<HouseReclaim>(ss, vch); break;
    case HOUSE_OP_ATTEST: Bind<HouseAttest>(ss, vch); break;
    case HOUSE_OP_DEFER: Bind<HouseDefer>(ss, vch); break;
    case HOUSE_OP_RENEW: Bind<HouseRenew>(ss, vch); break;
    case HOUSE_OP_RELEASE: Bind<HouseRelease>(ss, vch); break;
    case HOUSE_OP_REGISTER_MO: Bind<HouseRegisterMO>(ss, vch); break;
    case HOUSE_OP_MEMBER_ADD:
    case HOUSE_OP_MEMBER_REMOVE:
    case HOUSE_OP_MEMBER_PURGE: Bind<HouseMemberOp>(ss, vch); break;
    case HOUSE_OP_CLOSE: Bind<HouseClose>(ss, vch); break;
    case HOUSE_OP_RATE: Bind<HouseRate>(ss, vch); break;
    case HOUSE_OP_CHARTER: Bind<HouseCharter>(ss, vch); break;
    default: BindRaw(ss, vch);
    }
}

void BindNote(CHashWriter& ss, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    switch (nOp) {
    case NOTE_OP_MINT: Bind<NoteMint>(ss, vch); break;
    case NOTE_OP_TRANSFER: Bind<NoteTransfer>(ss, vch); break;
    case NOTE_OP_REDEEM: Bind<NoteRedeem>(ss, vch); break;
    case NOTE_OP_LOCK: Bind<NoteLock>(ss, vch); break;
    case NOTE_OP_UNLOCK: Bind<NoteUnlock>(ss, vch); break;
    case NOTE_OP_CLAIM: Bind<NoteClaim>(ss, vch); break;
    case NOTE_OP_DEMAND: Bind<NoteDemand>(ss, vch); break;
    case NOTE_OP_PROTEST: Bind<NoteProtest>(ss, vch); break;
    case NOTE_OP_TOKEN_KEYSET: Bind<NoteTokenKeyset>(ss, vch); break;
    case NOTE_OP_TOKEN_POST: Bind<NoteTokenPost>(ss, vch); break;
    case NOTE_OP_TOKEN_CLAIM: Bind<NoteTokenClaim>(ss, vch); break;
    case NOTE_OP_TOKEN_COLLECT: Bind<NoteTokenCollect>(ss, vch); break;
    case NOTE_OP_SWAP: Bind<NoteSwap>(ss, vch); break;
    case NOTE_OP_SWAP_DONE: Bind<NoteSwapDone>(ss, vch); break;
    case NOTE_OP_SWAP_PAY: Bind<NoteSwapPay>(ss, vch); break;
    case NOTE_OP_SWAP_PROTEST: Bind<NoteSwapProtest>(ss, vch); break;
    case NOTE_OP_SWAP_EXPIRE: Bind<NoteSwapExpire>(ss, vch); break;
    case NOTE_OP_SWAP_CLAIM: Bind<NoteSwapClaim>(ss, vch); break;
    default: BindRaw(ss, vch);
    }
}

void BindDeposit(CHashWriter& ss, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    switch (nOp) {
    case DEPOSIT_OP_ORIGINATE: Bind<DepositOriginate>(ss, vch); break;
    case DEPOSIT_OP_TRANSFER: Bind<DepositTransfer>(ss, vch); break;
    case DEPOSIT_OP_WITHDRAW: Bind<DepositWithdraw>(ss, vch); break;
    case DEPOSIT_OP_CLAIM: Bind<DepositClaim>(ss, vch); break;
    case DEPOSIT_OP_DEMAND: Bind<DepositDemand>(ss, vch); break;
    case DEPOSIT_OP_PROTEST: Bind<DepositProtest>(ss, vch); break;
    case DEPOSIT_OP_DISCHARGE: Bind<DepositDischarge>(ss, vch); break;
    default: BindRaw(ss, vch);
    }
}

void BindPool(CHashWriter& ss, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    switch (nOp) {
    case POOL_OP_CREATE: Bind<PoolCreate>(ss, vch); break;
    case POOL_OP_ADD_LIQ: Bind<PoolAddLiq>(ss, vch); break;
    case POOL_OP_REMOVE_LIQ: Bind<PoolRemoveLiq>(ss, vch); break;
    case POOL_OP_SWAP: Bind<PoolSwap>(ss, vch); break;
    case POOL_OP_RETIRE: Bind<PoolRetire>(ss, vch); break;
    default: BindRaw(ss, vch);
    }
}

void BindSettle(CHashWriter& ss, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    switch (nOp) {
    case SETTLE_OP_EXCHANGE: Bind<SettleExchange>(ss, vch); break;
    case SETTLE_OP_NET: Bind<SettleNet>(ss, vch); break;
    default: BindRaw(ss, vch);
    }
}

void BindIssued(CHashWriter& ss, uint8_t nOp, const std::vector<unsigned char>& vch)
{
    switch (nOp) {
    case ISSUED_OP_CREATE: Bind<IssuedCreate>(ss, vch); break;
    case ISSUED_OP_MINT: Bind<IssuedMint>(ss, vch); break;
    case ISSUED_OP_BURN: Bind<IssuedBurn>(ss, vch); break;
    case ISSUED_OP_FREEZE:
    case ISSUED_OP_UNFREEZE: Bind<IssuedFreeze>(ss, vch); break;
    case ISSUED_OP_POOL_CREATE: Bind<IssuedPoolCreate>(ss, vch); break;
    case ISSUED_OP_POOL_ADD: Bind<IssuedPoolAdd>(ss, vch); break;
    case ISSUED_OP_POOL_REMOVE: Bind<IssuedPoolRemove>(ss, vch); break;
    case ISSUED_OP_POOL_SWAP: Bind<IssuedPoolSwap>(ss, vch); break;
    default: BindRaw(ss, vch);   // TRANSFER's empty payload included
    }
}

} // namespace

bool IsCreditBindingVersion(int32_t nVersion)
{
    return nVersion >= TRANSACTION_BILL_VERSION && nVersion <= TRANSACTION_TOKEN_VERSION;
}

uint256 CreditBindingHash(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    switch (tx.nVersion) {
    case TRANSACTION_BILL_VERSION: ss << tx.nBillOp; BindBill(ss, tx.nBillOp, tx.vchBillPayload); break;
    case TRANSACTION_HOUSE_VERSION: ss << tx.nHouseOp; BindHouse(ss, tx.nHouseOp, tx.vchHousePayload); break;
    case TRANSACTION_NOTE_VERSION: ss << tx.nNoteOp; BindNote(ss, tx.nNoteOp, tx.vchNotePayload); break;
    case TRANSACTION_DEPOSIT_VERSION: ss << tx.nDepositOp; BindDeposit(ss, tx.nDepositOp, tx.vchDepositPayload); break;
    case TRANSACTION_POOL_VERSION: ss << tx.nPoolOp; BindPool(ss, tx.nPoolOp, tx.vchPoolPayload); break;
    case TRANSACTION_SETTLE_VERSION: ss << tx.nSettleOp; BindSettle(ss, tx.nSettleOp, tx.vchSettlePayload); break;
    case TRANSACTION_TOKEN_VERSION: ss << tx.nIssuedOp; BindIssued(ss, tx.nIssuedOp, tx.vchIssuedPayload); break;
    default: break;
    }
    // Gram-notes release: which outputs carry which issued units is the annex's alone, so it is bound whole.
    if (HasIssuedAnnex(tx.nVersion)) {
        ss << tx.vIssuedOut;
    }
    return ss.GetHash();
}
