// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bill.h>

#include <coins.h>            // Coin, for the shared payload-pure output tagger
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <note.h>             // NOTE_DUST_VALUE / MAX_NOTE_OUTPUTS / SumNoteUnits
#include <pubkey.h>
#include <script/standard.h>
#include <streams.h>
#include <version.h>

#include <set>

uint256 BillIDFromBody(const std::vector<unsigned char>& vchBody)
{
    uint256 hash;
    CSHA256().Write(vchBody.data(), vchBody.size()).Finalize(hash.begin());
    return hash;
}

uint256 BillIssueSigHash(const uint256& billID, const CAmount& amount, const CAmount& amountEscrow, uint32_t nMaturityHeight, uint32_t nGraceBlocks, const std::vector<unsigned char>& vchDrawerPubKey, const std::vector<unsigned char>& vchAcceptorPubKey, const std::vector<unsigned char>& vchHolderPubKey)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/issue");
    ss << billID;
    ss << amount;
    ss << amountEscrow;   // binds the posted bond -> no token-escrow replay
    ss << nMaturityHeight;
    ss << nGraceBlocks;
    ss << vchDrawerPubKey;
    ss << vchAcceptorPubKey;
    ss << vchHolderPubKey;
    return ss.GetHash();
}

uint256 BillEndorseSigHash(const uint256& billID, const std::vector<unsigned char>& vchTo, uint32_t nAtHeight)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/endorse");
    ss << billID;
    ss << vchTo;
    ss << nAtHeight;
    return ss.GetHash();
}

uint256 BillHashOutputs(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxOut& out : tx.vout)
        ss << out;
    return ss.GetHash();
}

uint256 BillRetireSigHash(const uint256& billID, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/retire");
    ss << billID;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 BillClaimSigHash(const uint256& billID, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/claim");
    ss << billID;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 BillHashPrevouts(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        ss << in.prevout;
    return ss.GetHash();
}

uint256 BillDiscountSigHash(const BillDiscount& x, const uint256& billID,
                            const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/discount");
    ss << x.nBillID;
    ss << billID;                 // canonical identity - immune to dense-id renumbering
    ss << x.nHouseID;
    ss << x.amountPrice;
    ss << x.amountFace;           // both parties sign the face they are trading
    ss << x.nBillMaturityHeight;
    ss << x.nNoteOutputs;
    ss << x.vUnits;
    ss << x.vchCustodyPubKey;
    ss << x.nExpiryHeight;
    ss << x.nAsOfHeight;
    ss << x.nPrevMintedUnits;
    ss << x.nPrevLoanBookFace;
    ss << x.nPrevLoanWtMatHi;
    ss << x.nPrevLoanWtMatLo;
    // The reserve proofs and the endorsement link ride OUTSIDE this digest: the
    // proofs carry their own per-coin challenge signatures, and the link carries
    // the classic BillEndorseSigHash by the same seller.
    ss << hashPrevouts;           // R-i6 - the sig authorizes consuming the title
    ss << hashOutputs;            // pins the title destination and every note output
    return ss.GetHash();
}

uint256 BillRecourseSigHash(const BillRecourse& x, const uint256& billID,
                            const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankBill/recourse");
    ss << x.nBillID;
    ss << billID;
    ss << x.vchPayerPubKey;
    ss << x.vchPrevHolderPubKey;
    ss << hashPrevouts;
    ss << hashOutputs;            // pins the payment to the holder
    return ss.GetHash();
}

CScript BillEscrowScript(const uint256& billID)
{
    return CScript() << std::vector<unsigned char>(billID.begin(), billID.end()) << OP_DROP << OP_TRUE;
}

bool IsBillEscrowScript(const CScript& script)
{
    // <32-byte push> OP_DROP OP_TRUE
    return script.size() == 35 && script[0] == 0x20 &&
           script[33] == OP_DROP && script[34] == OP_TRUE;
}

CScript BillScriptForPubKey(const std::vector<unsigned char>& vchPubKey)
{
    CPubKey pubkey(vchPubKey);
    return GetScriptForDestination(pubkey.GetID());
}

template <typename T>
bool DecodeBillPayload(const std::vector<unsigned char>& vch, T& payload)
{
    try {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> payload;
        if (!ss.empty())
            return false;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

template bool DecodeBillPayload<BillIssue>(const std::vector<unsigned char>&, BillIssue&);
template bool DecodeBillPayload<BillEndorse>(const std::vector<unsigned char>&, BillEndorse&);
template bool DecodeBillPayload<BillRetire>(const std::vector<unsigned char>&, BillRetire&);
template bool DecodeBillPayload<BillClaim>(const std::vector<unsigned char>&, BillClaim&);
template bool DecodeBillPayload<BillDiscount>(const std::vector<unsigned char>&, BillDiscount&);
template bool DecodeBillPayload<BillRecourse>(const std::vector<unsigned char>&, BillRecourse&);
template bool DecodeBillPayload<BillHRetire>(const std::vector<unsigned char>&, BillHRetire&);
template bool DecodeBillPayload<BillHClaim>(const std::vector<unsigned char>&, BillHClaim&);

void ApplyBillCoinTags(const CTransaction& tx, uint32_t n, Coin& coin)
{
    if (tx.nVersion != TRANSACTION_BILL_VERSION)
        return;

    if (tx.nBillOp == BILL_OP_ISSUE) {
        // vout[0] = title, vout[1] = the escrow bond.
        if (n < 2)
            coin.SetBill(n == 1 /* fEscrow */, 0);
        return;
    }
    if (tx.nBillOp == BILL_OP_ENDORSE) {
        if (n == 0)
            coin.SetBill(false, 0);
        return;
    }
    if (tx.nBillOp == BILL_OP_DISCOUNT) {
        // vout[0] = the title moving into house custody; vout[1..nNoteOutputs]
        // = the house's OWN notes, minted in this transaction as the
        // consideration. Both are consensus-locked, and the note leg is what the
        // seller is actually paid - it must reach the wallet's note machinery,
        // not its fee-coin pool.
        if (n == 0) {
            coin.SetBill(false, 0);
            return;
        }
        BillDiscount d;
        if (!DecodeBillPayload(tx.vchBillPayload, d))
            return;
        if (n >= 1 && (size_t)(n - 1) < d.vUnits.size() && n <= (uint32_t)d.nNoteOutputs)
            coin.SetNote(d.nHouseID, d.vUnits[n - 1], 0);
        return;
    }
    // RECOURSE / HRETIRE / HCLAIM create no tagged output: recourse pays the
    // holder in plain value, and the two terminal events pay out of the escrow.
}

static bool IsValidBillPubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;

    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

/** vout[1..n] of a DISCOUNT are note coins; same dust P2PKH shape a MINT pins
 * (note.cpp:23). Duplicated rather than exported, as IsValidBillPubKey /
 * IsValidNotePubKey already are - each family owns its own shape predicates. */
static bool IsBillNoteP2PKH(const CScript& script)
{
    // OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG
    return script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 &&
           script[2] == 0x14 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG;
}

/** Every B1 payload signature is born canonical: strict minimal DER (raw, no
 * sighash byte) AND low-S. The shipped ops 1-4 get the same treatment when A5's
 * VerifyStrict swap lands; ops 5-8 never have a malleable window at all, so a
 * relayed discount can never be re-encoded into a different txid and orphan a
 * child transaction built on it.
 *
 * This runs in the context-free path, which the ISSUE branch below deliberately
 * keeps ECDSA-free - so it is worth being explicit about why it is not the same
 * kind of cost. Neither predicate VERIFIES anything: CheckStrictDER is byte
 * inspection, and CheckLowS is a DER parse plus a scalar compare - no field or
 * group arithmetic, ~1000x cheaper than the verify that lives contextually.
 * The work is bounded by, and proportional to, bytes already received: at most
 * 2 + MAX_HOUSE_PARTNERS + MAX_ATTEST_PROOFS = 130 sigs of <= 72 bytes on the
 * largest op, under a payload cap that is itself the binding constraint. An
 * attacker gets no leverage he did not already have from making us deserialize
 * the payload at all. */
static bool IsCanonicalBillSig(const std::vector<unsigned char>& vchSig)
{
    return CPubKey::CheckStrictDER(vchSig) && CPubKey::CheckLowS(vchSig);
}

/** House M-of-N approver arrays: parallel, non-empty, strictly ascending,
 * bounded by the partner cap. Index ranges against the CURRENT partner set and
 * the ECDSA verifies are contextual (CheckBillOperation). Mirrors the MINT
 * approver shape checks at note.cpp:217-224. */
static bool CheckBillApproverShape(const std::vector<uint32_t>& vIndex,
                                   const std::vector<std::vector<unsigned char>>& vSig)
{
    if (vIndex.empty() || vIndex.size() != vSig.size() || vIndex.size() > MAX_HOUSE_PARTNERS)
        return false;
    for (size_t i = 0; i < vIndex.size(); i++) {
        if (i > 0 && vIndex[i] <= vIndex[i - 1])
            return false;
        if (vSig[i].empty() || vSig[i].size() > 80)
            return false;
    }
    return true;
}

bool CheckBillTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-bill-coinbase");

    if (tx.nBillOp < BILL_OP_ISSUE || tx.nBillOp > BILL_OP_HCLAIM)
        return state.DoS(100, false, REJECT_INVALID, "bad-bill-op");

    // Per-op payload ceilings. Ops 1-4 keep the shipped bound exactly (an ISSUE
    // carries the encrypted body); a DISCOUNT is the only op that can carry a
    // full approver set AND a full reserve-proof set, and the three small B1 ops
    // carry neither, so they get the tightest cap of the three.
    const size_t nPayloadCap =
            tx.nBillOp == BILL_OP_DISCOUNT ? MAX_BILL_DISCOUNT_PAYLOAD :
            (tx.nBillOp > BILL_OP_DISCOUNT ? MAX_BILL_OP_PAYLOAD : MAX_BILL_BODY_BYTES + 1024);
    if (tx.vchBillPayload.size() > nPayloadCap)
        return state.DoS(100, false, REJECT_INVALID, "bad-bill-payload-oversize");

    if (tx.nBillOp == BILL_OP_ISSUE) {
        BillIssue issue;
        if (!DecodeBillPayload(tx.vchBillPayload, issue))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-payload");

        if (issue.vchEncryptedBody.empty() || issue.vchEncryptedBody.size() > MAX_BILL_BODY_BYTES)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-body");
        if (issue.amount <= 0 || issue.amount > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-amount");
        if (issue.nMaturityHeight == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-maturity");
        if (issue.nGraceBlocks > MAX_BILL_GRACE_BLOCKS)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-grace");
        if (!IsValidBillPubKey(issue.vchDrawerPubKey) ||
                !IsValidBillPubKey(issue.vchAcceptorPubKey) ||
                !IsValidBillPubKey(issue.vchHolderPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-pubkey");

        // vout[0] = title to the initial holder, vout[1] = the escrow bond
        if (tx.vout.size() < 2)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-vout-size");
        if (tx.vout[0].nValue != BILL_TITLE_VALUE ||
                tx.vout[0].scriptPubKey != BillScriptForPubKey(issue.vchHolderPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-title");

        const uint256 billID = BillIDFromBody(issue.vchEncryptedBody);
        if (tx.vout[1].nValue <= 0 ||
                tx.vout[1].scriptPubKey != BillEscrowScript(billID))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-issue-escrow");

        // NB: the drawer/acceptor ECDSA verifies are deliberately NOT done here.
        // CheckBillTransactionShape runs in the context-free CheckTransaction
        // path (before inputs/fees are checked), so verifying signatures here
        // would let a stream of orphan v11 txs force free CPU. The two verifies
        // run in CheckBillOperation (validation.cpp), after CheckTxInputs.
    }
    else
    if (tx.nBillOp == BILL_OP_ENDORSE) {
        BillEndorse endorse;
        if (!DecodeBillPayload(tx.vchBillPayload, endorse))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-payload");

        if (!IsValidBillPubKey(endorse.endorsement.vchFrom) ||
                !IsValidBillPubKey(endorse.endorsement.vchTo))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-pubkey");

        // vout[0] = the title moving to the endorsee. The endorsement
        // signature needs the bill hash, so it is checked contextually.
        if (tx.vout.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-vout-size");
        if (tx.vout[0].nValue != BILL_TITLE_VALUE ||
                tx.vout[0].scriptPubKey != BillScriptForPubKey(endorse.endorsement.vchTo))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-endorse-title");
    }
    else
    if (tx.nBillOp == BILL_OP_RETIRE) {
        BillRetire retire;
        if (!DecodeBillPayload(tx.vchBillPayload, retire))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-retire-payload");
    }
    else
    if (tx.nBillOp == BILL_OP_CLAIM) {
        BillClaim claim;
        if (!DecodeBillPayload(tx.vchBillPayload, claim))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-claim-payload");
    }
    else
    if (tx.nBillOp == BILL_OP_DISCOUNT) {
        BillDiscount d;
        if (!DecodeBillPayload(tx.vchBillPayload, d))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-payload");

        if (d.nBillID == 0 || d.nHouseID == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-ids");

        // The <= face rail is payload-pure - both quantities are bound into the
        // shared digest and byte-exact-pinned to the record at connect - so it
        // is a SHAPE rule, not a contextual one: a house may never book a bill
        // above its face, and a discount at zero is not a purchase.
        if (d.amountFace <= 0 || d.amountFace > MAX_MONEY ||
                d.amountPrice <= 0 || d.amountPrice > d.amountFace)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-price-range");
        if (d.nBillMaturityHeight == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-maturity");

        // The priced note leg: one coin per unit entry, summing EXACTLY to the
        // price. SumNoteUnits is the shipped MINT helper - non-empty, every
        // entry >= 1, overflow-safe and money-ranged.
        uint64_t nUnitsTotal = 0;
        if (d.vUnits.size() > MAX_NOTE_OUTPUTS ||
                (size_t)d.nNoteOutputs != d.vUnits.size() ||
                !SumNoteUnits(d.vUnits, nUnitsTotal) ||
                nUnitsTotal != (uint64_t)d.amountPrice)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-units");

        if (!IsValidBillPubKey(d.vchCustodyPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-custody-shape");
        // Mandatory, bounded expiry: a signed discount must not sit around as a
        // free option on the house's own credit.
        if (d.nExpiryHeight == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-no-expiry");

        // The stored link must move the title from the seller to the pinned
        // custody key, so the endorsement chain stays verifiable from CBill alone.
        if (!IsValidBillPubKey(d.endorsement.vchFrom) ||
                !IsValidBillPubKey(d.endorsement.vchTo) ||
                d.endorsement.vchTo != d.vchCustodyPubKey)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-link-shape");
        // ...and the custody key may not sell to itself: that would mint notes
        // against paper the house already holds, with no seller being paid.
        if (d.endorsement.vchFrom == d.vchCustodyPubKey)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-self-purchase");

        if (!CheckBillApproverShape(d.vApproverIndex, d.vApproverSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-approver-shape");

        // Every discount MINTS, so the rho-at-mint reserve proof set (R-i7) is
        // unconditionally required - an empty set is invalid outright, and is
        // caught here rather than costing a DB read to discover.
        if (d.vReserveProofs.empty() || d.vReserveProofs.size() > MAX_ATTEST_PROOFS)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-proofs-shape");
        std::set<COutPoint> setProof;
        for (const AttestProof& p : d.vReserveProofs) {
            if (p.vchPubKey.size() != 33 || p.vchSig.empty() || p.vchSig.size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-proofs-shape");
            if (p.outpoint.IsNull() || !setProof.insert(p.outpoint).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-proofs-shape");
        }

        // Born strict: seller, stored endorsement, every approver, every proof.
        if (!IsCanonicalBillSig(d.vchSellerSig) || !IsCanonicalBillSig(d.endorsement.vchSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-sig-encoding");
        for (const std::vector<unsigned char>& vchSig : d.vApproverSig) {
            if (!IsCanonicalBillSig(vchSig))
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-sig-encoding");
        }
        for (const AttestProof& p : d.vReserveProofs) {
            if (!IsCanonicalBillSig(p.vchSig))
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-sig-encoding");
        }

        // vout[0] = the title moving into custody; vout[1..n] = the priced note
        // leg. Everything past that is free change at this layer; the
        // no-side-payment rule (and vout[0]'s exemption from it) is contextual.
        if (tx.vout.size() < (size_t)1 + d.nNoteOutputs)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-vout-size");
        if (tx.vout[0].nValue != BILL_TITLE_VALUE ||
                tx.vout[0].scriptPubKey != BillScriptForPubKey(d.vchCustodyPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-title-out");
        for (size_t i = 1; i <= (size_t)d.nNoteOutputs; i++) {
            if (tx.vout[i].nValue != NOTE_DUST_VALUE ||
                    !IsBillNoteP2PKH(tx.vout[i].scriptPubKey))
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-discount-note-out");
        }
    }
    else
    if (tx.nBillOp == BILL_OP_RECOURSE) {
        BillRecourse r;
        if (!DecodeBillPayload(tx.vchBillPayload, r))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-recourse-payload");

        if (r.nBillID == 0 ||
                !IsValidBillPubKey(r.vchPayerPubKey) ||
                !IsValidBillPubKey(r.vchPrevHolderPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-recourse-fields");
        // One key paying itself is not a cure, it is a way to strip a bill out
        // of a loan book without the house quorum HCLAIM requires. The other
        // half of that fix - recourse is legal ONLY on a bill that is not
        // house-held - needs the record, so it lives in CheckBillOperation.
        if (r.vchPayerPubKey == r.vchPrevHolderPubKey)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-recourse-self");
        if (!IsCanonicalBillSig(r.vchPayerSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-recourse-sig-encoding");
    }
    else
    if (tx.nBillOp == BILL_OP_HRETIRE) {
        BillHRetire h;
        if (!DecodeBillPayload(tx.vchBillPayload, h))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-hretire-payload");

        if (h.nBillID == 0 || h.nOwnerHouseID == 0 ||
                h.amountFace <= 0 || h.amountFace > MAX_MONEY ||
                h.nBillMaturityHeight == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-hretire-fields");
        if (!IsCanonicalBillSig(h.vchAcceptorSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-hretire-sig-encoding");
    }
    else
    if (tx.nBillOp == BILL_OP_HCLAIM) {
        BillHClaim h;
        if (!DecodeBillPayload(tx.vchBillPayload, h))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-hclaim-payload");

        if (h.nBillID == 0 || h.nOwnerHouseID == 0 ||
                h.amountFace <= 0 || h.amountFace > MAX_MONEY ||
                h.nBillMaturityHeight == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-hclaim-fields");
        // The quorum REPLACES the single holder signature here, so its shape is
        // load-bearing: no approvers means no authority at all.
        if (!CheckBillApproverShape(h.vApproverIndex, h.vApproverSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-bill-hclaim-approver-shape");
        for (const std::vector<unsigned char>& vchSig : h.vApproverSig) {
            if (!IsCanonicalBillSig(vchSig))
                return state.DoS(100, false, REJECT_INVALID, "bad-bill-hclaim-sig-encoding");
        }
    }

    return true;
}

CAmount BillValuePaidTo(const CTransaction& tx, const std::vector<unsigned char>& vchPubKey)
{
    const CScript script = BillScriptForPubKey(vchPubKey);

    CAmount nValue = 0;
    for (const CTxOut& out : tx.vout) {
        if (out.scriptPubKey == script)
            nValue += out.nValue;
    }
    return nValue;
}

CAmount BillEndorseFeeFloor(size_t nLen)
{
    if (nLen <= BILL_ENDORSE_SOFT_CAP)
        return CAmount(0);

    size_t nShift = nLen - BILL_ENDORSE_SOFT_CAP;
    if (nShift > 30)
        nShift = 30;

    return BILL_ENDORSE_BASE_FEE << nShift;
}
