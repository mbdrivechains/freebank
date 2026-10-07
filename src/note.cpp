// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <note.h>

#include <house.h>   // BLOCKS_PER_YEAR (deferral interest)

#include <coins.h>   // Coin, for the shared payload-pure output tagger
#include <consensus/validation.h>
#include <algorithm>
#include <hash.h>
#include <set>
#include <pubkey.h>
#include <script/standard.h>
#include <streams.h>
#include <version.h>

CScript NoteScriptForPubKey(const std::vector<unsigned char>& vchPubKey)
{
    CPubKey pubkey(vchPubKey);
    return GetScriptForDestination(pubkey.GetID());
}

static bool IsNoteP2PKH(const CScript& script)
{
    // OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG
    return script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 &&
           script[2] == 0x14 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG;
}

CScript NotePreAuthScript(const std::vector<unsigned char>& vchPubKey)
{
    const CKeyID keyid = CPubKey(vchPubKey).GetID();
    return CScript() << std::vector<unsigned char>(keyid.begin(), keyid.end()) << OP_DROP << OP_TRUE;
}

bool IsNotePreAuthScript(const CScript& script)
{
    // <20-byte push> OP_DROP OP_TRUE - the escrow family with a keyid-sized
    // push (the escrows push 32). Shape only; WHICH keyid is contextual.
    return script.size() == 23 && script[0] == 0x14 &&
           script[21] == OP_DROP && script[22] == OP_TRUE;
}

uint256 NoteHashPrevouts(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        ss << in.prevout;
    return ss.GetHash();
}

uint256 NoteMintSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/mint");
    ss << nHouseID;
    ss << vUnits;
    ss << hashPrevouts;   // tx-unique -> a mint's approver sigs are not replayable
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteTransferSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/transfer");
    ss << nHouseID;
    ss << vUnits;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteRedeemSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/redeem");
    ss << nHouseID;
    ss << nUnitsBurned;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteClaimSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/claim");
    ss << nHouseID;
    ss << nUnitsBurned;
    ss << hashOutputs;   // binds payout + escrow change exactly
    return ss.GetHash();
}

uint256 NoteDemandSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/demand");
    ss << nHouseID;
    ss << vUnits;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NotePreAuthSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits,
                           const std::vector<unsigned char>& vchPayoutScript)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/preauth");   // domain-separated: NOT the demand digest
    ss << nHouseID;
    ss << vUnits;
    ss << vchPayoutScript;
    return ss.GetHash();
}

uint256 NoteProtestSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/protest");
    ss << nHouseID;
    ss << vUnits;
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteLockSigHash(uint32_t nHouseID, uint64_t nUnits, const std::vector<uint64_t>& vChangeUnits,
                        const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/lock");
    ss << nHouseID;
    ss << nUnits;
    ss << vChangeUnits;
    ss << hashPrevouts;   // tx-unique -> neither signer's approval is replayable
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 NoteUnlockSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits,
                          const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankNote/unlock");
    ss << nHouseID;
    ss << vUnits;
    ss << hashPrevouts;   // tx-unique -> an unlock's approvals are not replayable
    ss << hashOutputs;
    return ss.GetHash();
}

uint32_t DeferInterestBpsAt(const std::vector<Consensus::DeferInterestStep>& vSchedule, uint32_t nHeight)
{
    uint32_t nBps = 0;
    for (const Consensus::DeferInterestStep& step : vSchedule) {
        if (step.nHeight > nHeight)
            break;
        nBps = step.nBps;
    }
    return nBps;
}

CAmount NoteDeferralInterest(uint64_t nUnits, uint32_t nFrom, uint32_t nTo,
                             const std::vector<Consensus::DeferInterestStep>& vSchedule)
{
    if (nUnits == 0 || nTo <= nFrom)
        return 0;
    // Sum bps*blocks over the schedule segments that overlap [nFrom, nTo).
    // Segment i covers [step_i.nHeight, step_{i+1}.nHeight) (the last one is
    // open-ended). Blocks before the first step accrue nothing (the schedule
    // starts at 0 on every network, so that range is empty in practice).
    unsigned __int128 bpsBlocks = 0;
    for (size_t i = 0; i < vSchedule.size(); i++) {
        const uint64_t nSegFrom = vSchedule[i].nHeight;
        const uint64_t nSegTo = (i + 1 < vSchedule.size()) ? (uint64_t)vSchedule[i + 1].nHeight
                                                            : (uint64_t)nTo;
        const uint64_t a = std::max<uint64_t>(nSegFrom, nFrom);
        const uint64_t b = std::min<uint64_t>(nSegTo, nTo);
        if (b > a)
            bpsBlocks += (unsigned __int128)vSchedule[i].nBps * (unsigned __int128)(b - a);
    }
    // units * sum(bps*blocks) / (10000 * blocks_per_year); 128-bit throughout
    // (units <= 2^64, sum <= 2^32 * 2^32 -> product < 2^128).
    const unsigned __int128 num = (unsigned __int128)nUnits * bpsBlocks;
    const unsigned __int128 den = (unsigned __int128)10000 * (unsigned __int128)BLOCKS_PER_YEAR;
    unsigned __int128 interest = num / den;
    // Never let interest alone leave the money range (a pathological block
    // count would otherwise wrap the payout arithmetic).
    if (interest > (unsigned __int128)MAX_MONEY)
        interest = (unsigned __int128)MAX_MONEY;
    return (CAmount)interest;
}

void NoteDemandAccrualWindow(const CHouse& house, uint32_t nDemandTag, uint32_t nPayHeight,
                             uint32_t nDemandWindow, uint32_t& nStartOut, uint32_t& nEndOut)
{
    // THE TAG IS READ MASKED: the raw field carries the B3 marker bits (bit 31
    // pre-auth, bit 30 protested); reading it raw made the height ~2^31 and the
    // floor vanish on exactly the coins B3 protects.
    const uint32_t nDemandHeight = NoteDemandHeightOf(nDemandTag);
    // D-iii (operator-signed 2026-08-04): a B3 formal demand (pre-auth, filed at
    // Open/Stressed) starts at window LAPSE ("pay in a week and it costs you
    // par"). The suspension queue - every plain demand, and a pre-auth demand
    // carrying the queue marker (v0.2.18) - accrues from the demand itself.
    uint32_t nStart = nDemandHeight;
    if (!NoteDemandAccruesFromDemand(nDemandTag))
        nStart += nDemandWindow;
    // Q8 (operator-signed 2026-10-02): accrue until PAID, except after a reopen
    // E with the house open at payment:
    //  - paid within W of E (INCLUSIVE: paying at E + W is in time): stop at E;
    //  - later, a QUEUE demand (plain, or pre-auth with the queue marker) stops
    //    at E + W (Q8 follow-up "b": no perpetual bond). For a plain demand the
    //    house cannot pay alone, so the holder's week to cash in at par ends the
    //    clock. For a pre-auth queue demand the holder's remedy after that week
    //    is PROTEST (its window also starts at E), not more interest - which
    //    also closes the side door of upgrading a plain demand long after the
    //    reopen to restart its clock;
    //  - later, a B3 formal demand (filed at Open) keeps accruing to payment, as
    //    before: the house can discharge it alone at any time.
    // A demand in the same block as the reopen (D == E) has a zero window. A
    // payment while the house is suspended again accrues to payment: a reopen
    // followed by re-suspension can never freeze a clock. (A queue demand from
    // an older episode paid during a later suspension may thereby also accrue
    // across the open gap between them; the house record keeps only the latest
    // episode, and the error is in the holder's favour.)
    uint32_t nEnd = nPayHeight;
    const uint32_t E = house.nDeferEndedHeight;
    if (house.nDeferInvokedHeight == 0 && E != 0 && E >= nDemandHeight && E < nPayHeight) {
        const uint64_t nCap = (uint64_t)E + nDemandWindow;
        if ((uint64_t)nPayHeight <= nCap)
            nEnd = E;
        else if (NoteDemandAccruesFromDemand(nDemandTag))
            nEnd = (uint32_t)nCap;
    }
    nStartOut = nStart;
    nEndOut = nEnd;
}

CAmount NoteDemandInterest(const CHouse& house, uint32_t nDemandTag, uint64_t nUnits,
                           uint32_t nPayHeight, const Consensus::Params& consensus)
{
    if (NoteDemandHeightOf(nDemandTag) == 0)
        return 0;
    uint32_t nStart = 0, nEnd = 0;
    NoteDemandAccrualWindow(house, nDemandTag, nPayHeight, consensus.nDemandWindow, nStart, nEnd);
    // A QUEUE demand from an earlier episode, paid while the house is suspended
    // AGAIN after an open gap longer than the holder's week: it accrues to the
    // end of that week (E + W) and again from the new suspension (I) to payment,
    // but not across the open gap - the holder could have cashed in at par there,
    // and for a plain demand the house could not pay it alone. A re-suspension
    // INSIDE the week (I <= E + W) accrues continuously (the window above).
    const uint32_t E = house.nDeferEndedHeight, I = house.nDeferInvokedHeight;
    const uint64_t nCap = (uint64_t)E + consensus.nDemandWindow;
    if (I != 0 && E != 0 && E >= NoteDemandHeightOf(nDemandTag) && NoteDemandAccruesFromDemand(nDemandTag) &&
            (uint64_t)I > nCap && I < nPayHeight && nStart < nCap) {
        return NoteDeferralInterest(nUnits, nStart, (uint32_t)nCap, consensus.vDeferInterestSchedule) +
               NoteDeferralInterest(nUnits, I, nPayHeight, consensus.vDeferInterestSchedule);
    }
    return NoteDeferralInterest(nUnits, nStart, nEnd, consensus.vDeferInterestSchedule);
}

CAmount NoteClaimEntitlement(uint64_t nUnits, const CAmount& amountPot, uint64_t nSnapshotUnits)
{
    if (nSnapshotUnits == 0 || amountPot <= 0 || nUnits == 0)
        return 0;
    // nUnits <= 3*MAX_MONEY and amountPot <= MAX_MONEY: the product needs
    // ~104 bits - 128-bit intermediate, then the min() caps at par.
    const unsigned __int128 prorata =
        (unsigned __int128)nUnits * (unsigned __int128)amountPot / (unsigned __int128)nSnapshotUnits;
    const unsigned __int128 par = (unsigned __int128)nUnits;
    const unsigned __int128 take = prorata < par ? prorata : par;
    return (CAmount)take;
}

CAmount HouseResidualShare(const CAmount& amountPledge, const CAmount& amountResidual, const CAmount& amountPledgeSum)
{
    if (amountPledgeSum <= 0 || amountResidual <= 0 || amountPledge <= 0)
        return 0;
    return (CAmount)((unsigned __int128)amountPledge * (unsigned __int128)amountResidual
                     / (unsigned __int128)amountPledgeSum);
}

bool SumNoteUnits(const std::vector<uint64_t>& vUnits, uint64_t& total)
{
    total = 0;
    if (vUnits.empty())
        return false;
    for (const uint64_t u : vUnits) {
        if (u == 0)
            return false;
        // Overflow-safe; also keep the total inside the money range so it can
        // never wrap when combined with nMintedUnits / the escrow cap.
        if (u > (uint64_t)MAX_MONEY || total > (uint64_t)MAX_MONEY - u)
            return false;
        total += u;
    }
    return true;
}

template <typename T>
bool DecodeNotePayload(const std::vector<unsigned char>& vch, T& payload)
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

template bool DecodeNotePayload<NoteMint>(const std::vector<unsigned char>&, NoteMint&);
template bool DecodeNotePayload<NoteTransfer>(const std::vector<unsigned char>&, NoteTransfer&);
template bool DecodeNotePayload<NoteRedeem>(const std::vector<unsigned char>&, NoteRedeem&);
template bool DecodeNotePayload<NoteClaim>(const std::vector<unsigned char>&, NoteClaim&);
template bool DecodeNotePayload<NoteDemand>(const std::vector<unsigned char>&, NoteDemand&);
template bool DecodeNotePayload<NoteProtest>(const std::vector<unsigned char>&, NoteProtest&);
template bool DecodeNotePayload<NoteLock>(const std::vector<unsigned char>&, NoteLock&);
template bool DecodeNotePayload<NoteUnlock>(const std::vector<unsigned char>&, NoteUnlock&);

void ApplyNoteCoinTags(const CTransaction& tx, uint32_t n, Coin& coin, bool fConnected, uint32_t nHeight)
{
    if (tx.nVersion != TRANSACTION_NOTE_VERSION)
        return;

    // A note carries its house and unit split in the PAYLOAD, so the tag needs
    // no threaded id and connect == rollforward == mempool. MINT, TRANSFER,
    // DEMAND and PROTEST create note outputs at vout[0..vUnits-1].
    if (tx.nNoteOp == NOTE_OP_MINT) {
        NoteMint m;
        if (DecodeNotePayload(tx.vchNotePayload, m) && m.nHouseID != 0 && n < m.vUnits.size())
            coin.SetNote(m.nHouseID, m.vUnits[n], 0);
    } else if (tx.nNoteOp == NOTE_OP_TRANSFER) {
        // Carries the payload's demand height forward (tx_verify has forced it
        // to equal the spent notes'), so a demanded note keeps its interest
        // clock when it changes hands.
        NoteTransfer x;
        if (DecodeNotePayload(tx.vchNotePayload, x) && x.nHouseID != 0 && n < x.vUnits.size())
            coin.SetNote(x.nHouseID, x.vUnits[n], x.nDemandHeight);
    } else if (tx.nNoteOp == NOTE_OP_DEMAND) {
        // B3: a fresh demand stamps the height it confirms at; the delta-1b
        // upgrade re-stamps the PRIOR height (tx_verify has forced it to equal
        // the spent coins'), so the clock is preserved rather than reset. The
        // pre-auth bit rides in the same field - see NOTE_DEMAND_PREAUTH_BIT
        // (D-i: no Coin format change, so no fleet -reindex). Unconfirmed, a
        // fresh demand's stamp is unknown: tag 0, and spending it is refused.
        NoteDemand d;
        if (DecodeNotePayload(tx.vchNotePayload, d) && d.nHouseID != 0 && n < d.vUnits.size()) {
            uint32_t nTag = 0;
            if (d.nPriorDemandHeight != 0)
                nTag = NoteDemandTag(d.nPriorDemandHeight, d.fPreAuth);
            else if (fConnected)
                nTag = NoteDemandTag(nHeight, d.fPreAuth);
            coin.SetNote(d.nHouseID, d.vUnits[n], nTag);
        }
    } else if (tx.nNoteOp == NOTE_OP_PROTEST) {
        // Re-issued UNCHANGED: same units, same tag. A protest asserts a claim;
        // it must not alter it.
        NoteProtest pro;
        if (DecodeNotePayload(tx.vchNotePayload, pro) && pro.nHouseID != 0 && n < pro.vUnits.size())
            coin.SetNote(pro.nHouseID, pro.vUnits[n], pro.nDemandTag);
    } else if (tx.nNoteOp == NOTE_OP_LOCK) {
        // v0.2.20: a lock's change notes go back to the holder, undemanded
        // (only undemanded notes can be locked).
        NoteLock l;
        if (DecodeNotePayload(tx.vchNotePayload, l) && l.nHouseID != 0 && n < l.vChangeUnits.size())
            coin.SetNote(l.nHouseID, l.vChangeUnits[n], 0);
    } else if (tx.nNoteOp == NOTE_OP_UNLOCK) {
        // v0.2.20: released backing becomes ordinary undemanded notes.
        NoteUnlock u;
        if (DecodeNotePayload(tx.vchNotePayload, u) && u.nHouseID != 0 && n < u.vUnits.size())
            coin.SetNote(u.nHouseID, u.vUnits[n], 0);
    } else if (tx.nNoteOp == NOTE_OP_REDEEM && n == 1) {
        // The dynamic-brassage spread (3.5) is an escrow output at vout[1].
        NoteRedeem r;
        if (DecodeNotePayload(tx.vchNotePayload, r) && r.fBrassage)
            coin.SetHouseEscrow(fConnected ? r.nHouseID : 0);
    } else if (tx.nNoteOp == NOTE_OP_CLAIM && n == 1) {
        // An insolvency claim may return escrow change at vout[1]; the
        // contextual check pinned its script to the canonical escrow script
        // before this coin can exist.
        NoteClaim c;
        if (DecodeNotePayload(tx.vchNotePayload, c) && c.fEscrowChange)
            coin.SetHouseEscrow(fConnected ? c.nHouseID : 0);
    }
}

static bool IsValidNotePubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

/** vout[0..nUnits-1] must each be a dust-valued note output: P2PKH normally,
 * or (fCustody, B3) the consensus-custody shape a pre-auth re-issue moves the
 * coins onto. Shape only; the exact keyid inside a custody script is
 * contextual (it must be the demanding holder's - CheckNoteOperation). */
static bool CheckNoteOutputs(const CTransaction& tx, size_t nUnits, CValidationState& state,
                             bool fCustody = false)
{
    if (nUnits == 0 || nUnits > MAX_NOTE_OUTPUTS)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-units-count");
    if (tx.vout.size() < nUnits)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-vout-size");
    for (size_t i = 0; i < nUnits; i++) {
        if (tx.vout[i].nValue != NOTE_DUST_VALUE)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-output-value");
        if (fCustody ? !IsNotePreAuthScript(tx.vout[i].scriptPubKey)
                     : !IsNoteP2PKH(tx.vout[i].scriptPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-output-script");
    }
    return true;
}

/** The approver-array shape MINT checks inline (non-empty, sized, strictly
 * ascending, sanely bounded sigs), for LOCK and UNLOCK. Index ranges against the
 * partner set and the ECDSA are contextual (VerifyHouseApprovers). */
static bool CheckNoteApproverShape(const std::vector<uint32_t>& vIndex, const std::vector<std::vector<unsigned char>>& vSig)
{
    if (vIndex.empty() || vIndex.size() != vSig.size())
        return false;
    for (size_t i = 0; i < vIndex.size(); i++) {
        if (i > 0 && vIndex[i] <= vIndex[i - 1])
            return false;
        if (vSig[i].empty() || vSig[i].size() > 80)
            return false;
    }
    return true;
}

bool CheckNoteTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-note-coinbase");

    // v0.2.20: LOCK (4) and UNLOCK (5), reserved inert since v1, are live (the
    // token mint and burn record, D-2026-10-08-1).
    if (tx.nNoteOp < NOTE_OP_MINT || tx.nNoteOp > NOTE_OP_PROTEST)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-op");

    // 100 outputs x u64 + M approver sigs + (MINT, R-i7) up to 64 reserve proofs
    // (~145 B each); bounded well above the worst case.
    if (tx.vchNotePayload.size() > 32768)
        return state.DoS(100, false, REJECT_INVALID, "bad-note-payload-oversize");

    if (tx.nNoteOp == NOTE_OP_MINT) {
        NoteMint mint;
        if (!DecodeNotePayload(tx.vchNotePayload, mint))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(mint.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-units");
        if (!CheckNoteOutputs(tx, mint.vUnits.size(), state))
            return false;

        // Approver arrays: non-empty, ascending, sized, sanely bounded. Index
        // ranges vs the current partner set are contextual; ECDSA is contextual.
        if (mint.vApproverIndex.empty() || mint.vApproverIndex.size() != mint.vApproverSig.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-approvers");
        for (size_t i = 0; i < mint.vApproverIndex.size(); i++) {
            if (i > 0 && mint.vApproverIndex[i] <= mint.vApproverIndex[i - 1])
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-approvers");
            if (mint.vApproverSig[i].empty() || mint.vApproverSig[i].size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-approvers");
        }

        // R-i7 reserve proof (context-free shape only; ECDSA + liveness are
        // contextual). Bound the set and each proof's key/sig, and require
        // unique outpoints - mirrors the HOUSE_OP_ATTEST proof shape checks.
        if (mint.vReserveProofs.size() > MAX_ATTEST_PROOFS)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-count");
        std::set<COutPoint> setProof;
        for (const AttestProof& p : mint.vReserveProofs) {
            if (p.vchPubKey.size() != 33)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-pubkey");
            if (p.vchSig.empty() || p.vchSig.size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-sig");
            if (!setProof.insert(p.outpoint).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-mint-reserve-dup");
        }
    }
    else if (tx.nNoteOp == NOTE_OP_TRANSFER) {
        NoteTransfer xfer;
        if (!DecodeNotePayload(tx.vchNotePayload, xfer))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(xfer.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-units");
        if (!CheckNoteOutputs(tx, xfer.vUnits.size(), state))
            return false;
        if (!IsValidNotePubKey(xfer.vchSenderPubKey) ||
                xfer.vchSenderSig.empty() || xfer.vchSenderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-transfer-auth");
    }
    else if (tx.nNoteOp == NOTE_OP_REDEEM) {
        NoteRedeem redeem;
        if (!DecodeNotePayload(tx.vchNotePayload, redeem))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-payload");

        // A DISCHARGE (B3) carries no fresh holder signature - that is its
        // entire point - so the holder-sig requirement applies only to the
        // plain form. The holder KEY is always required: it is what the
        // pre-auth digest verifies against, and what the burned inputs must
        // hash to either way.
        if (!IsValidNotePubKey(redeem.vchHolderPubKey))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-auth");
        if (!redeem.fPreAuthDischarge &&
                (redeem.vchHolderSig.empty() || redeem.vchHolderSig.size() > 80))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-auth");
        if (redeem.fBrassage > 1)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-flag");
        if (redeem.fPreAuthDischarge > 1)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-discharge-flag");
        // Discharge fields are all-or-nothing, both directions (the T-b2 demand
        // rule, same reasoning): units+script+sig present iff discharging.
        if (redeem.fPreAuthDischarge) {
            uint64_t nAuthTotal = 0;
            if (!SumNoteUnits(redeem.vPreAuthUnits, nAuthTotal))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-discharge-units");
            if (redeem.vchPayoutScript.empty() || redeem.vchPayoutScript.size() > MAX_NOTE_PAYOUT_SCRIPT)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-discharge-script");
            if (redeem.vchPreAuthSig.empty() || redeem.vchPreAuthSig.size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-discharge-sig");
            if (!redeem.vchHolderSig.empty())
                return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-discharge-extra-sig");
        } else if (!redeem.vPreAuthUnits.empty() || !redeem.vchPayoutScript.empty() ||
                   !redeem.vchPreAuthSig.empty()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-discharge-unexpected");
        }
        // vout[0] = holder payout; vout[1] = the brassage escrow output when
        // flagged. The spread AMOUNT, the escrow script and the >= U payout are
        // contextual (they need the house record and the spent inputs' units).
        if (tx.vout.empty() || (redeem.fBrassage && tx.vout.size() < 2))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-redeem-vout");
    }
    else if (tx.nNoteOp == NOTE_OP_DEMAND) {
        NoteDemand dem;
        if (!DecodeNotePayload(tx.vchNotePayload, dem))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(dem.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-units");
        // The notes are RE-ISSUED, not surrendered. A plain (Deferred-era)
        // demand keeps the dust-P2PKH transfer shape; a PRE-AUTH demand moves
        // the coins onto the consensus-custody script - the holder signed away
        // unilateral control, and the house must be able to discharge alone.
        if (!CheckNoteOutputs(tx, dem.vUnits.size(), state, dem.fPreAuth != 0))
            return false;
        if (!IsValidNotePubKey(dem.vchHolderPubKey) ||
                dem.vchHolderSig.empty() || dem.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-auth");
        // B3: the PRE-AUTH leg. Shape only - WHICH house states require or
        // forbid it is contextual (T-b3), because it depends on the house
        // record. Here we pin that the flag is a real boolean and that the two
        // pre-auth fields are present exactly when it is set: a payload
        // carrying a payout script with fPreAuth clear would be a standing
        // authorisation consensus never checks, and fPreAuth set with no script
        // would be a discharge target that cannot exist.
        if (dem.fPreAuth > NOTE_DEMAND_MODE_PREAUTH_QUEUE)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-flag");
        if (dem.fPreAuth) {
            // A payout script must be a plausible standard script - it is what
            // the house is forced to pay, and consensus compares it literally.
            if (dem.vchPayoutScript.empty() || dem.vchPayoutScript.size() > MAX_NOTE_PAYOUT_SCRIPT)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-preauth-script");
            if (dem.vchPreAuthSig.empty() || dem.vchPreAuthSig.size() > 80)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-preauth-sig");
        } else if (!dem.vchPayoutScript.empty() || !dem.vchPreAuthSig.empty()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-note-demand-preauth-unexpected");
        }
    }
    else if (tx.nNoteOp == NOTE_OP_PROTEST) {
        NoteProtest pro;
        if (!DecodeNotePayload(tx.vchNotePayload, pro))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-protest-payload");

        uint64_t total = 0;
        if (!SumNoteUnits(pro.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-protest-units");
        // Same spend-and-re-issue shape as a pre-auth DEMAND: the coins stay in
        // consensus custody (only pre-auth coins can be protested), re-issued
        // to the same holder's custody script. Standing is proven by the
        // holder's payload signature - the custody script is script-level open,
        // so the scriptSig proves nothing here.
        if (!CheckNoteOutputs(tx, pro.vUnits.size(), state, /*fCustody=*/true))
            return false;
        if (!IsValidNotePubKey(pro.vchHolderPubKey) ||
                pro.vchHolderSig.empty() || pro.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-protest-auth");
    }
    else if (tx.nNoteOp == NOTE_OP_CLAIM) {
        NoteClaim claim;
        if (!DecodeNotePayload(tx.vchNotePayload, claim))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-payload");

        if (!IsValidNotePubKey(claim.vchHolderPubKey) ||
                claim.vchHolderSig.empty() || claim.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-auth");
        if (claim.fEscrowChange > 1)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-flag");
        // vout[0] = payout; escrow change (if flagged) lives at vout[1] with
        // the canonical escrow script (script + entitlement are contextual -
        // they need the house record and the insolvency snapshot).
        if (tx.vout.empty() || (claim.fEscrowChange && tx.vout.size() < 2))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-claim-vout");
    }
    else if (tx.nNoteOp == NOTE_OP_LOCK) {
        NoteLock lock;
        if (!DecodeNotePayload(tx.vchNotePayload, lock))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-lock-payload");
        if (lock.nUnits == 0 || lock.nUnits > (uint64_t)MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-lock-units");
        // Change is optional; when present it is note outputs at vout[0..] and
        // the lock + change total stays in the money range.
        if (!lock.vChangeUnits.empty()) {
            uint64_t nChange = 0;
            if (!SumNoteUnits(lock.vChangeUnits, nChange) || nChange > (uint64_t)MAX_MONEY - lock.nUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-note-lock-change-units");
            if (!CheckNoteOutputs(tx, lock.vChangeUnits.size(), state))
                return false;
        }
        if (!IsValidNotePubKey(lock.vchHolderPubKey) ||
                lock.vchHolderSig.empty() || lock.vchHolderSig.size() > 80)
            return state.DoS(100, false, REJECT_INVALID, "bad-note-lock-auth");
        if (!CheckNoteApproverShape(lock.vApproverIndex, lock.vApproverSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-lock-approvers");
    }
    else if (tx.nNoteOp == NOTE_OP_UNLOCK) {
        NoteUnlock unlock;
        if (!DecodeNotePayload(tx.vchNotePayload, unlock))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-unlock-payload");
        uint64_t total = 0;
        if (!SumNoteUnits(unlock.vUnits, total))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-unlock-units");
        if (!CheckNoteOutputs(tx, unlock.vUnits.size(), state))
            return false;
        if (!CheckNoteApproverShape(unlock.vApproverIndex, unlock.vApproverSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-note-unlock-approvers");
    }

    return true;
}
