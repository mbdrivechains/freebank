// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/policy.h>

#include <bill.h>
#include <house.h>
#include <note.h>
#include <deposit.h>
#include <issued.h>
#include <pool.h>

#include <consensus/validation.h>
#include <validation.h>
#include <coins.h>
#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>


CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kB.
    // A typical spendable segwit txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kB.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    size_t nSize = GetSerializeSize(txout, SER_DISK, 0);
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        // sum the sizes of the parts of a transaction input
        // with 75% segwit discount applied to the script size.
        nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
    } else {
        nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    return (txout.nValue < GetDustThreshold(txout, dustRelayFeeIn));
}

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType, const bool witnessEnabled)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_MULTISIG)
    {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    } else if (whichType == TX_NULL_DATA &&
               (!fAcceptDatacarrier || scriptPubKey.size() > nMaxDatacarrierBytes))
          return false;

    else if (!witnessEnabled && (whichType == TX_WITNESS_V0_KEYHASH || whichType == TX_WITNESS_V0_SCRIPTHASH))
        return false;

    return whichType != TX_NONSTANDARD && whichType != TX_WITNESS_UNKNOWN;
}

/** MM-1 (security 11-11): FreeBank's script families - each an OP_TRUE coin whose only protection is the tag consensus
 *  gives it (or, for the mutual fund, a spend rule of its own). */
static bool IsFreeBankFamilyScript(const CScript& script)
{
    return IsHouseEscrowScript(script) || IsBillEscrowScript(script) || IsNotePreAuthScript(script) ||
           IsPoolEscrowScript(script) || IsTokenPoolScript(script);
}

static bool HasFreeBankTag(const Coin& coin)
{
    return coin.fBill || coin.fBillEscrow || coin.fHouseEscrow || coin.fNote || coin.fDeposit || coin.fPoolEscrow ||
           coin.fLpShare || coin.fCustody || coin.fIssued;
}

/** MM-1: the tag consensus would give output i of tx - AddCoins itself, run on a scratch view, so policy and consensus
 *  share one decision (no second list to keep in step). Placeholder dense ids stand in for the ones connect assigns. */
static std::vector<Coin> FreeBankOutputTags(const CTransaction& tx)
{
    CCoinsView viewEmpty;
    CCoinsViewCache scratch(&viewEmpty);
    AddCoins(scratch, tx, 1, AssetTags(), 1 /* nBillID placeholder */, 1 /* nHouseID placeholder */, false);
    std::vector<Coin> v;
    v.reserve(tx.vout.size());
    for (size_t i = 0; i < tx.vout.size(); i++)
        v.push_back(scratch.AccessCoin(COutPoint(tx.GetHash(), (uint32_t)i)));
    return v;
}

/** MM-1: a sidechain object output (OP_RETURN AC DC F6 6F <serialization>): a withdrawal's record, at most this big. */
static const size_t MAX_STANDARD_SIDECHAIN_OBJECT_SCRIPT = 400;
static bool IsSidechainObjectScript(const CScript& script)
{
    return script.size() >= 5 && script[0] == OP_RETURN && script[1] == 0xAC && script[2] == 0xDC && script[3] == 0xF6 &&
           script[4] == 0x6F;
}

bool IsStandardTx(const CTransaction& tx, std::string& reason, const bool witnessEnabled)
{
    if (tx.nVersion > CTransaction::MAX_STANDARD_VERSION || tx.nVersion < 1) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    unsigned int sz = GetTransactionWeight(tx);
    if (sz >= MAX_STANDARD_TX_WEIGHT) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys (remember the 520 byte limit on redeemScript size). That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard.
        if (txin.scriptSig.size() > 1650) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    const bool fFreeBankTx = tx.nVersion >= TRANSACTION_BILL_VERSION && tx.nVersion <= TRANSACTION_TOKEN_VERSION;
    // MM-1 (R1 cost): bounds the tag step (AreFreeBankOutputsStandard) before it can run.
    if (fFreeBankTx && tx.vout.size() > MAX_STANDARD_FREEBANK_OUTPUTS) {
        reason = "freebank-too-many-outputs";
        return false;
    }
    unsigned int nSidechainObjects = 0;
    for (size_t o = 0; o < tx.vout.size(); o++) {
        const CTxOut& txout = tx.vout[o];

        // MM-1: a family-script output is checked against its consensus tag after the inputs are known
        // (AreFreeBankOutputsStandard, MM1-R1: no per-output tagging for a tx whose inputs don't exist).
        if (IsFreeBankFamilyScript(txout.scriptPubKey))
            continue;
        // MM-1: a withdrawal's sidechain object - one per tx, size-capped, counted as a data output beside its burn.
        if (IsSidechainObjectScript(txout.scriptPubKey)) {
            if (++nSidechainObjects > 1 || txout.scriptPubKey.size() > MAX_STANDARD_SIDECHAIN_OBJECT_SCRIPT) {
                reason = "sidechain-object";
                return false;
            }
            nDataOut++;
            continue;
        }
        {
            uint256 wtID;
            std::vector<unsigned char> vchSig;
            if (txout.scriptPubKey.IsWithdrawalRefundRequest(wtID, vchSig)) {   // fixed 102-byte script
                nDataOut++;
                continue;
            }
        }

        // v0.2.28: CLOSE's mutual fund output (consensus pins its value and its place after the partner shares)
        if (tx.nVersion == TRANSACTION_HOUSE_VERSION && tx.nHouseOp == HOUSE_OP_CLOSE &&
                IsMutualFundScript(txout.scriptPubKey))
            continue;

        if (!::IsStandard(txout.scriptPubKey, whichType, witnessEnabled)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if ((whichType == TX_MULTISIG) && (!fIsBareMultisigStd)) {
            reason = "bare-multisig";
            return false;
        } else if (fFreeBankTx) {
            // MM-1: dust in a FreeBank op is checked after the inputs are known - a consensus-tagged coin (a note's
            // dust base) has its value fixed by consensus, an untagged one is held to the dust rule.
        } else if (IsDust(txout, ::dustRelayFee)) {
            reason = "dust";
            return false;
        }
    }

    // MM-1 (security 11-11): one data output - or two, a withdrawal's sidechain object beside its burn.
    if (nDataOut > (nSidechainObjects == 1 ? 2u : 1u)) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

/** MM1-R2 (security 11-11): each script family takes its own family's tag - a note tag on an escrow script is not escrow.
 *  House, bill and pool escrow share ONE shape (<32-byte push> OP_DROP OP_TRUE; house.cpp, bill.cpp, pool.cpp) and
 *  consensus tells them apart by tag only, never by script: that shape matches any of the three escrow tags. */
static bool FamilyTagMatches(const CScript& script, const Coin& coin)
{
    if (IsHouseEscrowScript(script))   // == IsBillEscrowScript == IsPoolEscrowScript
        return coin.fHouseEscrow || coin.fBillEscrow || coin.fPoolEscrow;
    if (IsNotePreAuthScript(script))
        return coin.fNote || coin.fDeposit;   // demanded notes and receipts both re-issue onto B3 custody
    if (IsTokenPoolScript(script))
        return coin.fCustody;
    return false;
}

bool AreFreeBankOutputsStandard(const CTransaction& tx, std::string& reason)
{
    const bool fFreeBankTx = tx.nVersion >= TRANSACTION_BILL_VERSION && tx.nVersion <= TRANSACTION_TOKEN_VERSION;
    bool fHaveFamily = false;
    for (const CTxOut& out : tx.vout)
        fHaveFamily = fHaveFamily || IsFreeBankFamilyScript(out.scriptPubKey);
    if (!fHaveFamily && !fFreeBankTx)
        return true;
    const std::vector<Coin> vTag = FreeBankOutputTags(tx);
    for (size_t o = 0; o < tx.vout.size(); o++) {
        const CScript& script = tx.vout[o].scriptPubKey;
        if (IsFreeBankFamilyScript(script)) {
            // Untagged (or tagged as another family), it is an anyone-can-spend coin the payer may take for escrow.
            if (o >= vTag.size() || !FamilyTagMatches(script, vTag[o])) {
                reason = "freebank-untagged-family-output";
                return false;
            }
            continue;
        }
        if (fFreeBankTx && !script.IsUnspendable() && IsDust(tx.vout[o], ::dustRelayFee) &&
                (o >= vTag.size() || !HasFreeBankTag(vTag[o]))) {
            reason = "dust";
            return false;
        }
    }
    return true;
}

/**
 * Check transaction inputs to mitigate two
 * potential denial-of-service attacks:
 *
 * 1. scriptSigs with extra data stuffed into them,
 *    not consumed by scriptPubKey (or P2SH script)
 * 2. P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations
 *
 * Why bother? To avoid denial-of-service attacks; an attacker
 * can submit a standard HASH... OP_EQUAL transaction,
 * which will get accepted into blocks. The redemption
 * script can be anything; an attacker could use a very
 * expensive-to-check-upon-redemption script like:
 *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = mapInputs.AccessCoin(tx.vin[i].prevout);

        // MM-1 (security 11-11): a coin consensus tagged with a FreeBank family is spent under consensus's rules for
        // it, whatever the spending tx's version (a note CLAIM or a SETTLE spending escrow included). An UNTAGGED
        // family-script coin stays nonstandard to spend. The mutual fund has no tag but a spend rule of its own.
        if ((IsFreeBankFamilyScript(coin.out.scriptPubKey) && FamilyTagMatches(coin.out.scriptPubKey, coin)) ||
                IsMutualFundScript(coin.out.scriptPubKey))
            continue;

        // Bill title / escrow prevouts are governed by the bill consensus
        // rules; the escrow script has no standard type
        if (tx.nVersion == TRANSACTION_BILL_VERSION && (coin.fBill || coin.fBillEscrow))
            continue;

        // House pledge prevouts likewise (RECLAIM spends them)
        if (tx.nVersion == TRANSACTION_HOUSE_VERSION && coin.fHouseEscrow)
            continue;

        // v0.2.29: a demanded deposit receipt in B3 custody (PROTEST / DISCHARGE / CLAIM spend it, scriptSig empty)
        if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION && coin.fDeposit && coin.nDemandHeight != 0)
            continue;

        // B3 consensus-custody prevouts (pre-auth demanded notes): spent by
        // PROTEST / discharge / voluntary REDEEM / CLAIM with an empty
        // scriptSig - the note consensus rules govern them (payload sig
        // against the keyid the script embeds). Same class as the two
        // carve-outs above. NB (queued observation): v13 CLAIM spending
        // fHouseEscrow and v16 SETTLE spending escrow have NO carve-out and
        // relay today only because deployed chains run fRequireStandard=false
        // - a pre-mainnet policy item, tracked in SIGNOFF_QUEUE.md.
        if (tx.nVersion == TRANSACTION_NOTE_VERSION && coin.fNote &&
                NoteDemandIsPreAuth(coin.nDemandHeight))
            continue;

        const CTxOut& prev = coin.out;

        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            std::vector<std::vector<unsigned char> > stack;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SIGVERSION_BASE))
                return false;
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            if (subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS) {
                return false;
            }
        }
    }

    return true;
}

bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SIGVERSION_BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == 32) {
            if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
        }
    }
    return true;
}

CFeeRate incrementalRelayFee = CFeeRate(DEFAULT_INCREMENTAL_RELAY_FEE);
CFeeRate dustRelayFee = CFeeRate(DUST_RELAY_TX_FEE);
unsigned int nBytesPerSigOp = DEFAULT_BYTES_PER_SIGOP;

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost)
{
    return (std::max(nWeight, nSigOpCost * nBytesPerSigOp) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost);
}
