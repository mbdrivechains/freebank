// Copyright (c) 2017-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_SIDECHAIN_H
#define BITCOIN_PRIMITIVES_SIDECHAIN_H

#include <amount.h>
#include <merkleblock.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <limits.h>
#include <set>
#include <string>
#include <vector>

//
//
//
//
// TODO note to sidechain developers:
//
// You must update THIS_SIDECHAIN to the sidechain number that gets
// assigned to this sidechain once activated.
//
// BUILD_COMMIT_HASH & BUILD_TAR_HASH all may be set by you.
//
// You must also update the genesis block, port numbers (including rpc server)
// magic bytes, data directory, checkpoint blocks, and other chainparams.
//
//
//
//
//

/* Sidechain Identifiers */

//! Sidechain number
// LOCKED (S-5/Tx-10, v0.1.0 M1 package, 2026-07-11): FreeBank = slot 130
static const unsigned int THIS_SIDECHAIN = 130;

//! Sidechain build commit hash (M1 hash_id_2). Display-only; the authoritative
//! per-release values live in the M1 proposal and the GitHub release notes
//! (github.com/mbdrivechains/freebank/releases). A binary cannot embed the
//! hash of the tarball that contains it, so these stay empty in-source.
static const std::string SIDECHAIN_BUILD_COMMIT_HASH = "";

//! Sidechain build tar hash (M1 hash_id_1). See SIDECHAIN_BUILD_COMMIT_HASH.
static const std::string SIDECHAIN_BUILD_TAR_HASH = "";

//! Required workscore for mainchain payout
static const int MAINCHAIN_WITHDRAWAL_BUNDLE_MIN_WORKSCORE = 131;

//! Minimum number of pooled withdrawals to create new bundle
static const unsigned int DEFAULT_MIN_WITHDRAWAL_CREATE_BUNDLE = 10;

// Temporary testnet value
static const int WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD = 20;
// Real value final release: static const int WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD = 144;

// The destination string for the change of a bundle
static const std::string SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST = "D";

struct Sidechain {
    uint8_t nSidechain;
    CScript depositScript;

    std::string ToString() const;
    std::string GetSidechainName() const;
};

//! Withdrawal status / zone (unspent, included in a bundle, paid out)
static const char WITHDRAWAL_UNSPENT = 'u';
static const char WITHDRAWAL_IN_BUNDLE = 'p';
static const char WITHDRAWAL_SPENT = 's';

//! Withdrawal Bundle status / zone
static const char WITHDRAWAL_BUNDLE_CREATED = 'c';
static const char WITHDRAWAL_BUNDLE_FAILED = 'f';
static const char WITHDRAWAL_BUNDLE_SPENT = 'o';

//! Key ID for fee script
static const std::string feeKey = "5f8f196a4f0c212fee1b4eda31e3ef383c52d9fc";
// 19iGcwHuZA1edpd6veLfbkHtbDPS9hAXbh
// ed7565854e9b7a334e39e33614abce078a6c06603b048a9536a7e41abf3da504

//! The default payment amount to mainchain miner for critical data commitment
static const CAmount DEFAULT_CRITICAL_DATA_AMOUNT = 0.0001 * COIN;

//! The fee for sidechain deposits on this sidechain
static const CAmount SIDECHAIN_DEPOSIT_FEE = 0.00001 * COIN;

static const char DB_SIDECHAIN_DEPOSIT_OP = 'D';
static const char DB_SIDECHAIN_WITHDRAWAL_OP = 'W';
static const char DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP = 'P';

/**
 * Base object for sidechain related database entries
 */
struct SidechainObj {
    char sidechainop;

    SidechainObj(void) { }
    virtual ~SidechainObj(void) { }

    uint256 GetHash(void) const;
    CScript GetScript(void) const;
    virtual std::string ToString(void) const;
};

struct BitAssetObj {
    char assetop;

    BitAssetObj(void) { }
    virtual ~BitAssetObj(void) { }

    CScript GetScript(void) const;
};

/**
 * BitAsset
 */
struct BitAsset : public BitAssetObj {
    uint32_t nID;
    std::string strTicker;
    std::string strHeadline;
    uint256 payload;
    uint256 txid;
    int64_t nSupply;
    std::string strController;
    std::string strOwner;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nID);
        READWRITE(strTicker);
        READWRITE(strHeadline);
        READWRITE(payload);
        READWRITE(txid);
        READWRITE(nSupply);
        READWRITE(strController);
        READWRITE(strOwner);
    }
};

/**
 * Sidechain individual withdrawal database object
 */
struct SidechainWithdrawal: public SidechainObj {
    uint8_t nSidechain;
    std::string strDestination;
    std::string strRefundDestination;
    CAmount amount;
    CAmount mainchainFee;
    char status;
    uint256 hashBlindTx; // Hash of transaction minus the serialization output

    SidechainWithdrawal(void) : SidechainObj() { sidechainop = DB_SIDECHAIN_WITHDRAWAL_OP; status = WITHDRAWAL_UNSPENT; }
    virtual ~SidechainWithdrawal(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sidechainop);
        READWRITE(nSidechain);
        READWRITE(strDestination);
        READWRITE(strRefundDestination);
        READWRITE(amount);
        READWRITE(mainchainFee);
        READWRITE(status);
        READWRITE(hashBlindTx);
    }

    std::string ToString(void) const;
    std::string GetStatusStr(void) const;

    uint256 GetID() const {
        SidechainWithdrawal withdrawal(*this);
        withdrawal.status = WITHDRAWAL_UNSPENT;
        return withdrawal.GetHash();
    }
};

/**
 * Sidechain withdrawal bundle proposal database object
 */
struct SidechainWithdrawalBundle: public SidechainObj {
    uint8_t nSidechain;
    CMutableTransaction tx;
    std::vector<uint256> vWithdrawalID; // The id in ldb of bundle's withdrawals
    int nHeight;
    // If the bundle fails we keep track of the sidechain height that it was
    // marked failed at so that we can wait WITHDRAWAL_BUNDLE_FAIL_WAIT_PERIOD
    // before trying the next bundle.
    int nFailHeight;
    char status;

    SidechainWithdrawalBundle(void) : SidechainObj() { sidechainop = DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP; status = WITHDRAWAL_BUNDLE_CREATED; nHeight = 0;}
    virtual ~SidechainWithdrawalBundle(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sidechainop);
        READWRITE(nSidechain);
        READWRITE(tx);
        READWRITE(vWithdrawalID);
        READWRITE(status);
        READWRITE(nHeight);
        READWRITE(nFailHeight);
    }

    uint256 GetID() const {
        SidechainWithdrawalBundle bundle(*this);
        bundle.status = WITHDRAWAL_BUNDLE_CREATED;
        bundle.nHeight = 0;
        bundle.nFailHeight = 0;
        return bundle.GetHash();
    }

    std::string ToString(void) const;

    std::string GetStatusStr(void) const;
};

/**
 * Sidechain deposit database object
 */
struct SidechainDeposit : public SidechainObj {
    uint8_t nSidechain;
    std::string strDest;
    CAmount amtUserPayout;
    CMutableTransaction dtx; // Mainchain deposit transaction
    uint32_t nBurnIndex; // Deposit burn output index
    uint32_t nTx; // Deposit transaction number in mainchain block
    uint256 hashMainchainBlock;

    SidechainDeposit(void) : SidechainObj() { sidechainop = DB_SIDECHAIN_DEPOSIT_OP; }
    virtual ~SidechainDeposit(void) { }

    SidechainDeposit(const SidechainDeposit* d) {
        sidechainop = d->sidechainop;
        nSidechain = d->nSidechain;
        strDest = d->strDest;
        amtUserPayout = d->amtUserPayout;
        dtx = d->dtx;
        nBurnIndex = d->nBurnIndex;
        nTx = d->nTx;
        hashMainchainBlock = d->hashMainchainBlock;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sidechainop);
        READWRITE(nSidechain);
        READWRITE(strDest);
        READWRITE(amtUserPayout);
        READWRITE(dtx);
        READWRITE(nBurnIndex);
        READWRITE(nTx);
        READWRITE(hashMainchainBlock);
    }

    std::string ToString(void) const;

    bool operator==(const SidechainDeposit& d) const
    {
        if (sidechainop == d.sidechainop &&
                nSidechain == d.nSidechain &&
                strDest == d.strDest &&
                amtUserPayout == d.amtUserPayout &&
                dtx == d.dtx &&
                nBurnIndex == d.nBurnIndex &&
                nTx == d.nTx &&
                hashMainchainBlock == d.hashMainchainBlock) {
            return true;
        }
        return false;
    }

    uint256 GetID() const
    {
        SidechainDeposit deposit(*this);
        deposit.amtUserPayout = CAmount(0);
        return deposit.GetHash();
    }
};

/**
 * Parse sidechain object from a sidechain object script
 */
SidechainObj* ParseSidechainObj(const std::vector<unsigned char>& vch);

// Functions for both withdrawal bundle creation and the GUI to use in order to
// make sure that what the GUI displays (on the pending table) is the same
// as what the bundle creation code will actually select.

// Sort a vector of SidechainWithdrawal by mainchain fee in descending order
void SortWithdrawalByFee(std::vector<SidechainWithdrawal>& vWithdrawal);

// Sort a vector of SidechainWithdrawalBundle by height in descending order
void SortWithdrawalBundleByHeight(std::vector<SidechainWithdrawalBundle>& vWithdrawalBundle);

// Erase all SidechainWithdrawal from a vector which do not have WITHDRAWAL_UNSPENT status
void SelectUnspentWithdrawal(std::vector<SidechainWithdrawal>& vWithdrawal);

/**
 * Does this deposit require a payout output in the coinbase, and if so, what?
 *
 * SINGLE SOURCE OF TRUTH for the block BUILDER (miner.cpp) and the block
 * VALIDATOR (validation.cpp).
 *
 * D-2 existed precisely because these were two independent implementations that
 * disagreed. The builder declined to pay a deposit whose destination does not
 * decode, or whose payout does not exceed SIDECHAIN_DEPOSIT_FEE; the validator
 * demanded a payout output unconditionally. The node therefore looped building
 * blocks its OWN validator rejected ("invalid-deposit-missing-output"), and
 * because deposits are processed in strict CTIP order and can never be skipped,
 * the deposit queue stuck permanently. Any depositor could trigger it with dust.
 *
 * Returns false when nothing is owed (bundle-change return, dust at or below the
 * fee, or an undecodable destination) - such a deposit is still RECORDED, it is
 * simply not paid out. Returns true and fills `out` otherwise.
 *
 * Callers must pass a deposit whose amtUserPayout is already the CTIP INCREMENT,
 * not the cumulative burn.
 */
bool GetDepositPayoutOutput(const SidechainDeposit& deposit, CTxOut& out);

/**
 * Claim a coinbase output satisfying `required`, marking it consumed.
 *
 * D-1: the old check scanned the coinbase for a matching (value, scriptPubKey)
 * and broke on the FIRST hit without consuming it. Two deposits in one block to
 * the same destination for the same CTIP increment therefore produce two
 * IDENTICAL requirements that a SINGLE coinbase output satisfies - so a miner
 * could emit one output instead of two, pocket the second deposit, and every
 * node would accept the block. No attacker is needed: a depositor sending the
 * same amount twice to the same address is enough.
 *
 * Two identical deposits require two identical outputs. `setClaimed` carries
 * the indices already spoken for by earlier deposits in the same block.
 */
bool ClaimDepositPayoutOutput(const CTxOut& required,
                              const std::vector<CTxOut>& vout,
                              std::set<size_t>& setClaimed);

/**
 * C6-A: the withdrawal-side twin of ClaimDepositPayoutOutput. A withdrawal
 * object must be backed by a DISTINCT burn OP_RETURN whose value equals its
 * amount (with a valid amount/fee). The original check set a flag on ANY match
 * and never consumed it, so one burn satisfied every withdrawal object of the
 * same amount in a transaction (distinct destinations -> distinct GetID ->
 * distinct rows), each later paid independently (N* escrow draw on the bundle
 * path, N* mint on the refund path). Claim the lowest-indexed not-yet-claimed
 * matching output and mark it used; `setClaimed` carries the indices already
 * spoken for by earlier withdrawals in the same transaction.
 */
bool ClaimWithdrawalBurn(const SidechainWithdrawal& withdrawal,
                         const std::vector<CTxOut>& vout,
                         std::set<size_t>& setClaimed);

std::string GenerateDepositAddress(const std::string& strDestIn);

bool ParseDepositAddress(const std::string& strAddressIn, std::string& strAddressOut, unsigned int& nSidechainOut);

#endif // BITCOIN_PRIMITIVES_SIDECHAIN_H
