// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <bill.h>
#include <deposit.h>
#include <oracle.h>
#include <pool.h>
#include <settle.h>
#include <house.h>
#include <note.h>
#include <txdb.h>

#include <base58.h>
#include <checkpoints.h>
#include <core_io.h>
#include <chain.h>
#include <wallet/coincontrol.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <fs.h>
#include <wallet/init.h>
#include <key.h>
#include <keystore.h>
#include <validation.h>
#include <net.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <scheduler.h>
#include <timedata.h>
#include <txmempool.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/fees.h>

#include <assert.h>
#include <future>

#include <boost/algorithm/string/replace.hpp>

std::vector<CWalletRef> vpwallets;
/** Transaction fee set by the user */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fWalletRbf = DEFAULT_WALLET_RBF;
OutputType g_address_type = OUTPUT_TYPE_NONE;
OutputType g_change_type = OUTPUT_TYPE_NONE;

const char * DEFAULT_WALLET_DAT = "wallet.dat";
const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

CFeeRate CWallet::m_discard_rate = CFeeRate(DEFAULT_DISCARD_FEE);

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly
{
    bool operator()(const CInputCoin& t1,
                    const CInputCoin& t2) const
    {
        return t1.txout.nValue < t2.txout.nValue;
    }
};

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->tx->vout[i].nValue));
}

class CAffectedKeysVisitor : public boost::static_visitor<void> {
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            for (const CTxDestination &dest : vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const WitnessV0ScriptHash& scriptID)
    {
        CScriptID id;
        CRIPEMD160().Write(scriptID.begin(), 32).Finalize(id.begin());
        CScript script;
        if (keystore.GetCScript(id, script)) {
            Process(script);
        }
    }

    void operator()(const WitnessV0KeyHash& keyid)
    {
        CKeyID id(keyid);
        if (keystore.HaveKey(id)) {
            vKeys.push_back(id);
        }
    }

    template<typename X>
    void operator()(const X &none) {}
};

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return nullptr;
    return &(it->second);
}

CPubKey CWallet::GenerateNewKey(CWalletDB &walletdb, bool internal)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // use HD key derivation if HD was enabled during wallet creation
    if (IsHDEnabled()) {
        DeriveNewChildKey(walletdb, metadata, secret, (CanSupportFeature(FEATURE_HD_SPLIT) ? internal : false));
    } else {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed) {
        SetMinVersion(FEATURE_COMPRPUBKEY);
    }

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    UpdateTimeFirstKey(nCreationTime);

    if (!AddKeyPubKeyWithDB(walletdb, secret, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": AddKey failed");
    }
    return pubkey;
}

void CWallet::DeriveNewChildKey(CWalletDB &walletdb, CKeyMetadata& metadata, CKey& secret, bool internal)
{
    // for now we use a fixed keypath scheme of m/0'/0'/k
    CKey key;                      //master key seed (256bit)
    CExtKey masterKey;             //hd master key
    CExtKey accountKey;            //key at m/0'
    CExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
    CExtKey childKey;              //key at m/0'/0'/<n>'

    // try to get the master key
    if (!GetKey(hdChain.masterKeyID, key))
        throw std::runtime_error(std::string(__func__) + ": Master key not found");

    masterKey.SetMaster(key.begin(), key.size());

    // derive m/0'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

    // derive m/0'/0' (external chain) OR m/0'/1' (internal chain)
    assert(internal ? CanSupportFeature(FEATURE_HD_SPLIT) : true);
    accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT+(internal ? 1 : 0));

    // derive child key at next index, skip keys already known to the wallet
    do {
        // always derive hardened keys
        // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
        // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
        if (internal) {
            chainChildKey.Derive(childKey, hdChain.nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/1'/" + std::to_string(hdChain.nInternalChainCounter) + "'";
            hdChain.nInternalChainCounter++;
        }
        else {
            chainChildKey.Derive(childKey, hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/0'/" + std::to_string(hdChain.nExternalChainCounter) + "'";
            hdChain.nExternalChainCounter++;
        }
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secret = childKey.key;
    metadata.hdMasterKeyID = hdChain.masterKeyID;
    // update the chain model in the database
    if (!walletdb.WriteHDChain(hdChain))
        throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
}

bool CWallet::AddKeyPubKeyWithDB(CWalletDB &walletdb, const CKey& secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata

    // CCryptoKeyStore has no concept of wallet databases, but calls AddCryptedKey
    // which is overridden below.  To avoid flushes, the database handle is
    // tunneled through to it.
    bool needsDB = !pwalletdbEncryption;
    if (needsDB) {
        pwalletdbEncryption = &walletdb;
    }
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey)) {
        if (needsDB) pwalletdbEncryption = nullptr;
        return false;
    }
    if (needsDB) pwalletdbEncryption = nullptr;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }

    if (!IsCrypted()) {
        return walletdb.WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    CWalletDB walletdb(*dbw);
    return CWallet::AddKeyPubKeyWithDB(walletdb, secret, pubkey);
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(*dbw).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
}

bool CWallet::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    UpdateTimeFirstKey(meta.nCreateTime);
    mapKeyMetadata[keyID] = meta;
    return true;
}

bool CWallet::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // m_script_metadata
    UpdateTimeFirstKey(meta.nCreateTime);
    m_script_metadata[script_id] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

/**
 * Update wallet first key creation time. This should be called whenever keys
 * are added to the wallet, with the oldest key creation time.
 */
void CWallet::UpdateTimeFirstKey(int64_t nCreateTime)
{
    AssertLockHeld(cs_wallet);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    return CWalletDB(*dbw).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(CScriptID(redeemScript));
        LogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript& dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    const CKeyMetadata& meta = m_script_metadata[CScriptID(dest)];
    UpdateTimeFirstKey(meta.nCreateTime);
    NotifyWatchonlyChanged(true);
    return CWalletDB(*dbw).WriteWatchOnly(dest, meta);
}

bool CWallet::AddWatchOnly(const CScript& dest, int64_t nCreateTime)
{
    m_script_metadata[CScriptID(dest)].nCreateTime = nCreateTime;
    return AddWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (!CWalletDB(*dbw).EraseWatchOnly(dest))
        return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial _vMasterKey;

    {
        LOCK(cs_wallet);
        for (const MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(_vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial _vMasterKey;
        for (MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(_vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime))));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime)))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(_vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(*dbw).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(*dbw);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(*dbw);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

std::set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

bool CWallet::HasWalletSpend(const uint256& txid) const
{
    AssertLockHeld(cs_wallet);
    auto iter = mapTxSpends.lower_bound(COutPoint(txid, 0));
    return (iter != mapTxSpends.end() && iter->first.hash == txid);
}

void CWallet::Flush(bool shutdown)
{
    dbw->Flush(shutdown);
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const CWalletTx* wtx = &mapWallet[it->second];
        if (wtx->nOrderPos < nMinOrderPos) {
            nMinOrderPos = wtx->nOrderPos;;
            copyFrom = wtx;
        }
    }

    assert(copyFrom);

    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        assert(copyFrom && "Oldest wallet transaction in range assumed to have been found.");
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const uint256& hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const uint256& wtxid)
{
    auto it = mapWallet.find(wtxid);
    assert(it != mapWallet.end());
    CWalletTx& thisTx = it->second;
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : thisTx.tx->vin)
        AddToSpends(txin.prevout, wtxid);
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial _vMasterKey;

    _vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(&_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = static_cast<unsigned int>(2500000 / ((double)(GetTimeMillis() - nStartTime)));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + static_cast<unsigned int>(kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime)))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        assert(!pwalletdbEncryption);
        pwalletdbEncryption = new CWalletDB(*dbw);
        if (!pwalletdbEncryption->TxnBegin()) {
            delete pwalletdbEncryption;
            pwalletdbEncryption = nullptr;
            return false;
        }
        pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);

        if (!EncryptKeys(_vMasterKey))
        {
            pwalletdbEncryption->TxnAbort();
            delete pwalletdbEncryption;
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (!pwalletdbEncryption->TxnCommit()) {
            delete pwalletdbEncryption;
            // We now have keys encrypted in memory, but not on disk...
            // die to avoid confusion and let the user reload the unencrypted wallet.
            assert(false);
        }

        delete pwalletdbEncryption;
        pwalletdbEncryption = nullptr;

        Lock();
        Unlock(strWalletPassphrase);

        // if we are using HD, replace the HD master key (seed) with a new one
        if (IsHDEnabled()) {
            if (!SetHDMasterKey(GenerateNewHDMasterKey())) {
                return false;
            }
        }

        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        dbw->Rewrite();

    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    CWalletDB walletdb(*dbw);

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (auto& entry : mapWallet)
    {
        CWalletTx* wtx = &entry.second;
        txByTime.insert(std::make_pair(wtx->nTimeReceived, TxPair(wtx, nullptr)));
    }
    std::list<CAccountingEntry> acentries;
    walletdb.ListAccountCreditDebit("", acentries);
    for (CAccountingEntry& entry : acentries)
    {
        txByTime.insert(std::make_pair(entry.nTime, TxPair(nullptr, &entry)));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != nullptr) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pwtx)
            {
                if (!walletdb.WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!walletdb.WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx)
            {
                if (!walletdb.WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!walletdb.WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }
    walletdb.WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(*dbw).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

bool CWallet::AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment)
{
    CWalletDB walletdb(*dbw);
    if (!walletdb.TxnBegin())
        return false;

    int64_t nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    AddAccountingEntry(debit, &walletdb);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    AddAccountingEntry(credit, &walletdb);

    if (!walletdb.TxnCommit())
        return false;

    return true;
}

bool CWallet::GetAccountDestination(CTxDestination &dest, std::string strAccount, bool bForceNew)
{
    CWalletDB walletdb(*dbw);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    if (!bForceNew) {
        if (!account.vchPubKey.IsValid())
            bForceNew = true;
        else {
            // Check if the current key has been used (TODO: check other addresses with the same key)
            CScript scriptPubKey = GetScriptForDestination(GetDestinationForKey(account.vchPubKey, g_address_type));
            for (std::map<uint256, CWalletTx>::iterator it = mapWallet.begin();
                 it != mapWallet.end() && account.vchPubKey.IsValid();
                 ++it)
                for (const CTxOut& txout : (*it).second.tx->vout)
                    if (txout.scriptPubKey == scriptPubKey) {
                        bForceNew = true;
                        break;
                    }
        }
    }

    // Generate a new key
    if (bForceNew) {
        if (!GetKeyFromPool(account.vchPubKey, false))
            return false;

        LearnRelatedScripts(account.vchPubKey, g_address_type);
        dest = GetDestinationForKey(account.vchPubKey, g_address_type);
        SetAddressBook(dest, strAccount, "receive");
        walletdb.WriteAccount(strAccount, account);
    } else {
        dest = GetDestinationForKey(account.vchPubKey, g_address_type);
    }

    return true;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (std::pair<const uint256, CWalletTx>& item : mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::MarkReplaced(const uint256& originalHash, const uint256& newHash)
{
    LOCK(cs_wallet);

    auto mi = mapWallet.find(originalHash);

    // There is a bug if MarkReplaced is not called on an existing wallet transaction.
    assert(mi != mapWallet.end());

    CWalletTx& wtx = (*mi).second;

    // Ensure for now that we're not overwriting data
    assert(wtx.mapValue.count("replaced_by_txid") == 0);

    wtx.mapValue["replaced_by_txid"] = newHash.ToString();

    CWalletDB walletdb(*dbw, "r+");

    bool success = true;
    if (!walletdb.WriteTx(wtx)) {
        LogPrintf("%s: Updating walletdb tx %s failed", __func__, wtx.GetHash().ToString());
        success = false;
    }

    NotifyTransactionChanged(this, originalHash, CT_UPDATED);

    return success;
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn, bool fFlushOnClose)
{
    LOCK(cs_wallet);

    CWalletDB walletdb(*dbw, "r+", fFlushOnClose);

    uint256 hash = wtxIn.GetHash();

    // Inserts only if not already there, returns tx inserted or tx found
    std::pair<std::map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(std::make_pair(hash, wtxIn));
    CWalletTx& wtx = (*ret.first).second;
    wtx.BindWallet(this);
    bool fInsertedNew = ret.second;
    if (fInsertedNew)
    {
        wtx.nTimeReceived = GetAdjustedTime();
        wtx.nOrderPos = IncOrderPosNext(&walletdb);
        wtxOrdered.insert(std::make_pair(wtx.nOrderPos, TxPair(&wtx, nullptr)));
        wtx.nTimeSmart = ComputeTimeSmart(wtx);
        AddToSpends(hash);
    }

    bool fUpdated = false;
    if (!fInsertedNew)
    {
        // Merge
        if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock)
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        // If no longer abandoned, update
        if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned())
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex))
        {
            wtx.nIndex = wtxIn.nIndex;
            fUpdated = true;
        }
        if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
        {
            wtx.fFromMe = wtxIn.fFromMe;
            fUpdated = true;
        }
        // If we have a witness-stripped version of this transaction, and we
        // see a new version with a witness, then we must be upgrading a pre-segwit
        // wallet.  Store the new version of the transaction with the witness,
        // as the stripped-version must be invalid.
        // TODO: Store all versions of the transaction, instead of just one.
        if (wtxIn.tx->HasWitness() && !wtx.tx->HasWitness()) {
            wtx.SetTx(wtxIn.tx);
            fUpdated = true;
        }

        if (wtxIn.amountAssetIn != wtx.amountAssetIn) {
            wtx.amountAssetIn = wtxIn.amountAssetIn;
            fUpdated = true;
        }
        if (wtxIn.nControlN != wtx.nControlN) {
            wtx.nControlN = wtxIn.nControlN;
            fUpdated = true;
        }
        if (wtxIn.nAssetID != wtx.nAssetID) {
            wtx.nAssetID = wtxIn.nAssetID;
            fUpdated = true;
        }
    }

    //// debug print
    LogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

    // Write to disk
    if (fInsertedNew || fUpdated)
        if (!walletdb.WriteTx(wtx))
            return false;

    // Break debit/credit balance caches:
    wtx.MarkDirty();

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = gArgs.GetArg("-walletnotify", "");

    if (!strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
        std::thread t(runCommand, strCmd);
        t.detach(); // thread runs free
    }

    return true;
}

bool CWallet::LoadToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CWalletTx& wtx = mapWallet.emplace(hash, wtxIn).first->second;
    wtx.BindWallet(this);
    wtxOrdered.insert(std::make_pair(wtx.nOrderPos, TxPair(&wtx, nullptr)));
    AddToSpends(hash);
    for (const CTxIn& txin : wtx.tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            CWalletTx& prevtx = it->second;
            if (prevtx.nIndex == -1 && !prevtx.hashUnset()) {
                MarkConflicted(prevtx.hashBlock, wtx.GetHash());
            }
        }
    }

    return true;
}

/**
 * Add a transaction to the wallet, or update it.  pIndex and posInBlock should
 * be set when the transaction was known to be included in a block.  When
 * pIndex == nullptr, then wallet state is not updated in AddToWallet, but
 * notifications happen and cached balances are marked dirty.
 *
 * If fUpdate is true, existing transactions will be updated.
 * TODO: One exception to this is that the abandoned state is cleared under the
 * assumption that any further notification of a transaction that was considered
 * abandoned is an indication that it is not safe to be considered abandoned.
 * Abandoned state should probably be more carefully tracked via different
 * posInBlock signals or by checking mempool presence when necessary.
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate, CAmount amountAssetIn, int nControlN, uint32_t nAssetID)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);

        if (pIndex != nullptr) {
            for (const CTxIn& txin : tx.vin) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        LogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), pIndex->GetBlockHash().ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(pIndex->GetBlockHash(), range.first->second);
                    }
                    range.first++;
                }
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            /* Check if any keys in the wallet keypool that were supposed to be unused
             * have appeared in a new transaction. If so, remove those keys from the keypool.
             * This can happen when restoring an old wallet backup that does not contain
             * the mostly recently created transactions from newer versions of the wallet.
             */

            // loop though all outputs
            for (const CTxOut& txout: tx.vout) {
                // extract addresses and check if they match with an unused keypool key
                std::vector<CKeyID> vAffected;
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                for (const CKeyID &keyid : vAffected) {
                    std::map<CKeyID, int64_t>::const_iterator mi = m_pool_key_to_index.find(keyid);
                    if (mi != m_pool_key_to_index.end()) {
                        LogPrintf("%s: Detected a used keypool key, mark all keypool key up to this key as used\n", __func__);
                        MarkReserveKeysAsUsed(mi->second);

                        if (!TopUpKeyPool()) {
                            LogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
                        }
                    }
                }
            }

            CWalletTx wtx(this, ptx);
            wtx.amountAssetIn = amountAssetIn;
            wtx.nControlN = nControlN;
            wtx.nAssetID = nAssetID;

            // Get merkle branch if transaction was found in a block
            if (pIndex != nullptr)
                wtx.SetMerkleBranch(pIndex, posInBlock);

            return AddToWallet(wtx, false);
        }
    }
    return false;
}

bool CWallet::TransactionCanBeAbandoned(const uint256& hashTx) const
{
    LOCK2(cs_main, cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && wtx->GetDepthInMainChain() == 0 && !wtx->InMempool();
}

bool CWallet::AbandonTransaction(const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet);

    CWalletDB walletdb(*dbw, "r+");

    std::set<uint256> todo;
    std::set<uint256> done;

    // Can't mark abandoned if confirmed or in mempool
    auto it = mapWallet.find(hashTx);
    assert(it != mapWallet.end());
    CWalletTx& origtx = it->second;
    if (origtx.GetDepthInMainChain() != 0 || origtx.InMempool()) {
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;
        int currentconfirm = wtx.GetDepthInMainChain();
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned()) {
            // If the orig tx was not in block/mempool, none of its spends can be in mempool
            assert(!wtx.InMempool());
            wtx.nIndex = -1;
            wtx.setAbandoned();
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            NotifyTransactionChanged(this, wtx.GetHash(), CT_UPDATED);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                if (!done.count(iter->second)) {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (const CTxIn& txin : wtx.tx->vin)
            {
                auto it = mapWallet.find(txin.prevout.hash);
                if (it != mapWallet.end()) {
                    it->second.MarkDirty();
                }
            }
        }
    }

    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet);

    int conflictconfirms = 0;
    if (mapBlockIndex.count(hashBlock)) {
        CBlockIndex* pindex = mapBlockIndex[hashBlock];
        if (chainActive.Contains(pindex)) {
            conflictconfirms = -(chainActive.Height() - pindex->nHeight + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(*dbw, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;
        int currentconfirm = wtx.GetDepthInMainChain();
        if (conflictconfirms < currentconfirm) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                 if (!done.count(iter->second)) {
                     todo.insert(iter->second);
                 }
                 iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (const CTxIn& txin : wtx.tx->vin) {
                auto it = mapWallet.find(txin.prevout.hash);
                if (it != mapWallet.end()) {
                    it->second.MarkDirty();
                }
            }
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef& ptx, const CBlockIndex *pindex, int posInBlock, CAmount amountAssetIn, int nControlN, uint32_t nAssetID) {
    const CTransaction& tx = *ptx;

    if (!AddToWalletIfInvolvingMe(ptx, pindex, posInBlock, true, amountAssetIn, nControlN, nAssetID))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    for (const CTxIn& txin : tx.vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            it->second.MarkDirty();
        }
    }
}

void CWallet::TransactionAddedToMempool(const CTransactionRef& ptx) {
    LOCK2(cs_main, cs_wallet);
    SyncTransaction(ptx);

    auto it = mapWallet.find(ptx->GetHash());
    if (it != mapWallet.end()) {
        it->second.fInMempool = true;
    }
}

void CWallet::TransactionRemovedFromMempool(const CTransactionRef &ptx) {
    LOCK(cs_wallet);
    auto it = mapWallet.find(ptx->GetHash());
    if (it != mapWallet.end()) {
        it->second.fInMempool = false;
    }
}

void CWallet::BlockConnected(const std::map<uint256, BitAssetTransactionData>& mapAssetData, const std::shared_ptr<const CBlock>& pblock, const CBlockIndex *pindex, const std::vector<CTransactionRef>& vtxConflicted) {
    LOCK2(cs_main, cs_wallet);
    // TODO: Temporarily ensure that mempool removals are notified before
    // connected transactions.  This shouldn't matter, but the abandoned
    // state of transactions in our wallet is currently cleared when we
    // receive another notification and there is a race condition where
    // notification of a connected conflict might cause an outside process
    // to abandon a transaction and then have it inadvertently cleared by
    // the notification that the conflicted transaction was evicted.

    for (const CTransactionRef& ptx : vtxConflicted) {
        SyncTransaction(ptx);
        TransactionRemovedFromMempool(ptx);
    }
    for (size_t i = 0; i < pblock->vtx.size(); i++) {
        std::map<uint256, BitAssetTransactionData>::const_iterator it;
        it = mapAssetData.find(pblock->vtx[i]->GetHash());
        if (it != mapAssetData.end()) {
            SyncTransaction(pblock->vtx[i], pindex, i, it->second.amountAssetIn, it->second.nControlN, it->second.nAssetID);
        } else {
            SyncTransaction(pblock->vtx[i], pindex, i);
        }
        TransactionRemovedFromMempool(pblock->vtx[i]);
    }

    m_last_block_processed = pindex;
}

void CWallet::BlockDisconnected(const std::shared_ptr<const CBlock>& pblock) {
    LOCK2(cs_main, cs_wallet);

    for (const CTransactionRef& ptx : pblock->vtx) {
        SyncTransaction(ptx);
    }
}

void CWallet::BlockUntilSyncedToCurrentChain() {
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs_wallet);

    {
        // Skip the queue-draining stuff if we know we're caught up with
        // chainActive.Tip()...
        // We could also take cs_wallet here, and call m_last_block_processed
        // protected by cs_wallet instead of cs_main, but as long as we need
        // cs_main here anyway, its easier to just call it cs_main-protected.
        LOCK(cs_main);
        const CBlockIndex* initialChainTip = chainActive.Tip();

        if (m_last_block_processed->GetAncestor(initialChainTip->nHeight) == initialChainTip) {
            return;
        }
    }

    // ...otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).
    SyncWithValidationInterfaceQueue();
}


isminetype CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                return IsMine(prev.tx->vout[txin.prevout.n]);
        }
    }
    return ISMINE_NO;
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    return ::IsMine(*this, txout.scriptPubKey);
}

CAmount CWallet::GetCredit(const CTxOut& txout, const isminefilter& filter) const
{
    // TODO
    // Skip BitAssets & re-enable
    //if (!MoneyRange(txout.nValue))
    //    throw std::runtime_error(std::string(__func__) + ": value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut& txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    for (const CTxOut& txout : tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const
{
    LOCK(cs_wallet);

    for (const CTxIn& txin : tx.vin)
    {
        auto mi = mapWallet.find(txin.prevout.hash);
        if (mi == mapWallet.end())
            return false; // any unknown inputs can't be from us

        const CWalletTx& prev = (*mi).second;

        if (txin.prevout.n >= prev.tx->vout.size())
            return false; // invalid input!

        if (!(IsMine(prev.tx->vout[txin.prevout.n]) & filter))
            return false;
    }
    return true;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction& tx) const
{
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

CPubKey CWallet::GenerateNewHDMasterKey()
{
    CKey key;
    key.MakeNewKey(true);

    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the pubkey
    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));

    // set the hd keypath to "m" -> Master, refers the masterkeyid to itself
    metadata.hdKeypath     = "m";
    metadata.hdMasterKeyID = pubkey.GetID();

    {
        LOCK(cs_wallet);

        // mem store the metadata
        mapKeyMetadata[pubkey.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, pubkey))
            throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");
    }

    return pubkey;
}

bool CWallet::SetHDMasterKey(const CPubKey& pubkey)
{
    LOCK(cs_wallet);
    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.nVersion = CanSupportFeature(FEATURE_HD_SPLIT) ? CHDChain::VERSION_HD_CHAIN_SPLIT : CHDChain::VERSION_HD_BASE;
    newHdChain.masterKeyID = pubkey.GetID();
    SetHDChain(newHdChain, false);

    return true;
}

bool CWallet::SetHDChain(const CHDChain& chain, bool memonly)
{
    LOCK(cs_wallet);
    if (!memonly && !CWalletDB(*dbw).WriteHDChain(chain))
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");

    hdChain = chain;
    return true;
}

bool CWallet::IsHDEnabled() const
{
    return !hdChain.masterKeyID.IsNull();
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

void CWalletTx::GetAmounts(std::list<COutputEntry>& listReceived,
                           std::list<COutputEntry>& listSent, CAmount& nFee, std::string& strSentAccount, const isminefilter& filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = tx->GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < tx->vout.size(); ++i)
    {
        const CTxOut& txout = tx->vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            LogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                     this->GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

/**
 * Scan active chain for relevant transactions after importing keys. This should
 * be called whenever new keys are added to the wallet, with the oldest key
 * creation time.
 *
 * @return Earliest timestamp that could be successfully scanned from. Timestamp
 * returned will be higher than startTime if relevant blocks could not be read.
 */
int64_t CWallet::RescanFromTime(int64_t startTime, const WalletRescanReserver& reserver, bool update)
{
    // Find starting block. May be null if nCreateTime is greater than the
    // highest blockchain timestamp, in which case there is nothing that needs
    // to be scanned.
    CBlockIndex* startBlock = nullptr;
    {
        LOCK(cs_main);
        startBlock = chainActive.FindEarliestAtLeast(startTime - TIMESTAMP_WINDOW);
        LogPrintf("%s: Rescanning last %i blocks\n", __func__, startBlock ? chainActive.Height() - startBlock->nHeight + 1 : 0);
    }

    if (startBlock) {
        const CBlockIndex* const failedBlock = ScanForWalletTransactions(startBlock, nullptr, reserver, update);
        if (failedBlock) {
            return failedBlock->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1;
        }
    }
    return startTime;
}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 *
 * Returns null if scan was successful. Otherwise, if a complete rescan was not
 * possible (due to pruning or corruption), returns pointer to the most recent
 * block that could not be scanned.
 *
 * If pindexStop is not a nullptr, the scan will stop at the block-index
 * defined by pindexStop
 *
 * Caller needs to make sure pindexStop (and the optional pindexStart) are on
 * the main chain after to the addition of any new keys you want to detect
 * transactions for.
 */
CBlockIndex* CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, CBlockIndex* pindexStop, const WalletRescanReserver &reserver, bool fUpdate)
{
    int64_t nNow = GetTime();
    const CChainParams& chainParams = Params();

    assert(reserver.isReserved());
    if (pindexStop) {
        assert(pindexStop->nHeight >= pindexStart->nHeight);
    }

    CBlockIndex* pindex = pindexStart;
    CBlockIndex* ret = nullptr;
    {
        fAbortRescan = false;
        ShowProgress(_("Rescanning..."), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        CBlockIndex* tip = nullptr;
        double dProgressStart;
        double dProgressTip;
        {
            LOCK(cs_main);
            tip = chainActive.Tip();
            dProgressStart = GuessVerificationProgress(chainParams.TxData(), pindex);
            dProgressTip = GuessVerificationProgress(chainParams.TxData(), tip);
        }
        double gvp = dProgressStart;
        while (pindex && !fAbortRescan)
        {
            if (pindex->nHeight % 100 == 0 && dProgressTip - dProgressStart > 0.0) {
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99, (int)((gvp - dProgressStart) / (dProgressTip - dProgressStart) * 100))));
            }
            if (GetTime() >= nNow + 60) {
                nNow = GetTime();
                LogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex->nHeight, gvp);
            }

            CBlock block;
            if (ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
                LOCK2(cs_main, cs_wallet);
                if (pindex && !chainActive.Contains(pindex)) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    ret = pindex;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    AddToWalletIfInvolvingMe(block.vtx[posInBlock], pindex, posInBlock, fUpdate);
                }
            } else {
                ret = pindex;
            }
            if (pindex == pindexStop) {
                break;
            }
            {
                LOCK(cs_main);
                pindex = chainActive.Next(pindex);
                gvp = GuessVerificationProgress(chainParams.TxData(), pindex);
                if (tip != chainActive.Tip()) {
                    tip = chainActive.Tip();
                    // in case the tip has changed, update progress max
                    dProgressTip = GuessVerificationProgress(chainParams.TxData(), tip);
                }
            }
        }
        if (pindex && fAbortRescan) {
            LogPrintf("Rescan aborted at block %d. Progress=%f\n", pindex->nHeight, gvp);
        }
        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;
    LOCK2(cs_main, cs_wallet);
    std::map<int64_t, CWalletTx*> mapSorted;

    // Sort pending wallet transactions based on their initial wallet insertion order
    for (std::pair<const uint256, CWalletTx>& item : mapWallet)
    {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain();

        if (!wtx.IsCoinBase() && (nDepth == 0 && !wtx.isAbandoned())) {
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
        }
    }

    // Try to add wallet transactions to memory pool
    for (std::pair<const int64_t, CWalletTx*>& item : mapSorted) {
        CWalletTx& wtx = *(item.second);
        CValidationState state;
        wtx.AcceptToMemoryPool(maxTxFee, state);
    }
}

bool CWalletTx::RelayWalletTransaction(CConnman* connman)
{
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase() && !isAbandoned() && GetDepthInMainChain() == 0)
    {
        CValidationState state;
        /* GetDepthInMainChain already catches known conflicts. */
        if (InMempool() || AcceptToMemoryPool(maxTxFee, state)) {
            LogPrintf("Relaying wtx %s\n", GetHash().ToString());
            if (connman) {
                CInv inv(MSG_TX, GetHash());
                connman->ForEachNode([&inv](CNode* pnode)
                {
                    pnode->PushInventory(inv);
                });
                return true;
            }
        }
    }
    return false;
}

std::set<uint256> CWalletTx::GetConflicts() const
{
    std::set<uint256> result;
    if (pwallet != nullptr)
    {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (tx->vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*tx, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*tx, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    CAmount credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableCreditCached)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(hashTx, i))
        {
            const CTxOut &txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + " : value out of range");
        }
    }

    nAvailableCreditCached = nCredit;
    fAvailableCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(GetHash(), i))
        {
            const CTxOut &txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*tx);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const
{
    return fInMempool;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases
    if (!CheckFinalTx(*tx))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!InMempool())
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : tx->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == nullptr)
            return false;
        // Bounds-check the parent output before indexing it. Upstream 0.16
        // indexes blind, which turns any wallet entry whose input references a
        // missing/short parent vout into an out-of-bounds READ - the CScript
        // handed to Solver() is then garbage and IsPayToScriptHash() faults.
        // Observed on the droplet 2026-07-26 as a deterministic freebankd
        // SIGSEGV inside getbalance -> IsTrusted -> IsMine -> Solver ->
        // IsPayToScriptHash (backtrace from the core dump), which crashloops
        // the node because the wallet is polled constantly. An unresolvable
        // parent output cannot be proven ours, so the honest answer is "not
        // trusted" - never a crash.
        if (!parent->tx || txin.prevout.n >= parent->tx->vout.size())
            return false;
        const CTxOut& parentOut = parent->tx->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

bool CWalletTx::IsEquivalentTo(const CWalletTx& _tx) const
{
        CMutableTransaction tx1 = *this->tx;
        CMutableTransaction tx2 = *_tx.tx;
        for (auto& txin : tx1.vin) txin.scriptSig = CScript();
        for (auto& txin : tx2.vin) txin.scriptSig = CScript();
        return CTransaction(tx1) == CTransaction(tx2);
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime, CConnman* connman)
{
    std::vector<uint256> result;

    LOCK(cs_wallet);

    // Sort them in chronological order
    std::multimap<unsigned int, CWalletTx*> mapSorted;
    for (std::pair<const uint256, CWalletTx>& item : mapWallet)
    {
        CWalletTx& wtx = item.second;
        // Don't rebroadcast if newer than nTime:
        if (wtx.nTimeReceived > nTime)
            continue;
        mapSorted.insert(std::make_pair(wtx.nTimeReceived, &wtx));
    }
    for (std::pair<const unsigned int, CWalletTx*>& item : mapSorted)
    {
        CWalletTx& wtx = *item.second;
        if (wtx.RelayWalletTransaction(connman))
            result.push_back(wtx.GetHash());
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime-5*60, connman);
    if (!relayed.empty())
        LogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

// Calculate total balance in a different way from GetBalance. The biggest
// difference is that GetBalance sums up all unspent TxOuts paying to the
// wallet, while this sums up both spent and unspent TxOuts paying to the
// wallet, and then subtracts the values of TxIns spending from the wallet. This
// also has fewer restrictions on which unconfirmed transactions are considered
// trusted.
CAmount CWallet::GetLegacyBalance(const isminefilter& filter, int minDepth, const std::string* account) const
{
    LOCK2(cs_main, cs_wallet);

    CAmount balance = 0;
    for (const auto& entry : mapWallet) {
        const CWalletTx& wtx = entry.second;
        const int depth = wtx.GetDepthInMainChain();
        if (depth < 0 || !CheckFinalTx(*wtx.tx) || wtx.GetBlocksToMaturity() > 0) {
            continue;
        }

        // Loop through tx outputs and add incoming payments. For outgoing txs,
        // treat change outputs specially, as part of the amount debited.
        CAmount debit = wtx.GetDebit(filter);
        const bool outgoing = debit > 0;
        for (const CTxOut& out : wtx.tx->vout) {
            if (outgoing && IsChange(out)) {
                debit -= out.nValue;
            } else if (IsMine(out) & filter && depth >= minDepth && (!account || *account == GetAccountName(out.scriptPubKey))) {
                balance += out.nValue;
            }
        }

        // For outgoing txs, subtract amount debited.
        if (outgoing && (!account || *account == wtx.strFromAccount)) {
            balance -= debit;
        }
    }

    if (account) {
        balance += CWalletDB(*dbw).GetAccountCreditDebit(*account);
    }

    return balance;
}

CAmount CWallet::GetAvailableBalance(const CCoinControl* coinControl) const
{
    LOCK2(cs_main, cs_wallet);

    CAmount balance = 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);
    for (const COutput& out : vCoins) {
        if (out.fSpendable) {
            balance += out.tx->tx->vout[out.i].nValue;
        }
    }
    return balance;
}

void CWallet::AvailableCoins(std::vector<COutput> &vCoins, bool fOnlySafe, const CCoinControl *coinControl, const CAmount &nMinimumAmount, const CAmount &nMaximumAmount, const CAmount &nMinimumSumAmount, const uint64_t nMaximumCount, const int nMinDepth, const int nMaxDepth) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    vCoins.clear();
    CAmount nTotal = 0;

    for (const auto& entry : mapWallet)
    {
        const uint256& wtxid = entry.first;
        const CWalletTx* pcoin = &entry.second;

        if (!CheckFinalTx(*pcoin->tx))
            continue;

        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
            continue;

        int nDepth = pcoin->GetDepthInMainChain();
        if (nDepth < 0)
            continue;

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !pcoin->InMempool())
            continue;

        bool safeTx = pcoin->IsTrusted();

        // We should not consider coins from transactions that are replacing
        // other transactions.
        //
        // Example: There is a transaction A which is replaced by bumpfee
        // transaction B. In this case, we want to prevent creation of
        // a transaction B' which spends an output of B.
        //
        // Reason: If transaction A were initially confirmed, transactions B
        // and B' would no longer be valid, so the user would have to create
        // a new transaction C to replace B'. However, in the case of a
        // one-block reorg, transactions B' and C might BOTH be accepted,
        // when the user only wanted one of them. Specifically, there could
        // be a 1-block reorg away from the chain where transactions A and C
        // were accepted to another chain where B, B', and C were all
        // accepted.
        if (nDepth == 0 && pcoin->mapValue.count("replaces_txid")) {
            safeTx = false;
        }

        // Similarly, we should not consider coins from transactions that
        // have been replaced. In the example above, we would want to prevent
        // creation of a transaction A' spending an output of A, because if
        // transaction B were initially confirmed, conflicting with A and
        // A', we wouldn't want to the user to create a transaction D
        // intending to replace A', but potentially resulting in a scenario
        // where A, A', and D could all be accepted (instead of just B and
        // D, or just A and A' like the user would want).
        if (nDepth == 0 && pcoin->mapValue.count("replaced_by_txid")) {
            safeTx = false;
        }

        if (fOnlySafe && !safeTx) {
            continue;
        }

        if (nDepth < nMinDepth || nDepth > nMaxDepth)
            continue;

        CAmount amountAssetIn = pcoin->amountAssetIn;
        CAmount amountAssetOut = CAmount(0);

        for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
            // Skip outputs until we have accounted for BitAsset input
            if (amountAssetIn != amountAssetOut) {
                amountAssetOut += pcoin->tx->vout[i].nValue;
                continue;
            }

            // Skip controller & genesis output of asset creation tx
            if (pcoin->tx->nVersion == TRANSACTION_BITASSET_CREATE_VERSION && i < 2)
                continue;

            // Skip bill title & escrow outputs - locked to bill operations
            // Skip consensus-tagged v11 outputs. Decided by the SAME
            // payload-pure tagger consensus uses, so this skip cannot drift -
            // the enumerated form here covered ISSUE and ENDORSE only, and a
            // DISCOUNT's title AND its minted note leg would have been offered
            // as fee coins: the fifth recurrence of the class documented below.
            // The seller's whole payment sits in those note outputs.
            if (pcoin->tx->nVersion == TRANSACTION_BILL_VERSION) {
                Coin coinProbe;
                ApplyBillCoinTags(*pcoin->tx, i, coinProbe);
                if (coinProbe.fBill || coinProbe.fBillEscrow || coinProbe.fNote)
                    continue;
            }

            // Skip note outputs - they are P2PKH (IsMine) but consensus locks
            // them to v13 TRANSFER/REDEEM; spending one as a base fee coin would
            // build a tx the note guard rejects.
            if (pcoin->tx->nVersion == TRANSACTION_NOTE_VERSION) {
                if (pcoin->tx->nNoteOp == NOTE_OP_MINT) {
                    NoteMint m;
                    if (DecodeNotePayload(pcoin->tx->vchNotePayload, m) && i < m.vUnits.size())
                        continue;
                } else if (pcoin->tx->nNoteOp == NOTE_OP_TRANSFER) {
                    NoteTransfer x;
                    if (DecodeNotePayload(pcoin->tx->vchNotePayload, x) && i < x.vUnits.size())
                        continue;
                } else if (pcoin->tx->nNoteOp == NOTE_OP_DEMAND) {
                    // A DEMAND RE-ISSUES its notes and AddCoins tags them fNote
                    // (coins.cpp, the nNoteDemandHeight arm) - but this skip
                    // enumerated MINT and TRANSFER only, so a demanded note has
                    // been offered as a fee coin since 3.5. Same class as the
                    // four below, and worse in consequence: a demanded note
                    // carries an interest clock, so losing it to an unminable
                    // spend strands principal AND accrued deferral interest.
                    // Found while closing the v11 instance; the enumerations
                    // here should follow the pool/bill arms onto a shared
                    // payload-pure tagger (NEXT.md A8).
                    NoteDemand dm;
                    if (DecodeNotePayload(pcoin->tx->vchNotePayload, dm) && i < dm.vUnits.size())
                        continue;
                }
            }

            // Skip term-deposit RECEIPT outputs (same reason as notes): P2PKH and
            // IsMine, but consensus locks a receipt coin to its house's v14
            // TRANSFER/WITHDRAW/CLAIM. Offering one as a base fee coin lets a later
            // funding SelectCoins grab it - the wallet then records the receipt as
            // spent by a tx the deposit guard rejects, silently STRANDING the
            // deposit (its liability D stays on the house books but the holder can
            // no longer find the receipt to withdraw/claim). ORIGINATE receipts are
            // vout[0..n-1]; a TRANSFER receipt is vout[0]. WITHDRAW/CLAIM outputs
            // are plain base-coin payouts and stay spendable.
            if (pcoin->tx->nVersion == TRANSACTION_DEPOSIT_VERSION) {
                if (pcoin->tx->nDepositOp == DEPOSIT_OP_ORIGINATE) {
                    DepositOriginate o;
                    if (DecodeDepositPayload(pcoin->tx->vchDepositPayload, o) && i < o.vPrincipal.size())
                        continue;
                } else if (pcoin->tx->nDepositOp == DEPOSIT_OP_TRANSFER && i == 0) {
                    continue;
                }
            }

            // Skip pool-tagged outputs (Phase 3.7) - LP coins, note payouts and
            // note/LP change are P2PKH and IsMine, but consensus locks them to
            // v15 ops; offering one as a base fee coin strands it (the 4th-
            // recurrence tagged-coin-as-fee-coin class). Decided by the SAME
            // payload-pure tagger consensus uses, so this skip cannot drift.
            // Untagged pool outputs (the plain BTX payouts) stay spendable.
            if (pcoin->tx->nVersion == TRANSACTION_POOL_VERSION) {
                Coin coinProbe;
                ApplyPoolCoinTags(*pcoin->tx, i, coinProbe);
                if (coinProbe.fNote || coinProbe.fLpShare || coinProbe.fPoolEscrow)
                    continue;
            }

            if (pcoin->tx->vout[i].nValue < nMinimumAmount || pcoin->tx->vout[i].nValue > nMaximumAmount)
                continue;

            if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(entry.first, i)))
                continue;

            if (IsLockedCoin(entry.first, i))
                continue;

            if (IsSpent(wtxid, i))
                continue;

            isminetype mine = IsMine(pcoin->tx->vout[i]);

            if (mine == ISMINE_NO) {
                continue;
            }

            bool fSpendableIn = ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (coinControl && coinControl->fAllowWatchOnly && (mine & ISMINE_WATCH_SOLVABLE) != ISMINE_NO);
            bool fSolvableIn = (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO;

            vCoins.push_back(COutput(pcoin, i, nDepth, fSpendableIn, fSolvableIn, safeTx));

            // Checks the sum amount of all UTXO's.
            if (nMinimumSumAmount != MAX_MONEY) {
                nTotal += pcoin->tx->vout[i].nValue;

                if (nTotal >= nMinimumSumAmount) {
                    return;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                return;
            }
        }
    }
}

// TODO
// For basic testing this will take in an optional txid
// A better version might take in an asset ID to filter outputs
void CWallet::AvailableAssets(std::vector<COutput> &vCoins, uint256 txid) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    vCoins.clear();

    for (const auto& entry : mapWallet)
    {
        const uint256& wtxid = entry.first;
        const CWalletTx* wtx = &entry.second;

        // Skip transactions not from optional txid
        if (!txid.IsNull() && wtxid != txid)
            continue;

        if (wtx->amountAssetIn <= 0 && wtx->tx->nVersion != TRANSACTION_BITASSET_CREATE_VERSION)
            continue;

        if (!CheckFinalTx(*wtx->tx))
            continue;

        // Ignore unconfirmed assets
        int nDepth = wtx->GetDepthInMainChain();
        if (nDepth < 1)
            continue;

        bool safeTx = wtx->IsTrusted();
        if (!safeTx)
            continue;

        if (wtx->amountAssetIn) {
            // Need to find the asset outputs that belong to us,
            // while adding up to the total amountassetin. Some of the outputs
            // might not be ours.
            CAmount amountAssetOut = CAmount(0);
            for (unsigned int i = 0; i < wtx->tx->vout.size(); i++) {
                if (amountAssetOut >= wtx->amountAssetIn)
                    break;

                amountAssetOut += wtx->tx->vout[i].nValue;

                // Skip asset control outputs
                if (wtx->nControlN == (int)i)
                   continue;

                if (IsLockedCoin(entry.first, i))
                    continue;

                if (IsSpent(wtxid, i))
                    continue;

                isminetype mine = IsMine(wtx->tx->vout[i]);

                if (mine == ISMINE_NO) {
                    continue;
                }

                bool fSpendableIn = ((mine & ISMINE_SPENDABLE) != ISMINE_NO);
                bool fSolvableIn = (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO;

                vCoins.push_back(COutput(wtx, i, nDepth, fSpendableIn, fSolvableIn, true));
            }
        }
        else
        if (wtx->tx->nVersion == TRANSACTION_BITASSET_CREATE_VERSION) {
            // Check if we have any assets from the first two outputs
            if (wtx->tx->vout.size() < 2)
                continue;

            // Do not return the controller output
            /*
            if (!IsLockedCoin(entry.first, 0) && !IsSpent(wtxid, 0)) {
                isminetype mine = IsMine(wtx->tx->vout[0]);
                if (mine != ISMINE_NO) {
                    bool fSpendableIn = ((mine & ISMINE_SPENDABLE) != ISMINE_NO);
                    bool fSolvableIn = (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO;
                    vCoins.push_back(COutput(wtx, 0, nDepth, fSpendableIn, fSolvableIn, true));
                }
            }
            */
            if  (!IsLockedCoin(entry.first, 1) && !IsSpent(wtxid, 1)) {
                isminetype mine = IsMine(wtx->tx->vout[1]);
                if (mine != ISMINE_NO) {
                    bool fSpendableIn = ((mine & ISMINE_SPENDABLE) != ISMINE_NO);
                    bool fSolvableIn = (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO;
                    vCoins.push_back(COutput(wtx, 1, nDepth, fSpendableIn, fSolvableIn, true));
                }
            }
        }
    }
}

std::map<CTxDestination, std::vector<COutput>> CWallet::ListCoins() const
{
    // TODO: Add AssertLockHeld(cs_wallet) here.
    //
    // Because the return value from this function contains pointers to
    // CWalletTx objects, callers to this function really should acquire the
    // cs_wallet lock before calling it. However, the current caller doesn't
    // acquire this lock yet. There was an attempt to add the missing lock in
    // https://github.com/bitcoin/bitcoin/pull/10340, but that change has been
    // postponed until after https://github.com/bitcoin/bitcoin/pull/10244 to
    // avoid adding some extra complexity to the Qt code.

    std::map<CTxDestination, std::vector<COutput>> result;
    std::vector<COutput> availableCoins;

    LOCK2(cs_main, cs_wallet);
    AvailableCoins(availableCoins);

    for (auto& coin : availableCoins) {
        CTxDestination address;
        if (coin.fSpendable &&
            ExtractDestination(FindNonChangeParentOutput(*coin.tx->tx, coin.i).scriptPubKey, address)) {
            result[address].emplace_back(std::move(coin));
        }
    }

    std::vector<COutPoint> lockedCoins;
    ListLockedCoins(lockedCoins);
    for (const auto& output : lockedCoins) {
        auto it = mapWallet.find(output.hash);
        if (it != mapWallet.end()) {
            int depth = it->second.GetDepthInMainChain();
            if (depth >= 0 && output.n < it->second.tx->vout.size() &&
                IsMine(it->second.tx->vout[output.n]) == ISMINE_SPENDABLE) {
                CTxDestination address;
                if (ExtractDestination(FindNonChangeParentOutput(*it->second.tx, output.n).scriptPubKey, address)) {
                    result[address].emplace_back(
                        &it->second, output.n, depth, true /* spendable */, true /* solvable */, false /* safe */);
                }
            }
        }
    }

    return result;
}

const CTxOut& CWallet::FindNonChangeParentOutput(const CTransaction& tx, int output) const
{
    const CTransaction* ptx = &tx;
    int n = output;
    while (IsChange(ptx->vout[n]) && ptx->vin.size() > 0) {
        const COutPoint& prevout = ptx->vin[0].prevout;
        auto it = mapWallet.find(prevout.hash);
        if (it == mapWallet.end() || it->second.tx->vout.size() <= prevout.n ||
            !IsMine(it->second.tx->vout[prevout.n])) {
            break;
        }
        ptx = it->second.tx.get();
        n = prevout.n;
    }
    return ptx->vout[n];
}

static void ApproximateBestSubset(const std::vector<CInputCoin>& vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    FastRandomContext insecure_rand;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand.randbool() : !vfIncluded[i])
                {
                    nTotal += vValue[i].txout.nValue;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].txout.nValue;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(const CAmount& nTargetValue, const int nConfMine, const int nConfTheirs, const uint64_t nMaxAncestors, std::vector<COutput> vCoins,
                                 std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    boost::optional<CInputCoin> coinLowestLarger;
    std::vector<CInputCoin> vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    for (const COutput &output : vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        if (!mempool.TransactionWithinChainLimit(pcoin->GetHash(), nMaxAncestors))
            continue;

        int i = output.i;

        CInputCoin coin = CInputCoin(pcoin, i);

        if (coin.txout.nValue == nTargetValue)
        {
            setCoinsRet.insert(coin);
            nValueRet += coin.txout.nValue;
            return true;
        }
        else if (coin.txout.nValue < nTargetValue + MIN_CHANGE)
        {
            vValue.push_back(coin);
            nTotalLower += coin.txout.nValue;
        }
        else if (!coinLowestLarger || coin.txout.nValue < coinLowestLarger->txout.nValue)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (const auto& input : vValue)
        {
            setCoinsRet.insert(input);
            nValueRet += input.txout.nValue;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (!coinLowestLarger)
            return false;
        setCoinsRet.insert(coinLowestLarger.get());
        nValueRet += coinLowestLarger->txout.nValue;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.begin(), vValue.end(), CompareValueOnly());
    std::reverse(vValue.begin(), vValue.end());
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger->txout.nValue <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.get());
        nValueRet += coinLowestLarger->txout.nValue;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i]);
                nValueRet += vValue[i].txout.nValue;
            }

        if (LogAcceptCategory(BCLog::SELECTCOINS)) {
            LogPrint(BCLog::SELECTCOINS, "SelectCoins() best subset: ");
            for (unsigned int i = 0; i < vValue.size(); i++) {
                if (vfBest[i]) {
                    LogPrint(BCLog::SELECTCOINS, "%s ", FormatMoney(vValue[i].txout.nValue));
                }
            }
            LogPrint(BCLog::SELECTCOINS, "total %s\n", FormatMoney(nBest));
        }
    }

    return true;
}

bool CWallet::SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl) const
{
    std::vector<COutput> vCoins(vAvailableCoins);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        for (const COutput& out : vCoins)
        {
            if (!out.fSpendable)
                 continue;
            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.insert(CInputCoin(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    std::set<CInputCoin> setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    for (const COutPoint& outpoint : vPresetInputs)
    {
        std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->tx->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->tx->vout[outpoint.n].nValue;
            setPresetCoins.insert(CInputCoin(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (std::vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(CInputCoin(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

    size_t nMaxChainLength = std::min(gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT), gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT));
    bool fRejectLongChains = gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    bool res = nTargetValue <= nValueFromPresetInputs ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 6, 0, vCoins, setCoinsRet, nValueRet) ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 1, 0, vCoins, setCoinsRet, nValueRet) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, 2, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, std::min((size_t)4, nMaxChainLength/3), vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength/2, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && !fRejectLongChains && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, std::numeric_limits<uint64_t>::max(), vCoins, setCoinsRet, nValueRet));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CWallet::SignTransaction(CMutableTransaction &tx)
{
    AssertLockHeld(cs_wallet); // mapWallet

    // sign the new tx
    CTransaction txNewConst(tx);
    int nIn = 0;
    for (const auto& input : tx.vin) {
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(input.prevout.hash);
        if(mi == mapWallet.end() || input.prevout.n >= mi->second.tx->vout.size()) {
            return false;
        }
        const CScript& scriptPubKey = mi->second.tx->vout[input.prevout.n].scriptPubKey;
        const CAmount& amount = mi->second.tx->vout[input.prevout.n].nValue;
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, amount, SIGHASH_ALL), scriptPubKey, sigdata)) {
            return false;
        }
        UpdateTransaction(tx, nIn, sigdata);
        nIn++;
    }
    return true;
}

bool CWallet::FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosInOut, std::string& strFailReason, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, CCoinControl coinControl)
{
    std::vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector.
    for (size_t idx = 0; idx < tx.vout.size(); idx++) {
        const CTxOut& txOut = tx.vout[idx];
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, setSubtractFeeFromOutputs.count(idx) == 1};
        vecSend.push_back(recipient);
    }

    coinControl.fAllowOtherInputs = true;

    for (const CTxIn& txin : tx.vin) {
        coinControl.Select(txin.prevout);
    }

    // Acquire the locks to prevent races to the new locked unspents between the
    // CreateTransaction call and LockCoin calls (when lockUnspents is true).
    LOCK2(cs_main, cs_wallet);

    CReserveKey reservekey(this);
    CWalletTx wtx;
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosInOut, strFailReason, coinControl, false)) {
        return false;
    }

    if (nChangePosInOut != -1) {
        tx.vout.insert(tx.vout.begin() + nChangePosInOut, wtx.tx->vout[nChangePosInOut]);
        // We don't have the normal Create/Commit cycle, and don't want to risk
        // reusing change, so just remove the key from the keypool here.
        reservekey.KeepKey();
    }

    // Copy output sizes from new transaction; they may have had the fee
    // subtracted from them.
    for (unsigned int idx = 0; idx < tx.vout.size(); idx++) {
        tx.vout[idx].nValue = wtx.tx->vout[idx].nValue;
    }

    // Add new txins while keeping original txin scriptSig/order.
    for (const CTxIn& txin : wtx.tx->vin) {
        if (!coinControl.IsSelected(txin.prevout)) {
            tx.vin.push_back(txin);

            if (lockUnspents) {
                LockCoin(txin.prevout);
            }
        }
    }

    return true;
}

OutputType CWallet::TransactionChangeType(OutputType change_type, const std::vector<CRecipient>& vecSend)
{
    // If -changetype is specified, always use that change type.
    if (change_type != OUTPUT_TYPE_NONE) {
        return change_type;
    }

    for (const auto& recipient : vecSend) {
        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;
        if (recipient.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            return OUTPUT_TYPE_BECH32;
        }
    }

    return OUTPUT_TYPE_LEGACY;
}

bool CWallet::CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet,
                                int& nChangePosInOut, std::string& strFailReason, const CCoinControl& coin_control, bool sign)
{
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    for (const auto& recipient : vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must not be negative");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty())
    {
        strFailReason = _("Transaction must have at least one recipient");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    txNew.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);
    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    unsigned int nBytes;
    {
        std::set<CInputCoin> setCoins;
        LOCK2(cs_main, cs_wallet);
        {
            std::vector<COutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, &coin_control);

            // Create change script that will be used if we need change
            // TODO: pass in scriptChange instead of reservekey so
            // change transaction isn't always pay-to-bitcoin-address
            CScript scriptChange;

            // coin control: send change to custom address
            if (!boost::get<CNoDestination>(&coin_control.destChange)) {
                scriptChange = GetScriptForDestination(coin_control.destChange);
            } else { // no coin control: send change to newly generated address
                // Note: We use a new key here to keep it from being obvious which side is the change.
                //  The drawback is that by not reusing a previous key, the change may be lost if a
                //  backup is restored, if the backup doesn't have the new private key for the change.
                //  If we reused the old key, it would be possible to add code to look for and
                //  rediscover unknown transactions that were written with keys of ours to recover
                //  post-backup change.

                // Reserve a new key pair from key pool
                CPubKey vchPubKey;
                bool ret;
                ret = reservekey.GetReservedKey(vchPubKey, true);
                if (!ret)
                {
                    strFailReason = _("Keypool ran out, please call keypoolrefill first");
                    return false;
                }

                const OutputType change_type = TransactionChangeType(coin_control.change_type, vecSend);

                LearnRelatedScripts(vchPubKey, change_type);
                scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
            }
            CTxOut change_prototype_txout(0, scriptChange);
            size_t change_prototype_size = GetSerializeSize(change_prototype_txout, SER_DISK, 0);

            CFeeRate discard_rate = GetDiscardRate(::feeEstimator);
            nFeeRet = 0;
            bool pick_new_inputs = true;
            CAmount nValueIn = 0;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                // vouts to the payees
                for (const auto& recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        assert(nSubtractFeeFromAmount != 0);
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    if (IsDust(txout, ::dustRelayFee))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                if (pick_new_inputs) {
                    nValueIn = 0;
                    setCoins.clear();
                    if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, &coin_control))
                    {
                        strFailReason = _("Insufficient funds");
                        return false;
                    }
                }

                const CAmount nChange = nValueIn - nValueToSelect;

                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    CTxOut newTxOut(nChange, scriptChange);

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (IsDust(newTxOut, discard_rate))
                    {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                    }
                    else
                    {
                        if (nChangePosInOut == -1)
                        {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size()+1);
                        }
                        else if ((unsigned int)nChangePosInOut > txNew.vout.size())
                        {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        std::vector<CTxOut>::iterator position = txNew.vout.begin()+nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                    }
                } else {
                    nChangePosInOut = -1;
                }

                // Fill vin
                //
                // Note how the sequence number is set to non-maxint so that
                // the nLockTime set above actually works.
                //
                // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
                // we use the highest possible value in that range (maxint-2)
                // to avoid conflicting with other possible uses of nSequence,
                // and in the spirit of "smallest possible change from prior
                // behavior."
                const uint32_t nSequence = coin_control.signalRbf ? MAX_BIP125_RBF_SEQUENCE : (CTxIn::SEQUENCE_FINAL - 1);
                for (const auto& coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.outpoint,CScript(),
                                              nSequence));

                // Fill in dummy signatures for fee calculation.
                if (!DummySignTx(txNew, setCoins)) {
                    strFailReason = _("Signing transaction failed");
                    return false;
                }

                nBytes = GetVirtualTransactionSize(txNew);

                // Remove scriptSigs to eliminate the fee calculation dummy signatures
                for (auto& vin : txNew.vin) {
                    vin.scriptSig = CScript();
                    vin.scriptWitness.SetNull();
                }

                nFeeNeeded = GetMinimumFee(nBytes, coin_control, ::mempool, ::feeEstimator, &feeCalc);

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded) {
                    // Reduce fee to only the needed amount if possible. This
                    // prevents potential overpayment in fees if the coins
                    // selected to meet nFeeNeeded result in a transaction that
                    // requires less fee than the prior iteration.

                    // If we have no change and a big enough excess fee, then
                    // try to construct transaction again only without picking
                    // new inputs. We now know we only need the smaller fee
                    // (because of reduced tx size) and so we should add a
                    // change output. Only try this once.
                    if (nChangePosInOut == -1 && nSubtractFeeFromAmount == 0 && pick_new_inputs) {
                        unsigned int tx_size_with_change = nBytes + change_prototype_size + 2; // Add 2 as a buffer in case increasing # of outputs changes compact size
                        CAmount fee_needed_with_change = GetMinimumFee(tx_size_with_change, coin_control, ::mempool, ::feeEstimator, nullptr);
                        CAmount minimum_value_for_change = GetDustThreshold(change_prototype_txout, discard_rate);
                        if (nFeeRet >= fee_needed_with_change + minimum_value_for_change) {
                            pick_new_inputs = false;
                            nFeeRet = fee_needed_with_change;
                            continue;
                        }
                    }

                    // If we have change output already, just increase it
                    if (nFeeRet > nFeeNeeded && nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                        CAmount extraFeePaid = nFeeRet - nFeeNeeded;
                        std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                        change_position->nValue += extraFeePaid;
                        nFeeRet -= extraFeePaid;
                    }
                    break; // Done, enough fee included.
                }
                else if (!pick_new_inputs) {
                    // This shouldn't happen, we should have had enough excess
                    // fee to pay for the new output and still meet nFeeNeeded
                    // Or we should have just subtracted fee from recipients and
                    // nFeeNeeded should not have changed
                    strFailReason = _("Transaction fee and change calculation failed");
                    return false;
                }

                // Try to reduce change to include necessary fee
                if (nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                    CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;
                    std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                    // Only reduce change if remaining amount is still a large enough output.
                    if (change_position->nValue >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                        change_position->nValue -= additionalFeeNeeded;
                        nFeeRet += additionalFeeNeeded;
                        break; // Done, able to increase fee from change
                    }
                }

                // If subtracting fee from recipients, we now know what fee we
                // need to subtract, we have no reason to reselect inputs
                if (nSubtractFeeFromAmount > 0) {
                    pick_new_inputs = false;
                }

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }

        if (nChangePosInOut == -1) reservekey.ReturnKey(); // Return any reserved key if we don't have change

        if (sign)
        {
            CTransaction txNewConst(txNew);
            int nIn = 0;
            for (const auto& coin : setCoins)
            {
                const CScript& scriptPubKey = coin.txout.scriptPubKey;
                SignatureData sigdata;

                if (!ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.txout.nValue, SIGHASH_ALL), scriptPubKey, sigdata))
                {
                    strFailReason = _("Signing transaction failed");
                    return false;
                } else {
                    UpdateTransaction(txNew, nIn, sigdata);
                }

                nIn++;
            }
        }

        // Embed the constructed transaction data in wtxNew.
        wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));

        // Limit size
        if (GetTransactionWeight(*wtxNew.tx) >= MAX_STANDARD_TX_WEIGHT)
        {
            strFailReason = _("Transaction too large");
            return false;
        }
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(wtxNew.tx, 0, 0, 0, false, false, uint256(), 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }

    LogPrintf("Fee Calculation: Fee:%d Bytes:%u Needed:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              nFeeRet, nBytes, nFeeNeeded, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              100 * feeCalc.est.pass.withinTarget / (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool),
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              100 * feeCalc.est.fail.withinTarget / (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool),
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return true;
}

bool CWallet::CreateAsset(CTransactionRef& tx, std::string& strFail, const std::string& strTicker, const std::string& strHeadline, const uint256& hashPayload, const CAmount& nFee, const int64_t nSupply, const std::string& strControllerDest, const std::string& strGenesisDest, bool fImmutable)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!\n";
        return false;
    }

    CTxDestination destControl = DecodeDestination(strControllerDest);
    if (!fImmutable && !IsValidDestination(destControl)) {
        strFail = "Invalid controller destination";
        return false;
    }

    CTxDestination destGenesis = DecodeDestination(strGenesisDest);
    if (!IsValidDestination(destGenesis)) {
        strFail = "Invalid genesis destination";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BITASSET_CREATE_VERSION;

    // BitAsset info
    mtx.ticker = strTicker;
    mtx.headline = strHeadline;
    mtx.payload = hashPayload;

    // contoller output
    if (fImmutable)
        mtx.vout.push_back(CTxOut(1, CScript() << OP_RETURN));
    else
        mtx.vout.push_back(CTxOut(1, GetScriptForDestination(destControl)));

    // genesis output
    mtx.vout.push_back(CTxOut(nSupply, GetScriptForDestination(destGenesis)));

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    // Select coins to cover fee
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nFee, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to cover fee!\n";
        return false;
    }

    // Handle change if there is any
    const CAmount nChange = nAmountRet - nFee;
    CReserveKey reserveKey(this);
    if (nChange > 0) {
        CScript scriptChange;

        // Reserve a new key pair from key pool
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey))
        {
            strFail = "Keypool ran out, please call keypoolrefill first!\n";
            return false;
        }
        scriptChange = GetScriptForDestination(vchPubKey.GetID());

        CTxOut out(nChange, scriptChange);
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    // Add inputs
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // Dummy sign the transaction to calculate minimum fee
    std::set<CInputCoin> setCoinsTemp = setCoins;
    if (!DummySignTx(mtx, setCoinsTemp)) {
        strFail = "Dummy signing transaction for required fee calculation failed!";
        return false;
    }

    // Get transaction size with dummy signatures
    unsigned int nBytes = GetVirtualTransactionSize(mtx);

    // Calculate fee
    CCoinControl coinControl;
    FeeCalculation feeCalc;
    CAmount nFeeNeeded = GetMinimumFee(nBytes, coinControl, ::mempool, ::feeEstimator, &feeCalc);

    // Check that the fee is valid for relay
    if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
        strFail = "Transaction too large for fee policy";
        return false;
    }

    // Check the user set fee
    if (nFee < nFeeNeeded) {
        strFail = "The fee you have set is too small!";
        return false;
    }

    // Remove dummy signatures
    for (auto& vin : mtx.vin) {
        vin.scriptSig = CScript();
        vin.scriptWitness.SetNull();
    }

    // Sign the inputs
    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        const CScript& scriptPubKey = coin.txout.scriptPubKey;
        SignatureData sigdata;

        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), scriptPubKey, sigdata))
        {
            strFail = "Signing inputs failed!\n";
            return false;
        } else {
            UpdateTransaction(mtx, nIn, sigdata);
        }

        nIn++;
    }

    // Broadcast transaction
    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);

    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    walletTx.nControlN = 0;

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit BitAsset creation transaction! Reject reason: " + FormatStateMessage(state) + "\n";
        return false;
    }
    tx = walletTx.tx;

    return true;
}

bool CWallet::IssueBill(CTransactionRef& tx, std::string& strFail, const std::vector<unsigned char>& vchBody, const CAmount& nAmount, const CAmount& nAmountEscrow, uint32_t nMaturityHeight, uint32_t nGraceBlocks, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }
    if (vchBody.empty() || vchBody.size() > MAX_BILL_BODY_BYTES) {
        strFail = "Invalid encrypted body size!";
        return false;
    }
    if (nAmount <= 0 || nAmountEscrow <= 0) {
        strFail = "Invalid bill amount / escrow amount!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    if (nMaturityHeight <= (uint32_t)chainActive.Height()) {
        strFail = "Maturity height must be in the future!";
        return false;
    }

    // Fresh keys per bill (Tx-9 privacy default). v1 is the single-wallet
    // issuance handshake: this wallet plays drawer, acceptor and holder.
    CPubKey pubDrawer, pubAcceptor, pubHolder;
    if (!GetKeyFromPool(pubDrawer) || !GetKeyFromPool(pubAcceptor) || !GetKeyFromPool(pubHolder)) {
        strFail = "Keypool ran out, please call keypoolrefill first!";
        return false;
    }

    CKey keyDrawer, keyAcceptor;
    if (!GetKey(pubDrawer.GetID(), keyDrawer) || !GetKey(pubAcceptor.GetID(), keyAcceptor)) {
        strFail = "Failed to load bill signing keys!";
        return false;
    }

    BillIssue issue;
    issue.vchEncryptedBody = vchBody;
    issue.amount = nAmount;
    issue.nMaturityHeight = nMaturityHeight;
    issue.nGraceBlocks = nGraceBlocks;
    issue.vchDrawerPubKey = std::vector<unsigned char>(pubDrawer.begin(), pubDrawer.end());
    issue.vchAcceptorPubKey = std::vector<unsigned char>(pubAcceptor.begin(), pubAcceptor.end());
    issue.vchHolderPubKey = std::vector<unsigned char>(pubHolder.begin(), pubHolder.end());

    const uint256 billID = BillIDFromBody(vchBody);
    const uint256 sighash = BillIssueSigHash(billID, nAmount, nAmountEscrow, nMaturityHeight, nGraceBlocks,
            issue.vchDrawerPubKey, issue.vchAcceptorPubKey, issue.vchHolderPubKey);

    if (!keyDrawer.Sign(sighash, issue.vchDrawerSig) || !keyAcceptor.Sign(sighash, issue.vchAcceptorSig)) {
        strFail = "Failed to sign bill issue!";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_ISSUE;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << issue;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // vout[0] title to the holder, vout[1] the escrow bond
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, GetScriptForDestination(pubHolder.GetID())));
    mtx.vout.push_back(CTxOut(nAmountEscrow, BillEscrowScript(billID)));

    // Fund escrow + title + fee
    const CAmount nTarget = nAmountEscrow + BILL_TITLE_VALUE + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to fund the bill escrow + fee!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) {
            strFail = "Keypool ran out, please call keypoolrefill first!";
            return false;
        }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // Sign the funding inputs
    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing bill issue inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit bill issue transaction! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    tx = walletTx.tx;

    return true;
}

bool CWallet::EndorseBill(std::string& strFail, uint256& txidOut, const uint32_t nBillID, const std::vector<unsigned char>& vchToPubKey, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }

    CPubKey pubTo(vchToPubKey);
    if (!pubTo.IsFullyValid() || vchToPubKey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) {
        strFail = "Invalid endorsee pubkey (need 33-byte compressed hex)!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CBill bill;
    if (!pbilltree->GetBill(nBillID, bill)) {
        strFail = "Unknown bill!";
        return false;
    }
    if (bill.status != BILL_STATUS_ACTIVE) {
        strFail = "Bill is not active!";
        return false;
    }

    CPubKey pubHolder(bill.vchHolderPubKey);
    CKey keyHolder;
    if (!GetKey(pubHolder.GetID(), keyHolder)) {
        strFail = "This wallet does not hold the bill (holder key missing)!";
        return false;
    }

    const uint32_t nAtHeight = (uint32_t)chainActive.Height();

    BillEndorse endorse;
    endorse.nBillID = nBillID;
    endorse.endorsement.vchFrom = bill.vchHolderPubKey;
    endorse.endorsement.vchTo = vchToPubKey;
    endorse.endorsement.nAtHeight = nAtHeight;

    const uint256 sighash = BillEndorseSigHash(bill.billID, vchToPubKey, nAtHeight);
    if (!keyHolder.Sign(sighash, endorse.endorsement.vchSig)) {
        strFail = "Failed to sign endorsement!";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_ENDORSE;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << endorse;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // vin[0] = the title, vout[0] = the title moving to the endorsee
    mtx.vin.push_back(CTxIn(bill.outTitle.hash, bill.outTitle.n, CScript()));
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, GetScriptForDestination(pubTo.GetID())));

    // Fund the fee (the title value passes through)
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nFee, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to cover the fee!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nFee;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) {
            strFail = "Keypool ran out, please call keypoolrefill first!";
            return false;
        }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // Sign: vin[0] against the title's P2PKH(holder), the rest against the
    // selected funding coins
    const CTransaction txToSign = mtx;
    {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, 0, BILL_TITLE_VALUE, SIGHASH_ALL), GetScriptForDestination(pubHolder.GetID()), sigdata)) {
            strFail = "Signing the title input failed!";
            return false;
        }
        UpdateTransaction(mtx, 0, sigdata);
    }
    int nIn = 1;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing endorsement inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit endorsement transaction! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::RetireBill(std::string& strFail, uint256& txidOut, const uint32_t nBillID, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CBill bill;
    if (!pbilltree->GetBill(nBillID, bill)) {
        strFail = "Unknown bill!";
        return false;
    }
    if (bill.status != BILL_STATUS_ACTIVE) {
        strFail = "Bill is not active!";
        return false;
    }
    // A discount house bought this paper: op 3 hard-rejects it
    // (bad-bill-retire-house-held), so retire it as op 7 instead. Same
    // authority (the acceptor), same money (face to the current holder, which
    // is now the house's pinned custody key) - only the book exit differs.
    if (bill.nOwnerHouseID != 0)
        return HouseHeldRetireBill(strFail, txidOut, bill, nFee);

    CPubKey pubAcceptor(bill.vchAcceptorPubKey);
    CKey keyAcceptor;
    if (!GetKey(pubAcceptor.GetID(), keyAcceptor)) {
        strFail = "This wallet is not the bill's acceptor (drawee key missing)!";
        return false;
    }

    // Fund face + fee; the escrow input contributes its bond value
    const CAmount nNeeded = bill.amount + nFee;
    const CAmount nTargetFunding = nNeeded > bill.amountEscrow ? nNeeded - bill.amountEscrow : CAmount(0);

    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (nTargetFunding > 0) {
        std::vector<COutput> vCoins;
        AvailableCoins(vCoins, true /* fOnlySafe */);
        if (!SelectCoins(vCoins, nTargetFunding, setCoins, nAmountRet)) {
            strFail = "Could not collect enough coins to pay the bill face + fee!";
            return false;
        }
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_RETIRE;

    // vout[0] = face payment to the current holder; change back to us
    mtx.vout.push_back(CTxOut(bill.amount, BillScriptForPubKey(bill.vchHolderPubKey)));

    CReserveKey reserveKey(this);
    const CAmount nChange = bill.amountEscrow + nAmountRet - bill.amount - nFee;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) {
            strFail = "Keypool ran out, please call keypoolrefill first!";
            return false;
        }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }
    else if (nChange < 0) {
        strFail = "Escrow + funding does not cover face + fee!";
        return false;
    }

    // vin[0] = the escrow (empty scriptSig - consensus rules govern it)
    mtx.vin.push_back(CTxIn(bill.outEscrow.hash, bill.outEscrow.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // The retire signature binds the exact output set
    BillRetire retire;
    retire.nBillID = nBillID;
    const uint256 sighash = BillRetireSigHash(bill.billID, BillHashOutputs(mtx));
    if (!keyAcceptor.Sign(sighash, retire.vchAcceptorSig)) {
        strFail = "Failed to sign bill retirement!";
        return false;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << retire;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // Sign the funding inputs (vin[0] escrow stays unsigned)
    const CTransaction txToSign = mtx;
    int nIn = 1;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing retirement inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit retirement transaction! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::ClaimBillEscrow(std::string& strFail, uint256& txidOut, const uint32_t nBillID, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CBill bill;
    if (!pbilltree->GetBill(nBillID, bill)) {
        strFail = "Unknown bill!";
        return false;
    }
    if (bill.status != BILL_STATUS_ACTIVE) {
        strFail = "Bill is not active!";
        return false;
    }
    // House-held paper defaults into op 8, whose authority is the owning house's
    // QUORUM rather than the single holder key - so this runs from the house's
    // wallet, not the custody-key holder's. That difference is the point: a
    // custody key alone must never be able to direct the escrow payout.
    if (bill.nOwnerHouseID != 0)
        return HouseHeldClaimBillEscrow(strFail, txidOut, bill, nFee);
    if ((uint64_t)chainActive.Height() + 1 <= (uint64_t)bill.nMaturityHeight + bill.nGraceBlocks) {
        strFail = "Bill has not passed maturity + grace yet!";
        return false;
    }

    CPubKey pubHolder(bill.vchHolderPubKey);
    CKey keyHolder;
    if (!GetKey(pubHolder.GetID(), keyHolder)) {
        strFail = "This wallet does not hold the bill (holder key missing)!";
        return false;
    }

    if (nFee <= 0 || nFee >= bill.amountEscrow) {
        strFail = "Fee must be positive and below the escrow value!";
        return false;
    }

    // Pay the escrow (minus fee) to a fresh key of ours
    CPubKey pubPayout;
    if (!GetKeyFromPool(pubPayout)) {
        strFail = "Keypool ran out, please call keypoolrefill first!";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_CLAIM;

    mtx.vin.push_back(CTxIn(bill.outEscrow.hash, bill.outEscrow.n, CScript()));
    mtx.vout.push_back(CTxOut(bill.amountEscrow - nFee, GetScriptForDestination(pubPayout.GetID())));

    // The claim signature binds the exact output set
    BillClaim claim;
    claim.nBillID = nBillID;
    const uint256 sighash = BillClaimSigHash(bill.billID, BillHashOutputs(mtx));
    if (!keyHolder.Sign(sighash, claim.vchHolderSig)) {
        strFail = "Failed to sign escrow claim!";
        return false;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << claim;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CReserveKey reserveKey(this);
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit escrow claim transaction! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}


// House helper: gather exactly nRequired approver (index, sig) pairs from
// ACTIVE partners whose keys this wallet holds.
static bool SignHouseApprovers(CWallet* pwallet, const CHouse& house, const uint256& sighash,
                               std::vector<uint32_t>& vIndex,
                               std::vector<std::vector<unsigned char>>& vSig,
                               std::string& strFail)
{
    vIndex.clear();
    vSig.clear();
    for (size_t i = 0; i < house.vPartner.size() && vIndex.size() < house.nThresholdM; i++) {
        const HousePartner& partner = house.vPartner[i];
        if (partner.status != HOUSE_PARTNER_ACTIVE)
            continue;
        CKey key;
        if (!pwallet->GetKey(CPubKey(partner.vchPubKey).GetID(), key))
            continue;
        std::vector<unsigned char> vchSig;
        if (!key.Sign(sighash, vchSig))
            continue;
        vIndex.push_back(i);
        vSig.push_back(vchSig);
    }
    if (vIndex.size() < house.nThresholdM) {
        strFail = "This wallet does not hold enough active partner keys to reach the house threshold!";
        return false;
    }
    return true;
}

// One of this wallet's spendable note coins of a house.
struct WalletNoteCoin {
    COutPoint outpoint;
    uint64_t units;
    std::vector<unsigned char> vchHolderPubKey;
    CScript script;
    uint32_t nDemandHeight;   // 0 = not demanded (3.5)
};

// Collect this wallet's unspent note coins of nHouseID, grouped by holder key
// (a TRANSFER/REDEEM spends a SINGLE holder's coins in v1).
// Grouped by (holder, demand height): consensus forbids mixing demand heights
// inside one note op (the interest owed would be ambiguous), so the wallet must
// never assemble such a spend.
static void CollectWalletNoteCoins(CWallet* pwallet, uint32_t nHouseID,
                                   std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>>& mapByHolder)
{
    for (const auto& entry : pwallet->mapWallet) {
        const uint256& wtxid = entry.first;
        const CWalletTx* pcoin = &entry.second;
        if (pcoin->tx->nVersion != TRANSACTION_NOTE_VERSION &&
                pcoin->tx->nVersion != TRANSACTION_POOL_VERSION &&
                pcoin->tx->nVersion != TRANSACTION_BILL_VERSION)
            continue;
        // Only coins that really exist in the UTXO set (or are on their way
        // there) may be offered. depth<0 is conflicted; an ABANDONED tx and an
        // unconfirmed tx that has been EVICTED from the mempool both sit at
        // depth 0 and would otherwise be offered as spendable - building a note
        // op on one produces a missing-inputs tx that ATMP silently drops, and
        // CommitTransaction does NOT surface that, so the RPC would hand the
        // caller a txid for a transaction that can never confirm.
        const int nDepth = pcoin->GetDepthInMainChain();
        if (nDepth < 0)
            continue;
        if (pcoin->isAbandoned())
            continue;
        if (nDepth == 0 && !pcoin->InMempool())
            continue;

        // A v11 DISCOUNT (B1) MINTS note coins too - it is how the seller is
        // paid. Without this arm the seller's entire proceeds are invisible to
        // the wallet's note machinery: listmynotes, transfernote, redeemnote and
        // settle presentment would all miss them, and §2.6's "the seller walks
        // away with working capital" would be false at the wallet layer.
        // Same shared payload-pure tagger, same undemanded-note shape as a pool
        // payout, so this cannot drift from consensus either.
        if (pcoin->tx->nVersion == TRANSACTION_BILL_VERSION ||
                pcoin->tx->nVersion == TRANSACTION_POOL_VERSION) {
            const bool fBillTx = pcoin->tx->nVersion == TRANSACTION_BILL_VERSION;
            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                Coin probe;
                if (fBillTx)
                    ApplyBillCoinTags(*pcoin->tx, i, probe);
                else
                    ApplyPoolCoinTags(*pcoin->tx, i, probe);
                if (!probe.fNote || probe.fPoolEscrow || probe.nHouseID != nHouseID)
                    continue;
                if (pwallet->IsSpent(wtxid, i))
                    continue;
                if (pwallet->IsMine(pcoin->tx->vout[i]) == ISMINE_NO)
                    continue;
                CTxDestination dest;
                if (!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, dest))
                    continue;
                const CKeyID* keyid = boost::get<CKeyID>(&dest);
                if (!keyid)
                    continue;
                CPubKey pub;
                if (!pwallet->GetPubKey(*keyid, pub))
                    continue;

                WalletNoteCoin nc;
                nc.outpoint = COutPoint(wtxid, i);
                nc.units = probe.nNoteUnits;
                nc.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
                nc.script = pcoin->tx->vout[i].scriptPubKey;
                nc.nDemandHeight = 0;
                mapByHolder[std::make_pair(*keyid, (uint32_t)0)].push_back(nc);
            }
            continue;
        }

        std::vector<uint64_t> vUnits;
        uint32_t nHouse = 0;
        if (pcoin->tx->nNoteOp == NOTE_OP_MINT) {
            NoteMint m;
            if (DecodeNotePayload(pcoin->tx->vchNotePayload, m)) { nHouse = m.nHouseID; vUnits = m.vUnits; }
        } else if (pcoin->tx->nNoteOp == NOTE_OP_TRANSFER) {
            NoteTransfer x;
            if (DecodeNotePayload(pcoin->tx->vchNotePayload, x)) { nHouse = x.nHouseID; vUnits = x.vUnits; }
        } else if (pcoin->tx->nNoteOp == NOTE_OP_DEMAND) {
            // A DEMAND re-issues the notes (stamped with the demand height) -
            // its outputs are live note coins like any other, and if we did not
            // decode them here the holder could lodge a demand and then never
            // find their own note again.
            NoteDemand d;
            if (DecodeNotePayload(pcoin->tx->vchNotePayload, d)) { nHouse = d.nHouseID; vUnits = d.vUnits; }
        } else if (pcoin->tx->nNoteOp == NOTE_OP_PROTEST) {
            // A PROTEST re-issues the marked coins custody-shaped (B3 T-b7).
            // The holder's wallet committed the protest itself, so the tx is
            // tracked here even though custody outputs are never IsMine.
            NoteProtest p;
            if (DecodeNotePayload(pcoin->tx->vchNotePayload, p)) { nHouse = p.nHouseID; vUnits = p.vUnits; }
        } else {
            continue;
        }
        if (nHouse != nHouseID)
            continue;

        for (size_t i = 0; i < vUnits.size(); i++) {
            if (pwallet->IsSpent(wtxid, i))
                continue;
            const CScript& script = pcoin->tx->vout[i].scriptPubKey;
            // Two shapes (B3 T-b7): the holder's own P2PKH, or the consensus-
            // custody script <holder-keyid> OP_DROP OP_TRUE that a pre-auth
            // demand re-issues onto. Custody coins are NOT IsMine - the wallet
            // knows about them because it committed the demand/protest tx
            // itself - so the ownership test there is key POSSESSION.
            CKeyID keyid;
            if (IsNotePreAuthScript(script)) {
                keyid = CKeyID(uint160(std::vector<unsigned char>(script.begin() + 1, script.begin() + 21)));
            } else {
                if (pwallet->IsMine(pcoin->tx->vout[i]) == ISMINE_NO)
                    continue;
                CTxDestination dest;
                if (!ExtractDestination(script, dest))
                    continue;
                const CKeyID* pkeyid = boost::get<CKeyID>(&dest);
                if (!pkeyid)
                    continue;
                keyid = *pkeyid;
            }
            CPubKey pub;
            if (!pwallet->GetPubKey(keyid, pub))
                continue;
            // The demand stamp lives on the COIN, so read it from the UTXO set
            // (a wallet tx alone cannot tell us the height it confirmed at).
            // For B3 coins this is the raw TAG (height + marker bits) - the
            // grouping key stays the exact tag so a group is always uniform.
            Coin coinUtxo;
            uint32_t nDemandHeight = 0;
            if (pcoinsTip->GetCoin(COutPoint(wtxid, i), coinUtxo) && !coinUtxo.IsSpent())
                nDemandHeight = coinUtxo.nDemandHeight;

            WalletNoteCoin nc;
            nc.outpoint = COutPoint(wtxid, i);
            nc.units = vUnits[i];
            nc.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
            nc.script = script;
            nc.nDemandHeight = nDemandHeight;
            mapByHolder[std::make_pair(keyid, nDemandHeight)].push_back(nc);
        }
    }
}

static bool HouseStateChangePending(uint32_t nHouseID);   // defined below (T-s6: settle-aware)
static bool HouseFailFastEnabled();                       // defined below (A8: regtest-only escape)

bool CWallet::MintNote(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nUnits, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // Fail fast if the mempool already holds a house-state-changing op for this
    // house - incl. a v16 SETTLE, which takes BOTH its houses' slots. Without
    // this the ATMP guard still rejects, but CommitTransaction does not surface
    // that to the RPC caller (the house-review precedent).
    if (HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }
    if (nUnits == 0 || nUnits > (uint64_t)MAX_MONEY) { strFail = "Invalid note units!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, chainActive.Height() + 1) != HOUSE_STATUS_OPEN) { strFail = "House is not effectively open (stressed/insolvent/wounddown) - minting blocked!"; return false; }

    // Fail-fast cap check (consensus enforces this too, but CommitTransaction
    // does not surface an ATMP rejection to the RPC caller - the house-review
    // precedent).
    {
        if (house.nMintedUnits > (uint64_t)MAX_MONEY - nUnits ||
                house.nMintedUnits + nUnits > HouseCapitalCapUnits(house)) {
            strFail = "Mint would exceed the escrow cap (N + mint <= lambda * active escrow)!";
            return false;
        }
        // A recent published attestation is still required (cadence/transparency);
        // a never-attested house has a zero published reserve and cannot mint.
        const int nNextHeight = chainActive.Height() + 1;
        if ((uint32_t)nNextHeight < house.nLastAttestHeight ||
                (uint32_t)nNextHeight - house.nLastAttestHeight > HOUSE_ATTEST_CADENCE) {
            strFail = "Attestation is stale - attest the house's reserves before minting!";
            return false;
        }
        if (house.nMintedUnits + nUnits > HouseReserveCapUnits(house)) {
            strFail = "Mint would exceed the published reserve cap (N + mint <= attested reserves / rho) - attest more liquid reserves first!";
            return false;
        }
        // The rho-at-mint LIVENESS half (R-i7 / DR-1) is checked below, once the
        // reserve proof is gathered: the binding cap is min(published, proven).
    }

    // Fresh holder key (Tx-9 hygiene)
    CPubKey pubHolder;
    if (!GetKeyFromPool(pubHolder)) { strFail = "Keypool ran out, please call keypoolrefill first!"; return false; }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_MINT;
    // vout[0] = the note (dust base, nUnits claim) to the holder. Built before
    // the M-of-N signature, which binds hashOutputs.
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, NoteScriptForPubKey(std::vector<unsigned char>(pubHolder.begin(), pubHolder.end()))));

    // R-i7 rho-at-mint reserve proof (DR-1): the mint proves the house's LIVE
    // liquid reserves in this very transaction, and funds its dust+fee from
    // OUTSIDE the proof set (consensus rejects a mint that spends the coins it
    // proves). Same partition as AttestHouse: gather PLAIN single-key candidates,
    // fund from the non-proof pool, and release the smallest candidates to
    // funding only if that pool can't cover the tiny dust+fee.
    const uint32_t nAsOfHeight = (uint32_t)chainActive.Height();
    const uint256 hashAsOf = chainActive.Tip()->GetBlockHash();
    const int nNextH = chainActive.Height() + 1;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);

    struct MintReserveCand { COutPoint outpoint; CTxOut txout; CKeyID keyid; };
    std::vector<MintReserveCand> vCand;
    std::vector<COutput> vFeePool;
    for (const COutput& out : vCoins) {
        const COutPoint outpoint(out.tx->GetHash(), out.i);
        const CTxOut& txout = out.tx->tx->vout[out.i];
        Coin coin;
        bool fReserve = out.nDepth >= 1 && out.fSpendable &&
                pcoinsTip->GetCoin(outpoint, coin) && !coin.IsSpent() &&
                coin.nHeight <= nAsOfHeight &&
                !(coin.fBitAsset || coin.fBitAssetControl || coin.fBill ||
                  coin.fBillEscrow || coin.fHouseEscrow || coin.fNote) &&
                !(coin.IsCoinBase() && nNextH - (int)coin.nHeight < COINBASE_MATURITY);
        CKeyID keyid;
        if (fReserve) {
            CTxDestination dest;
            fReserve = ExtractDestination(txout.scriptPubKey, dest);
            if (fReserve) {
                if (const CKeyID* id = boost::get<CKeyID>(&dest)) keyid = *id;
                else if (const WitnessV0KeyHash* wid = boost::get<WitnessV0KeyHash>(&dest)) keyid = CKeyID(*wid);
                else fReserve = false;
            }
            CKey probe;
            if (fReserve) fReserve = GetKey(keyid, probe);
            if (fReserve)
                fReserve = txout.scriptPubKey == GetScriptForDestination(keyid) ||
                           txout.scriptPubKey == GetScriptForDestination(WitnessV0KeyHash(keyid));
        }
        if (fReserve) { MintReserveCand c; c.outpoint = outpoint; c.txout = txout; c.keyid = keyid; vCand.push_back(c); }
        else vFeePool.push_back(out);
    }
    std::sort(vCand.begin(), vCand.end(),
        [](const MintReserveCand& a, const MintReserveCand& b) { return a.txout.nValue > b.txout.nValue; });

    // Prove the FEWEST LARGEST candidates that cover the reserve cap - not the
    // whole balance. Proving everything would sweep the small coins into the
    // proof and starve the tx of anything to fund the dust+fee from; the house
    // only has to demonstrate it holds ENOUGH liquid reserve, not all of it. The
    // unproven (smaller) candidates then fund the mint.
    const uint64_t needUnits = house.nMintedUnits + nUnits;
    CAmount amountProven = 0;
    std::vector<AttestProof> vReserveProofs;
    size_t nProven = 0;
    for (; nProven < vCand.size() && nProven < MAX_ATTEST_PROOFS; nProven++) {
        if (((uint64_t)amountProven * 100) / HOUSE_RESERVE_FLOOR_PCT >= needUnits)
            break;
        const MintReserveCand& c = vCand[nProven];
        CKey key;
        if (!GetKey(c.keyid, key)) { strFail = "Lost a reserve key mid-build!"; return false; }
        AttestProof proof;
        proof.outpoint = c.outpoint;
        const CPubKey pub = key.GetPubKey();
        proof.vchPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
        const uint256 challenge = HouseAttestChallenge(house.houseID, nAsOfHeight, hashAsOf, c.outpoint);
        if (!key.Sign(challenge, proof.vchSig)) { strFail = "Failed to sign a reserve proof!"; return false; }
        vReserveProofs.push_back(proof);
        amountProven += c.txout.nValue;
    }
    // Fail-fast the rho cap on min(published, proven) reserves (consensus too).
    const CAmount amountEff = std::min(house.amountLastAttestReserves, amountProven);
    const uint64_t reserveCap = ((uint64_t)amountEff * 100) / HOUSE_RESERVE_FLOOR_PCT;
    if (needUnits > reserveCap) {
        strFail = "Mint would exceed the reserve cap (N + mint <= min(attested, live) reserves / rho) - "
                  "attest and hold more liquid reserve coins before minting!";
        return false;
    }

    // The unproven candidates (smaller coins) join the fee pool for funding.
    std::set<COutPoint> setProven;
    for (const AttestProof& pr : vReserveProofs) setProven.insert(pr.outpoint);
    for (const COutput& out : vCoins) {
        const COutPoint op(out.tx->GetHash(), out.i);
        bool fCand = false;
        for (const MintReserveCand& c : vCand) if (c.outpoint == op) { fCand = true; break; }
        if (fCand && !setProven.count(op))
            vFeePool.push_back(out);
    }

    // Fund the note dust + fee from OUTSIDE the proof set.
    const CAmount nTarget = NOTE_DUST_VALUE + nFee;
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vFeePool, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not fund the note dust + fee separately from the reserve proof - "
                  "the wallet needs a spare liquid coin the mint is not proving as reserve!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }
    // Inputs added BEFORE the approver signature - the mint sighash binds
    // hashPrevouts (the tx-unique input set) to defeat mint replay.
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    NoteMint mint;
    mint.nHouseID = nHouseID;
    mint.vUnits.push_back(nUnits);
    mint.nAsOfHeight = nAsOfHeight;
    mint.vReserveProofs = vReserveProofs;
    if (!SignHouseApprovers(this, house,
            NoteMintSigHash(nHouseID, mint.vUnits, NoteHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx)),
            mint.vApproverIndex, mint.vApproverSig, strFail))
        return false;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << mint;
    mtx.vchNotePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing note mint inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit note mint! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::TransferNote(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nUnits, const CAmount& nFee, const CScript& scriptRecipient)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    if (nUnits == 0) { strFail = "Invalid note units!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // Pick a single holder whose note coins sum to >= nUnits (single-sender v1).
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nHouseID, mapByHolder);
    std::vector<WalletNoteCoin> chosen;
    uint64_t have = 0;
    for (const auto& kv : mapByHolder) {
        // Pre-auth demanded coins CANNOT transfer (B3: the standing
        // authorisation binds a payout script; a moved coin would have the
        // house discharge to a stale script). Consensus rejects it - skip the
        // group so the wallet never builds the doomed tx.
        if (NoteDemandIsPreAuth(kv.first.second))
            continue;
        uint64_t sum = 0;
        for (const WalletNoteCoin& nc : kv.second) sum += nc.units;
        if (sum >= nUnits) { chosen = kv.second; have = sum; break; }
    }
    if (chosen.empty()) { strFail = "No single holder has enough transferable note units (pre-auth demanded coins cannot transfer)!"; return false; }

    CKey keySender;
    if (!GetKey(CPubKey(chosen[0].vchHolderPubKey).GetID(), keySender)) { strFail = "Sender key missing!"; return false; }

    // Spend the smallest set of the holder's coins covering nUnits.
    std::sort(chosen.begin(), chosen.end(), [](const WalletNoteCoin& a, const WalletNoteCoin& b){ return a.units > b.units; });
    std::vector<WalletNoteCoin> spend;
    uint64_t spent = 0;
    for (const WalletNoteCoin& nc : chosen) { spend.push_back(nc); spent += nc.units; if (spent >= nUnits) break; }

    // Recipient script for vout[0]: an external payee's P2PKH (scriptRecipient)
    // when supplied, else a fresh own key (self-transfer, the v1 default). A note
    // is a plain P2PKH coin, so paying an external address just works — the
    // recipient's wallet tags it from the tx payload on connect.
    CScript scriptRecipientOut;
    if (!scriptRecipient.empty()) {
        scriptRecipientOut = scriptRecipient;
    } else {
        CPubKey pubRecipient;
        if (!GetKeyFromPool(pubRecipient)) { strFail = "Keypool ran out!"; return false; }
        scriptRecipientOut = NoteScriptForPubKey(std::vector<unsigned char>(pubRecipient.begin(), pubRecipient.end()));
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_TRANSFER;

    NoteTransfer xfer;
    xfer.nHouseID = nHouseID;
    // Carry the demand clock forward: a demanded note stays transferable and
    // keeps accruing from its original demand date (consensus requires the
    // payload value to equal the spent notes' height).
    xfer.nDemandHeight = spend[0].nDemandHeight;
    // vout[0] = nUnits to the recipient; vout[1] = change note back to the sender
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, scriptRecipientOut));
    xfer.vUnits.push_back(nUnits);
    const uint64_t changeUnits = spent - nUnits;
    if (changeUnits > 0) {
        mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, chosen[0].script)); // back to sender
        xfer.vUnits.push_back(changeUnits);
    }

    // Fund the note-output dust (spend note dust does not cover the new dust;
    // the burned note coins' dust becomes fee) + fee.
    const CAmount nDustNeeded = (CAmount)xfer.vUnits.size() * NOTE_DUST_VALUE;
    const CAmount nTarget = nDustNeeded + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the transfer dust + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    xfer.vchSenderPubKey = chosen[0].vchHolderPubKey;
    if (!keySender.Sign(NoteTransferSigHash(nHouseID, xfer.vUnits, BillHashOutputs(mtx)), xfer.vchSenderSig)) {
        strFail = "Failed to sign note transfer!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << xfer;
    mtx.vchNotePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // Inputs: the spent note coins (holder-signed) + the funding coins.
    for (const WalletNoteCoin& nc : spend)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const WalletNoteCoin& nc : spend) {
        SignatureData sigdata;
        CTxOut noteOut(NOTE_DUST_VALUE, nc.script);
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, noteOut.nValue, SIGHASH_ALL), nc.script, sigdata)) {
            strFail = "Signing note inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing transfer funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit note transfer! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

void CWallet::CollectNoteHoldings(std::map<uint32_t, WalletNoteHolding>& out)
{
    // Caller holds cs_main + cs_wallet and has synced (CollectWalletNoteCoins'
    // contract). Reuses the exact same per-house collector the note builders use,
    // so the hold view can never drift from what TransferNote/RedeemNote will spend.
    out.clear();
    if (!phousetree) return;
    for (const CHouse& house : phousetree->GetHouses()) {
        std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
        CollectWalletNoteCoins(this, house.nHouseID, mapByHolder);
        WalletNoteHolding h;
        for (const auto& kv : mapByHolder) {
            for (const WalletNoteCoin& nc : kv.second) {
                h.units += nc.units;
                if (nc.nDemandHeight > 0) h.demandedUnits += nc.units;
                if (NoteDemandIsPreAuth(nc.nDemandHeight)) {
                    h.preauthUnits += nc.units;
                    const uint32_t nDH = NoteDemandHeightOf(nc.nDemandHeight);
                    if (h.oldestDemandHeight == 0 || nDH < h.oldestDemandHeight)
                        h.oldestDemandHeight = nDH;
                }
                if (nc.nDemandHeight & NOTE_DEMAND_PROTESTED_BIT)
                    h.protestedUnits += nc.units;
                h.coins++;
            }
        }
        if (h.units > 0) out[house.nHouseID] = h;
    }
}

bool CWallet::DemandNote(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nUnits, const CAmount& nFee, const CScript& scriptPayout)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    if (nUnits == 0) { strFail = "Invalid note units!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // One op, two modes, keyed on house status - the consensus matrix
    // mirrored (B3 T-b3): Deferred => the 3.5 plain demand (the option
    // clause's queue); Open/Stressed => the B3 formal demand, pre-auth
    // REQUIRED (coins move onto consensus custody; the house can then
    // discharge alone, and MUST within the window or face protest).
    bool fPreAuth = false;
    uint256 houseID256;
    {
        CHouse house;
        if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
        houseID256 = house.houseID;
        const char chEff = HouseEffectiveStatus(house, chainActive.Height() + 1);
        if (chEff == HOUSE_STATUS_DEFERRED) {
            fPreAuth = false;
        } else if (chEff == HOUSE_STATUS_OPEN || chEff == HOUSE_STATUS_STRESSED) {
            fPreAuth = true;
        } else {
            strFail = "House is insolvent or wound down - the waterfall (claimnote) has replaced redemption!";
            return false;
        }
    }

    // An UNdemanded holding of exactly nUnits (mixing demand heights in one op
    // is a consensus error, and re-demanding would reset an existing clock).
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nHouseID, mapByHolder);
    std::vector<WalletNoteCoin> spend;
    uint64_t U = 0;
    for (const auto& kv : mapByHolder) {
        if (kv.first.second != 0)
            continue;   // already demanded
        uint64_t sum = 0;
        for (const WalletNoteCoin& nc : kv.second) sum += nc.units;
        if (sum == nUnits) { spend = kv.second; U = sum; break; }
    }
    if (spend.empty()) { strFail = "No undemanded holder's note coins sum exactly to that amount (transfer to consolidate first)!"; return false; }

    CKey keyHolder;
    if (!GetKey(CPubKey(spend[0].vchHolderPubKey).GetID(), keyHolder)) { strFail = "Holder key missing!"; return false; }

    // The notes are RE-ISSUED, stamped with the demand height by consensus -
    // nothing is surrendered. Plain mode re-issues to the holder's own P2PKH;
    // pre-auth mode moves them onto the consensus-custody script so the house
    // can spend them in a unilateral discharge (B3).
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_DEMAND;

    NoteDemand dem;
    dem.nHouseID = nHouseID;
    dem.vchHolderPubKey = spend[0].vchHolderPubKey;
    mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE,
        fPreAuth ? NotePreAuthScript(spend[0].vchHolderPubKey) : spend[0].script));
    dem.vUnits.push_back(U);

    if (fPreAuth) {
        dem.fPreAuth = 1;
        // The script the discharge must pay: the caller's, or the holder's own
        // P2PKH by default. The house's escrow script is poison (consensus
        // rejects it at the door - the discharge would be unbuildable and the
        // protest teeth would fire unjustly); fail fast with the reason.
        const CScript scriptPay = scriptPayout.empty()
            ? NoteScriptForPubKey(spend[0].vchHolderPubKey) : scriptPayout;
        if (scriptPay == HouseEscrowScript(houseID256)) {
            strFail = "The payout script must not be the house's own escrow script!";
            return false;
        }
        dem.vchPayoutScript = std::vector<unsigned char>(scriptPay.begin(), scriptPay.end());
        CKey keyPre;
        if (!GetKey(CPubKey(spend[0].vchHolderPubKey).GetID(), keyPre) ||
                !keyPre.Sign(NotePreAuthSigHash(nHouseID, dem.vUnits, dem.vchPayoutScript), dem.vchPreAuthSig)) {
            strFail = "Failed to sign the standing authorisation!"; return false;
        }
    }

    const CAmount nBurnedDust = (CAmount)spend.size() * NOTE_DUST_VALUE;
    const CAmount nTarget = NOTE_DUST_VALUE + nFee;
    const CAmount nRaise = nTarget > nBurnedDust ? nTarget - nBurnedDust : 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nRaise > 0 && !SelectCoins(vCoins, nRaise, setCoins, nAmountRet)) { strFail = "Could not fund the demand fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = (nBurnedDust + nAmountRet) - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    if (!keyHolder.Sign(NoteDemandSigHash(nHouseID, dem.vUnits, BillHashOutputs(mtx)), dem.vchHolderSig)) {
        strFail = "Failed to sign the demand!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << dem;
    mtx.vchNotePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    for (const WalletNoteCoin& nc : spend)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const WalletNoteCoin& nc : spend) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, NOTE_DUST_VALUE, SIGHASH_ALL), nc.script, sigdata)) {
            strFail = "Signing demanded note inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing demand fee inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the demand! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::ProtestNote(std::string& strFail, uint256& txidOut, uint32_t nHouseID, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // PROTEST takes the house slot - fail fast on a pending house-state op
    // (A8/C7c: ATMP would refuse anyway, but CommitTransaction does not
    // surface that, and the refused tx would pin its fee inputs).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    const int nNextHeight = chainActive.Height() + 1;
    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    {
        const char chEff = HouseEffectiveStatus(house, nNextHeight);
        if (chEff == HOUSE_STATUS_DEFERRED) {
            strFail = "House is deferred - the option clause already governs this grievance (its queue pays with interest)!";
            return false;
        }
        if (chEff != HOUSE_STATUS_OPEN && chEff != HOUSE_STATUS_STRESSED) {
            strFail = "House is insolvent or wound down - use the claim path!";
            return false;
        }
    }

    // The OLDEST lapsed, unprotested pre-auth demand this wallet holds against
    // the house. Groups are exact-tag, so a protest never mixes demands.
    const uint32_t W = Params().GetConsensus().nDemandWindow;
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nHouseID, mapByHolder);
    std::vector<WalletNoteCoin> spend;
    uint32_t nTag = 0;
    for (const auto& kv : mapByHolder) {
        const uint32_t tag = kv.first.second;
        if (!NoteDemandIsPreAuth(tag))
            continue;                                  // plain holding or plain demand
        if (tag & NOTE_DEMAND_PROTESTED_BIT)
            continue;                                  // already marked (idempotence)
        const uint32_t nDH = NoteDemandHeightOf(tag);
        if ((int64_t)nNextHeight < (int64_t)nDH + (int64_t)W)
            continue;                                  // window still running
        if (spend.empty() || nDH < NoteDemandHeightOf(nTag)) { spend = kv.second; nTag = tag; }
    }
    if (spend.empty()) { strFail = "No lapsed unprotested pre-auth demand to protest (the window must fully expire first)!"; return false; }

    CKey keyHolder;
    if (!GetKey(CPubKey(spend[0].vchHolderPubKey).GetID(), keyHolder)) { strFail = "Holder key missing!"; return false; }

    // Re-issue every coin custody-shaped to the same holder, marker added.
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_PROTEST;

    NoteProtest pro;
    pro.nHouseID = nHouseID;
    pro.vchHolderPubKey = spend[0].vchHolderPubKey;
    pro.nDemandTag = nTag | NOTE_DEMAND_PROTESTED_BIT;
    pro.nPrevProtestOpen = house.nProtestOpen;
    pro.nPrevProtestHeight = house.nProtestHeight;
    pro.nPrevProtestDemandHeight = house.nProtestDemandHeight;
    const CScript scriptCustody = NotePreAuthScript(spend[0].vchHolderPubKey);
    for (const WalletNoteCoin& nc : spend) {
        pro.vUnits.push_back(nc.units);
        mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, scriptCustody));
    }

    const CAmount nBurnedDust = (CAmount)spend.size() * NOTE_DUST_VALUE;
    const CAmount nTarget = (CAmount)spend.size() * NOTE_DUST_VALUE + nFee;
    const CAmount nRaise = nTarget > nBurnedDust ? nTarget - nBurnedDust : 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nRaise > 0 && !SelectCoins(vCoins, nRaise, setCoins, nAmountRet)) { strFail = "Could not fund the protest fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = (nBurnedDust + nAmountRet) - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    if (!keyHolder.Sign(NoteProtestSigHash(nHouseID, pro.vUnits, BillHashOutputs(mtx)), pro.vchHolderSig)) {
        strFail = "Failed to sign the protest!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << pro;
    mtx.vchNotePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // Custody inputs spend with an EMPTY scriptSig - the payload signature
    // against the embedded keyid is the authority. Only funding inputs sign.
    for (const WalletNoteCoin& nc : spend)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = (int)spend.size();
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing protest fee inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the protest! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::DischargeDemands(std::string& strFail, uint256& txidOut, uint32_t& nRemainingOut, uint32_t nHouseID, const CAmount& nFee)
{
    strFail = "Unknown error!";
    nRemainingOut = 0;
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A discharge is a REDEEM - it takes the house slot (A8/C7c fail-fast).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    const int nNextHeight = chainActive.Height() + 1;
    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    {
        const char chEff = HouseEffectiveStatus(house, nNextHeight);
        if (chEff == HOUSE_STATUS_DEFERRED) {
            strFail = "House is deferred - discharge resumes after recovery (the clause queue pays then)!";
            return false;
        }
        if (chEff != HOUSE_STATUS_OPEN && chEff != HOUSE_STATUS_STRESSED) {
            strFail = "House is insolvent or wound down - nothing can be discharged!";
            return false;
        }
    }

    // The demands live in the UTXO set, not in this wallet (the HOLDER's
    // wallet built them) - sweep the set for this house's custody coins. The
    // demand's standing authorisation (unit vector, payout script, pre-auth
    // sig) lives in the DEMAND tx's payload, and the coin tag names the
    // demand's connect height, so the tx is findable in that block with no
    // txindex. (A Delta-1b UPGRADED demand's tx lives at the upgrade height
    // instead - not yet reachable, the upgrade has no wallet builder.)
    FlushStateToDisk();
    struct CustodyCoin { COutPoint out; uint64_t units; uint32_t tag; CScript script; };
    std::vector<CustodyCoin> vCustody;
    {
        std::unique_ptr<CCoinsViewCursor> pcursor(pcoinsdbview->Cursor());
        while (pcursor && pcursor->Valid()) {
            COutPoint key;
            Coin coin;
            if (pcursor->GetKey(key) && pcursor->GetValue(coin) && !coin.IsSpent() &&
                    coin.fNote && coin.nHouseID == nHouseID &&
                    NoteDemandIsPreAuth(coin.nDemandHeight) &&
                    !mempool.isSpent(key)) {
                CustodyCoin cc;
                cc.out = key;
                cc.units = coin.nNoteUnits;
                cc.tag = coin.nDemandHeight;
                cc.script = coin.out.scriptPubKey;
                vCustody.push_back(cc);
            }
            if (pcursor) pcursor->Next();
        }
    }
    if (vCustody.empty()) { strFail = "No pre-auth demanded coins outstanding against this house!"; return false; }

    // Oldest-first over demand heights; per height, each DEMAND tx in that
    // block whose full unit vector is still collectable is dischargeable.
    std::set<uint32_t> setHeights;
    for (const CustodyCoin& cc : vCustody)
        setHeights.insert(NoteDemandHeightOf(cc.tag));

    NoteDemand demChosen;
    std::vector<CustodyCoin> vBurn;
    uint32_t nDemandHeight = 0;
    uint32_t nFound = 0;
    for (const uint32_t nDH : setHeights) {
        if ((int)nDH > chainActive.Height())
            continue;
        CBlock block;
        if (!ReadBlockFromDisk(block, chainActive[(int)nDH], Params().GetConsensus()))
            continue;
        for (const auto& ptx : block.vtx) {
            if (ptx->nVersion != TRANSACTION_NOTE_VERSION || ptx->nNoteOp != NOTE_OP_DEMAND)
                continue;
            NoteDemand dem;
            if (!DecodeNotePayload(ptx->vchNotePayload, dem) || dem.nHouseID != nHouseID || !dem.fPreAuth)
                continue;
            const CScript scriptCustody = NotePreAuthScript(dem.vchHolderPubKey);
            uint64_t nNeeded = 0;
            for (const uint64_t u : dem.vUnits) nNeeded += u;
            uint64_t nTotal = 0;
            std::vector<CustodyCoin> vGroup;
            for (const CustodyCoin& cc : vCustody) {
                if (NoteDemandHeightOf(cc.tag) == nDH && cc.script == scriptCustody) {
                    vGroup.push_back(cc);
                    nTotal += cc.units;
                }
            }
            // All-or-nothing per demand (the digest binds the full vector).
            // A mismatch means a partial voluntary redeem, a claim, or two
            // same-height demands by one holder (ambiguous) - skip; the
            // holder's own paths handle those coins.
            if (nTotal != nNeeded || vGroup.empty())
                continue;
            nFound++;
            if (nFound == 1) { demChosen = dem; vBurn = vGroup; nDemandHeight = nDH; }
        }
    }
    if (nFound == 0) { strFail = "No fully-collectable pre-auth demand to discharge (partial redeems or ambiguity)!"; return false; }
    nRemainingOut = nFound - 1;

    uint64_t U = 0;
    for (const CustodyCoin& cc : vBurn) U += cc.units;

    // The consensus floor, mirrored from RedeemNote: D-iii accrual from window
    // LAPSE (discharge in time pays par exactly), the DR-2 episode cap, and
    // the confirmation margin (the floor only grows with height; overpaying
    // is safe, a shortfall is permanently unconfirmable).
    static const uint32_t NOTE_REDEEM_INTEREST_MARGIN_BLOCKS = 6;
    uint32_t nEndHeight = (uint32_t)nNextHeight + NOTE_REDEEM_INTEREST_MARGIN_BLOCKS;
    if (house.nDeferEndedHeight >= nDemandHeight && house.nDeferEndedHeight < nEndHeight)
        nEndHeight = house.nDeferEndedHeight;
    const uint32_t nAccrualStart = nDemandHeight + Params().GetConsensus().nDemandWindow;
    const uint32_t nBlocks = nEndHeight > nAccrualStart ? nEndHeight - nAccrualStart : 0;
    const CAmount amountInterest = NoteDeferralInterest(U, nBlocks);

    // Brassage incidence (Delta-2): the RUNNER bears the spread - it comes out
    // of the payout, and the house's out-of-pocket stays U + interest.
    const uint32_t nBps = HouseBrassageBps(house);
    const CAmount amountSpread = HouseBrassageAmount(U, nBps);
    const CAmount amountPayout = (CAmount)U + amountInterest - amountSpread;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vout.push_back(CTxOut(amountPayout,
        CScript(demChosen.vchPayoutScript.begin(), demChosen.vchPayoutScript.end())));
    if (amountSpread > 0)
        mtx.vout.push_back(CTxOut(amountSpread, HouseEscrowScript(house.houseID)));

    const CAmount nBurnedDust = (CAmount)vBurn.size() * NOTE_DUST_VALUE;
    const CAmount nTarget = amountPayout + amountSpread + nFee;
    const CAmount nRaise = nTarget > nBurnedDust ? nTarget - nBurnedDust : 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nRaise > 0 && !SelectCoins(vCoins, nRaise, setCoins, nAmountRet)) { strFail = "House could not fund the discharge payout + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = (nBurnedDust + nAmountRet) - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    // The standing authorisation, re-supplied verbatim; the holder's fresh
    // signature is exactly what a discharge does not need.
    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = amountSpread > 0 ? 1 : 0;
    redeem.vchHolderPubKey = demChosen.vchHolderPubKey;
    redeem.fPreAuthDischarge = 1;
    redeem.vPreAuthUnits = demChosen.vUnits;
    redeem.vchPayoutScript = demChosen.vchPayoutScript;
    redeem.vchPreAuthSig = demChosen.vchPreAuthSig;
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // Custody inputs: empty scriptSig. Funding inputs: signed.
    for (const CustodyCoin& cc : vBurn)
        mtx.vin.push_back(CTxIn(cc.out, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = (int)vBurn.size();
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing discharge funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the discharge! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::RedeemNote(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nUnits, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }
    if (nUnits == 0) { strFail = "Invalid note units!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // Fail-fast mirror of the 3.4 consensus gate: redemption is open through
    // Stressed, blocked at effective Insolvent (the waterfall replaces it).
    {
        CHouse house;
        if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
        const char chEff = HouseEffectiveStatus(house, chainActive.Height() + 1);
        if (chEff == HOUSE_STATUS_DEFERRED) {
            strFail = "House has invoked the option clause - par redemption is suspended for the "
                      "deferral window (holders queue and accrue interest from the date of demand).";
            return false;
        }
        if (chEff != HOUSE_STATUS_OPEN && chEff != HOUSE_STATUS_STRESSED) {
            strFail = "House is insolvent or wound down - use the claim path, not redemption!";
            return false;
        }
    }

    // A redeem burns a SINGLE holder's coins summing EXACTLY to nUnits (v1: to
    // keep U = burned units clean, require the holder to hold coins that sum to
    // nUnits; change is a prior transfer's job).
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nHouseID, mapByHolder);
    std::vector<WalletNoteCoin> spend;
    uint64_t U = 0;
    for (const auto& kv : mapByHolder) {
        uint64_t sum = 0;
        for (const WalletNoteCoin& nc : kv.second) sum += nc.units;
        if (sum == nUnits) { spend = kv.second; U = sum; break; }
    }
    if (spend.empty()) { strFail = "No holder's note coins sum exactly to the redeem amount (transfer to consolidate first)!"; return false; }

    CKey keyHolder;
    if (!GetKey(CPubKey(spend[0].vchHolderPubKey).GetID(), keyHolder)) { strFail = "Holder key missing!"; return false; }

    // Payout: principal + any DEFERRAL INTEREST accrued since the holder's
    // demand (3.5 - consensus enforces this as a FLOOR, so the wallet must pay
    // at least it). Funded by the wallet (the house's reserves in
    // single-wallet v1) + the burned notes' dust rolls in.
    // B3: the coin field is a TAG (height + marker bits) - read it masked, or
    // a pre-auth coin's bit 31 turns the height into ~2^31 and the interest
    // mirror silently computes zero (the consensus-side bug this mirrors was
    // found by recon before it ever ran; same class as the -no prefix).
    const uint32_t nDemandTag = spend[0].nDemandHeight;
    const uint32_t nDemandHeight = NoteDemandHeightOf(nDemandTag);
    CHouse houseB;
    if (!phousetree->GetHouse(nHouseID, houseB)) { strFail = "Unknown house!"; return false; }
    CAmount amountInterest = 0;
    if (nDemandHeight != 0) {
        const int nNextHeight = chainActive.Height() + 1;
        // Consensus enforces a FLOOR of interest to the height the tx ACTUALLY
        // connects (validation.cpp), and the floor only grows with height. We fix
        // the payout at build time, so if the tx dwells in the mempool past the
        // height we priced, the floor overtakes it and the tx becomes PERMANENTLY
        // unconfirmable (every later height makes the shortfall worse). Overpaying
        // is safe - consensus checks only the floor - so carry a generous
        // confirmation margin: NOTE_REDEEM_INTEREST_MARGIN_BLOCKS of slack costs
        // the house a few sats but guarantees the redemption can confirm through a
        // realistic mempool backlog. See finding R-i6/[11].
        //
        // DR-2 mirror: consensus caps the window at the deferral-episode END
        // (the recovery height). Once capped the floor is FIXED - it no longer
        // grows with height - so the margin drops out and the payout matches the
        // consensus amount exactly.
        static const uint32_t NOTE_REDEEM_INTEREST_MARGIN_BLOCKS = 6;
        uint32_t nEndHeight = (uint32_t)nNextHeight + NOTE_REDEEM_INTEREST_MARGIN_BLOCKS;
        if (houseB.nDeferEndedHeight >= nDemandHeight && houseB.nDeferEndedHeight < nEndHeight)
            nEndHeight = houseB.nDeferEndedHeight;   // >= : same-block D==E caps at zero (consensus mirror)
        // D-iii mirror: a PRE-AUTH demand's clock starts at window lapse, not
        // at demand (consensus branches identically on the tag's bit 31).
        uint32_t nAccrualStart = nDemandHeight;
        if (NoteDemandIsPreAuth(nDemandTag))
            nAccrualStart += Params().GetConsensus().nDemandWindow;
        const uint32_t nBlocks = nEndHeight > nAccrualStart ? nEndHeight - nAccrualStart : 0;
        amountInterest = NoteDeferralInterest(U, nBlocks);
    }
    const CAmount amountPayout = (CAmount)U + amountInterest;

    // Dynamic brassage (3.5): a redemption while the house is below the floor
    // pays a spread into the escrow pot. DR-2: demanded notes are NOT exempt
    // (mirror of consensus - the old permanent-tag exemption is retired; a
    // post-recovery queue pays no spread anyway since recovery re-attests at
    // floor+buffer).
    const uint32_t nBps = HouseBrassageBps(houseB);
    const CAmount amountSpread = HouseBrassageAmount(U, nBps);

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_REDEEM;
    mtx.vout.push_back(CTxOut(amountPayout, NoteScriptForPubKey(spend[0].vchHolderPubKey)));
    if (amountSpread > 0)
        mtx.vout.push_back(CTxOut(amountSpread, HouseEscrowScript(houseB.houseID)));

    const CAmount nBurnedDust = (CAmount)spend.size() * NOTE_DUST_VALUE;
    const CAmount nTarget = amountPayout + amountSpread + nFee;   // payout + spread + fee to raise
    const CAmount nRaise = nTarget > nBurnedDust ? nTarget - nBurnedDust : 0; // burned dust helps fund
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nRaise > 0 && !SelectCoins(vCoins, nRaise, setCoins, nAmountRet)) { strFail = "House could not fund the redemption payout + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = (nBurnedDust + nAmountRet) - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    NoteRedeem redeem;
    redeem.nHouseID = nHouseID;
    redeem.fBrassage = amountSpread > 0 ? 1 : 0;
    redeem.vchHolderPubKey = spend[0].vchHolderPubKey;
    if (!keyHolder.Sign(NoteRedeemSigHash(nHouseID, U, BillHashOutputs(mtx)), redeem.vchHolderSig)) {
        strFail = "Failed to sign note redeem!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << redeem;
    mtx.vchNotePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    for (const WalletNoteCoin& nc : spend)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const WalletNoteCoin& nc : spend) {
        // A custody coin (pre-auth demanded, B3) has no scriptSig to produce:
        // the script is <keyid> OP_DROP OP_TRUE and the holder's authority is
        // the payload signature consensus verifies against that keyid.
        if (IsNotePreAuthScript(nc.script)) { nIn++; continue; }
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, NOTE_DUST_VALUE, SIGHASH_ALL), nc.script, sigdata)) {
            strFail = "Signing redeemed note inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing redeem funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit note redeem! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::ClaimNote(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nUnits, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }
    if (nUnits == 0) { strFail = "Invalid note units!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, chainActive.Height() + 1) != HOUSE_STATUS_INSOLVENT) {
        strFail = "House is not insolvent - use redeemnote while the window is open!";
        return false;
    }

    // Exact-sum single-holder burn, like REDEEM (transfer to consolidate first)
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nHouseID, mapByHolder);
    std::vector<WalletNoteCoin> spend;
    uint64_t U = 0;
    for (const auto& kv : mapByHolder) {
        uint64_t sum = 0;
        for (const WalletNoteCoin& nc : kv.second) sum += nc.units;
        if (sum == nUnits) { spend = kv.second; U = sum; break; }
    }
    if (spend.empty()) { strFail = "No holder's note coins sum exactly to the claim amount (transfer to consolidate first)!"; return false; }

    CKey keyHolder;
    if (!GetKey(CPubKey(spend[0].vchHolderPubKey).GetID(), keyHolder)) { strFail = "Holder key missing!"; return false; }

    // The pro-rata denominator: the stored snapshot if insolvency has been
    // materialized, else exactly what the first claim WILL materialize (live
    // escrow coins / current outstanding units).
    LOCK(mempool.cs);
    CCoinsViewMemPool viewMempool(pcoinsTip.get(), mempool);
    uint64_t nSnapshotUnits = house.nInsolventUnits;
    CAmount amountPot = house.amountInsolventPot;
    // All potential escrow outpoints - MUST mirror consensus HouseEscrowOutpoints
    // exactly: partner pledges + waterfall change + the DEFER till (R-i5 'till in
    // the pot'). Omitting the till understated the pot on both the pricing side
    // (silent under-recovery when this claim materializes insolvency) and the
    // spend side (a suspended-then-insolvent house whose till is a material
    // fraction of the pot would fail 'pot no longer covers the entitlement').
    std::vector<COutPoint> vEscrowOutpoints;
    for (const HousePartner& p : house.vPartner)
        vEscrowOutpoints.insert(vEscrowOutpoints.end(), p.vOutPledge.begin(), p.vOutPledge.end());
    vEscrowOutpoints.insert(vEscrowOutpoints.end(), house.vOutEscrowChange.begin(), house.vOutEscrowChange.end());
    vEscrowOutpoints.insert(vEscrowOutpoints.end(), house.vOutReserveLock.begin(), house.vOutReserveLock.end());

    if (house.status != HOUSE_STATUS_INSOLVENT) {
        nSnapshotUnits = house.nMintedUnits;
        amountPot = 0;
        for (const COutPoint& out : vEscrowOutpoints) {
            Coin coin;
            if (viewMempool.GetCoin(out, coin) && !coin.IsSpent() && coin.fHouseEscrow)
                amountPot += coin.out.nValue;
        }
    }
    const CAmount amountEntitlement = NoteClaimEntitlement(U, amountPot, nSnapshotUnits);
    if (amountEntitlement <= 0) { strFail = "Zero entitlement - the escrow pot is empty!"; return false; }

    // Select escrow coins (largest first) until the entitlement is covered
    std::vector<std::pair<COutPoint, CAmount>> vEscrowAll;
    for (const COutPoint& out : vEscrowOutpoints) {
        Coin coin;
        if (viewMempool.GetCoin(out, coin) && !coin.IsSpent() && coin.fHouseEscrow)
            vEscrowAll.push_back(std::make_pair(out, coin.out.nValue));
    }
    std::sort(vEscrowAll.begin(), vEscrowAll.end(),
        [](const std::pair<COutPoint, CAmount>& a, const std::pair<COutPoint, CAmount>& b) { return a.second > b.second; });
    std::vector<COutPoint> vEscrowSpend;
    CAmount amountEscrowIn = 0;
    for (const auto& e : vEscrowAll) {
        if (amountEscrowIn >= amountEntitlement)
            break;
        vEscrowSpend.push_back(e.first);
        amountEscrowIn += e.second;
    }
    if (amountEscrowIn < amountEntitlement) { strFail = "Escrow pot no longer covers the entitlement!"; return false; }
    const CAmount amountEscrowChange = amountEscrowIn - amountEntitlement;

    // Outputs: payout at vout[0]; escrow change (if any) at vout[1] with the
    // canonical script; plain change last. Finalized before the holder signs.
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_CLAIM;
    mtx.vout.push_back(CTxOut(amountEntitlement, NoteScriptForPubKey(spend[0].vchHolderPubKey)));
    if (amountEscrowChange > 0)
        mtx.vout.push_back(CTxOut(amountEscrowChange, HouseEscrowScript(house.houseID)));

    // Fee: burned note dust first, plain coins for the rest
    const CAmount nBurnedDust = (CAmount)spend.size() * NOTE_DUST_VALUE;
    const CAmount nRaise = nFee > nBurnedDust ? nFee - nBurnedDust : 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nRaise > 0 && !SelectCoins(vCoins, nRaise, setCoins, nAmountRet)) { strFail = "Could not fund the claim fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = (nBurnedDust + nAmountRet) - nFee;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    NoteClaim claim;
    claim.nHouseID = nHouseID;
    claim.fEscrowChange = amountEscrowChange > 0 ? 1 : 0;
    claim.vchHolderPubKey = spend[0].vchHolderPubKey;
    if (!keyHolder.Sign(NoteClaimSigHash(nHouseID, U, BillHashOutputs(mtx)), claim.vchHolderSig)) {
        strFail = "Failed to sign note claim!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << claim;
    mtx.vchNotePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // vin: note coins (holder-signed), escrow coins (empty scriptSig - the
    // consensus guard + payload signature authorize), then fee coins
    for (const WalletNoteCoin& nc : spend)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const COutPoint& out : vEscrowSpend)
        mtx.vin.push_back(CTxIn(out, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const WalletNoteCoin& nc : spend) {
        // Custody coins (B3): a protested demand that expired into the
        // waterfall is claimed like any note coin, but its scriptSig stays
        // empty - the payload signature is the authority.
        if (IsNotePreAuthScript(nc.script)) { nIn++; continue; }
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, NOTE_DUST_VALUE, SIGHASH_ALL), nc.script, sigdata)) {
            strFail = "Signing claimed note inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    nIn += vEscrowSpend.size();
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing claim fee inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit note claim! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

// One of this wallet's spendable term-deposit receipt coins of a house. The
// immutable terms live on the COIN TAG (read from the UTXO set), never the
// script - a transfer/withdraw/claim spends ONE whole receipt (atomic).
struct WalletDepositCoin {
    COutPoint outpoint;
    uint64_t principal;
    uint32_t rateBps;
    uint32_t maturityHeight;
    uint32_t originationHeight;
    std::vector<unsigned char> vchHolderPubKey;
    CScript script;
};

// Collect this wallet's unspent deposit receipt coins of nHouseID. Reads the
// terms from the live UTXO set (a wallet tx alone cannot tell us the origination
// height a coin confirmed at). Same depth/abandoned/evicted guard as the note
// collector: an offered coin that is not really in the UTXO set produces a
// missing-inputs tx that ATMP silently drops (CommitTransaction does not surface
// it), handing the caller a txid that can never confirm.
static void CollectWalletDepositCoins(CWallet* pwallet, uint32_t nHouseID,
                                      std::vector<WalletDepositCoin>& vOut)
{
    for (const auto& entry : pwallet->mapWallet) {
        const uint256& wtxid = entry.first;
        const CWalletTx* pcoin = &entry.second;
        if (pcoin->tx->nVersion != TRANSACTION_DEPOSIT_VERSION)
            continue;
        const int nDepth = pcoin->GetDepthInMainChain();
        if (nDepth < 0)
            continue;
        if (pcoin->isAbandoned())
            continue;
        if (nDepth == 0 && !pcoin->InMempool())
            continue;

        for (size_t i = 0; i < pcoin->tx->vout.size(); i++) {
            if (pwallet->IsSpent(wtxid, i))
                continue;
            if (pwallet->IsMine(pcoin->tx->vout[i]) == ISMINE_NO)
                continue;
            Coin coinUtxo;
            if (!pcoinsTip->GetCoin(COutPoint(wtxid, i), coinUtxo) || coinUtxo.IsSpent())
                continue;
            if (!coinUtxo.fDeposit || coinUtxo.nHouseID != nHouseID)
                continue;
            CTxDestination dest;
            if (!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, dest))
                continue;
            const CKeyID* keyid = boost::get<CKeyID>(&dest);
            if (!keyid)
                continue;
            CPubKey pub;
            if (!pwallet->GetPubKey(*keyid, pub))
                continue;

            WalletDepositCoin dc;
            dc.outpoint = COutPoint(wtxid, i);
            dc.principal = coinUtxo.nDepositPrincipal;
            dc.rateBps = coinUtxo.nDepositRateBps;
            dc.maturityHeight = coinUtxo.nDepositMaturityHeight;
            dc.originationHeight = coinUtxo.nDepositOriginationHeight;
            dc.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
            dc.script = pcoin->tx->vout[i].scriptPubKey;
            vOut.push_back(dc);
        }
    }
}

bool CWallet::OriginateDeposit(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nPrincipal, uint32_t nRateBps, uint32_t nMaturityHeight, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }
    if (nPrincipal == 0 || nPrincipal > (uint64_t)MAX_MONEY) { strFail = "Invalid deposit principal!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    const int nNextHeight = chainActive.Height() + 1;
    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, nNextHeight) != HOUSE_STATUS_OPEN) { strFail = "House is not effectively open - cannot take on new term liabilities!"; return false; }
    if (nMaturityHeight <= (uint32_t)nNextHeight) { strFail = "Maturity must be in the future!"; return false; }
    if (nMaturityHeight - (uint32_t)nNextHeight > MAX_DEPOSIT_TERM_BLOCKS) { strFail = "Deposit term is too long!"; return false; }

    // Fail-fast CM-2 capital cap (consensus enforces this too, but
    // CommitTransaction does not surface an ATMP rejection to the caller). Reads
    // LIVE N and D - notes and deposits share the one leverage ceiling. NO rho /
    // reserve proof: deposits are outside the liquidity machinery.
    if (house.nDepositUnits > (uint64_t)MAX_MONEY - nPrincipal ||
            house.nMintedUnits > (uint64_t)MAX_MONEY - (house.nDepositUnits + nPrincipal) ||
            house.nMintedUnits + house.nDepositUnits + nPrincipal > HouseCapitalCapUnits(house)) {
        strFail = "Origination would exceed the capital cap (N + D + principal <= lambda * active escrow)!";
        return false;
    }

    // Fresh holder key for the saver (Tx-9 hygiene).
    CPubKey pubHolder;
    if (!GetKeyFromPool(pubHolder)) { strFail = "Keypool ran out, please call keypoolrefill first!"; return false; }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_DEPOSIT_VERSION;
    mtx.nDepositOp = DEPOSIT_OP_ORIGINATE;
    // vout[0] = the receipt (dust base, terms on the coin tag) to the saver.
    mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(std::vector<unsigned char>(pubHolder.begin(), pubHolder.end()))));

    // Fund the receipt dust + fee from fungible plain inputs, added BEFORE the
    // M-of-N approver signature (the ORIGINATE sighash binds hashPrevouts, so a
    // confirmed origination's approver sigs are not replayable with fresh
    // funding - the notes-MINT lesson).
    const CAmount nTarget = DEPOSIT_DUST_VALUE + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the receipt dust + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    DepositOriginate org;
    org.nHouseID = nHouseID;
    org.vPrincipal.push_back(nPrincipal);
    org.vRateBps.push_back(nRateBps);
    org.vMaturityHeight.push_back(nMaturityHeight);
    if (!SignHouseApprovers(this, house,
            DepositOriginateSigHash(nHouseID, org.vPrincipal, org.vRateBps, org.vMaturityHeight,
                DepositHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx)),
            org.vApproverIndex, org.vApproverSig, strFail))
        return false;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << org;
    mtx.vchDepositPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing deposit originate inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit deposit originate! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

// Pick this wallet's first held receipt of (house, principal). fMaturedOnly
// filters to receipts at/after maturity (WITHDRAW). Returns false if none.
static bool SelectDepositReceipt(CWallet* pwallet, uint32_t nHouseID, uint64_t nPrincipal,
                                 bool fMaturedOnly, int nHeight, WalletDepositCoin& out)
{
    std::vector<WalletDepositCoin> vDep;
    CollectWalletDepositCoins(pwallet, nHouseID, vDep);
    for (const WalletDepositCoin& dc : vDep) {
        if (dc.principal != nPrincipal)
            continue;
        if (fMaturedOnly && (nHeight < 0 || (uint32_t)nHeight < dc.maturityHeight))
            continue;
        out = dc;
        return true;
    }
    return false;
}

bool CWallet::TransferDeposit(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nPrincipal, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    WalletDepositCoin dc;
    if (!SelectDepositReceipt(this, nHouseID, nPrincipal, false, chainActive.Height() + 1, dc)) {
        strFail = "No receipt of that house and principal is held by this wallet!"; return false;
    }
    CKey keySender;
    if (!GetKey(CPubKey(dc.vchHolderPubKey).GetID(), keySender)) { strFail = "Sender key missing!"; return false; }

    CPubKey pubRecipient;
    if (!GetKeyFromPool(pubRecipient)) { strFail = "Keypool ran out!"; return false; }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_DEPOSIT_VERSION;
    mtx.nDepositOp = DEPOSIT_OP_TRANSFER;
    // vout[0] = the whole receipt to the recipient, re-tagged identically by
    // AddCoins from the payload (which must equal the spent coin tag byte-exact).
    mtx.vout.push_back(CTxOut(DEPOSIT_DUST_VALUE, DepositScriptForPubKey(std::vector<unsigned char>(pubRecipient.begin(), pubRecipient.end()))));

    // Fund the new receipt dust (the burned receipt's dust becomes fee) + fee.
    const CAmount nTarget = DEPOSIT_DUST_VALUE + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the transfer dust + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    DepositTransfer xfer;
    xfer.nHouseID = nHouseID;
    xfer.nPrincipal = dc.principal;
    xfer.nRateBps = dc.rateBps;
    xfer.nMaturityHeight = dc.maturityHeight;
    xfer.nOriginationHeight = dc.originationHeight;
    xfer.vchSenderPubKey = dc.vchHolderPubKey;
    if (!keySender.Sign(DepositTransferSigHash(nHouseID, xfer.nPrincipal, xfer.nRateBps, xfer.nMaturityHeight,
                xfer.nOriginationHeight, BillHashOutputs(mtx)), xfer.vchSenderSig)) {
        strFail = "Failed to sign deposit transfer!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << xfer;
    mtx.vchDepositPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // Inputs: the burned receipt (holder-signed) + the funding coins.
    mtx.vin.push_back(CTxIn(dc.outpoint.hash, dc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    SignatureData sigReceipt;
    if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, 0, DEPOSIT_DUST_VALUE, SIGHASH_ALL), dc.script, sigReceipt)) {
        strFail = "Signing the transferred receipt failed!"; return false;
    }
    UpdateTransaction(mtx, 0, sigReceipt);
    int nIn = 1;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing transfer funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit deposit transfer! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::WithdrawDeposit(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nPrincipal, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    const int nNextHeight = chainActive.Height() + 1;
    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, nNextHeight) != HOUSE_STATUS_OPEN) {
        strFail = "House is not effectively open - a matured deposit queues behind notes until recovery (or claim at insolvency)!"; return false;
    }

    WalletDepositCoin dc;
    if (!SelectDepositReceipt(this, nHouseID, nPrincipal, true, nNextHeight, dc)) {
        strFail = "No matured receipt of that house and principal is held by this wallet (early withdrawal is not possible - sell the receipt instead)!"; return false;
    }
    CKey keyHolder;
    if (!GetKey(CPubKey(dc.vchHolderPubKey).GetID(), keyHolder)) { strFail = "Holder key missing!"; return false; }

    // Consensus FLOOR: principal + accrued at the receipt's own rate on one
    // continuous clock from origination to the CONNECT height. That floor GROWS
    // every block, but the tx may confirm several blocks after we build it (BMM
    // timing) - so we pay the floor at a height MARGIN blocks in the future, and a
    // delayed confirmation still clears it. Overpay is safe (the guard is only a
    // minimum, funded by the house) - the R-i6 RedeemNote lesson, applied to the
    // per-block-growing deposit interest.
    static const uint32_t WITHDRAW_CONFIRM_MARGIN = 12;
    const uint32_t nPayHeight = (uint32_t)nNextHeight + WITHDRAW_CONFIRM_MARGIN;
    const uint32_t nBlocks = nPayHeight > dc.originationHeight ? nPayHeight - dc.originationHeight : 0;
    const CAmount amountInterest = DepositMaturityInterest(dc.principal, nBlocks, dc.rateBps);
    const CAmount amountDue = (CAmount)dc.principal + amountInterest;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_DEPOSIT_VERSION;
    mtx.nDepositOp = DEPOSIT_OP_WITHDRAW;
    // vout[0] = principal + accrued to the holder, funded by the house (its own
    // base coins in single-wallet v1). Built before the holder signs.
    mtx.vout.push_back(CTxOut(amountDue, DepositScriptForPubKey(dc.vchHolderPubKey)));

    // Fund the payout + fee; the burned receipt's dust rolls in.
    const CAmount nTarget = amountDue + nFee;
    const CAmount nRaise = nTarget > DEPOSIT_DUST_VALUE ? nTarget - DEPOSIT_DUST_VALUE : 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nRaise > 0 && !SelectCoins(vCoins, nRaise, setCoins, nAmountRet)) { strFail = "Could not fund the maturity payout + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = (DEPOSIT_DUST_VALUE + nAmountRet) - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    DepositWithdraw wd;
    wd.nHouseID = nHouseID;
    wd.vchHolderPubKey = dc.vchHolderPubKey;
    if (!keyHolder.Sign(DepositWithdrawSigHash(nHouseID, dc.principal, dc.maturityHeight, dc.originationHeight, BillHashOutputs(mtx)), wd.vchHolderSig)) {
        strFail = "Failed to sign the withdrawal!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << wd;
    mtx.vchDepositPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    mtx.vin.push_back(CTxIn(dc.outpoint.hash, dc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    SignatureData sigReceipt;
    if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, 0, DEPOSIT_DUST_VALUE, SIGHASH_ALL), dc.script, sigReceipt)) {
        strFail = "Signing the withdrawn receipt failed!"; return false;
    }
    UpdateTransaction(mtx, 0, sigReceipt);
    int nIn = 1;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing withdrawal funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the withdrawal! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::ClaimDeposit(std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nPrincipal, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    const int nNextHeight = chainActive.Height() + 1;
    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, nNextHeight) != HOUSE_STATUS_INSOLVENT) {
        strFail = "House is not insolvent - use withdrawdeposit at maturity while it is open!"; return false;
    }

    WalletDepositCoin dc;
    if (!SelectDepositReceipt(this, nHouseID, nPrincipal, false, nNextHeight, dc)) {
        strFail = "No receipt of that house and principal is held by this wallet!"; return false;
    }
    CKey keyHolder;
    if (!GetKey(CPubKey(dc.vchHolderPubKey).GetID(), keyHolder)) { strFail = "Holder key missing!"; return false; }

    // The subordinated tranche: what the pot holds AFTER notes take their par
    // (the frozen note snapshot). Denominator = the deposit snapshot. Mirror the
    // note-CLAIM: use the stored snapshot if insolvency is materialized, else
    // exactly what this claim WILL materialize (live escrow / current D). The
    // escrow outpoint set MUST mirror consensus HouseEscrowOutpoints.
    LOCK(mempool.cs);
    CCoinsViewMemPool viewMempool(pcoinsTip.get(), mempool);
    std::vector<COutPoint> vEscrowOutpoints;
    for (const HousePartner& p : house.vPartner)
        vEscrowOutpoints.insert(vEscrowOutpoints.end(), p.vOutPledge.begin(), p.vOutPledge.end());
    vEscrowOutpoints.insert(vEscrowOutpoints.end(), house.vOutEscrowChange.begin(), house.vOutEscrowChange.end());
    vEscrowOutpoints.insert(vEscrowOutpoints.end(), house.vOutReserveLock.begin(), house.vOutReserveLock.end());

    uint64_t nNoteSnapshot = house.nInsolventUnits;
    uint64_t nDepositSnapshot = house.nInsolventDepositPrincipal;
    CAmount amountPot = house.amountInsolventPot;
    if (house.status != HOUSE_STATUS_INSOLVENT) {
        nNoteSnapshot = house.nMintedUnits;
        nDepositSnapshot = house.nDepositUnits;
        amountPot = 0;
        for (const COutPoint& out : vEscrowOutpoints) {
            Coin coin;
            if (viewMempool.GetCoin(out, coin) && !coin.IsSpent() && coin.fHouseEscrow)
                amountPot += coin.out.nValue;
        }
    }
    // Deposits are JUNIOR: the tranche is what remains after notes take par.
    const CAmount amountDepositPot = amountPot > (CAmount)nNoteSnapshot ? amountPot - (CAmount)nNoteSnapshot : 0;
    const CAmount amountEntitlement = DepositClaimEntitlement(dc.principal, amountDepositPot, nDepositSnapshot);
    if (amountEntitlement <= 0) { strFail = "Zero entitlement - the subordinated deposit tranche is empty (notes exhaust the pot)!"; return false; }

    // Select escrow coins (largest first) until the entitlement is covered.
    std::vector<std::pair<COutPoint, CAmount>> vEscrowAll;
    for (const COutPoint& out : vEscrowOutpoints) {
        Coin coin;
        if (viewMempool.GetCoin(out, coin) && !coin.IsSpent() && coin.fHouseEscrow)
            vEscrowAll.push_back(std::make_pair(out, coin.out.nValue));
    }
    std::sort(vEscrowAll.begin(), vEscrowAll.end(),
        [](const std::pair<COutPoint, CAmount>& a, const std::pair<COutPoint, CAmount>& b) { return a.second > b.second; });
    std::vector<COutPoint> vEscrowSpend;
    CAmount amountEscrowIn = 0;
    for (const auto& e : vEscrowAll) {
        if (amountEscrowIn >= amountEntitlement)
            break;
        vEscrowSpend.push_back(e.first);
        amountEscrowIn += e.second;
    }
    if (amountEscrowIn < amountEntitlement) { strFail = "Escrow pot no longer covers the entitlement!"; return false; }
    const CAmount amountEscrowChange = amountEscrowIn - amountEntitlement;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_DEPOSIT_VERSION;
    mtx.nDepositOp = DEPOSIT_OP_CLAIM;
    mtx.vout.push_back(CTxOut(amountEntitlement, DepositScriptForPubKey(dc.vchHolderPubKey)));
    if (amountEscrowChange > 0)
        mtx.vout.push_back(CTxOut(amountEscrowChange, HouseEscrowScript(house.houseID)));

    // Fee: the burned receipt's dust first, plain coins for the rest.
    const CAmount nRaise = nFee > DEPOSIT_DUST_VALUE ? nFee - DEPOSIT_DUST_VALUE : 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nRaise > 0 && !SelectCoins(vCoins, nRaise, setCoins, nAmountRet)) { strFail = "Could not fund the claim fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = (DEPOSIT_DUST_VALUE + nAmountRet) - nFee;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    DepositClaim clm;
    clm.nHouseID = nHouseID;
    clm.fEscrowChange = amountEscrowChange > 0 ? 1 : 0;
    clm.vchHolderPubKey = dc.vchHolderPubKey;
    if (!keyHolder.Sign(DepositClaimSigHash(nHouseID, dc.principal, BillHashOutputs(mtx)), clm.vchHolderSig)) {
        strFail = "Failed to sign the deposit claim!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << clm;
    mtx.vchDepositPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // vin: the burned receipt (holder-signed), the escrow coins (empty scriptSig
    // - the consensus guard + payload sig authorize), then the fee coins.
    mtx.vin.push_back(CTxIn(dc.outpoint.hash, dc.outpoint.n, CScript()));
    for (const COutPoint& out : vEscrowSpend)
        mtx.vin.push_back(CTxIn(out, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    SignatureData sigReceipt;
    if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, 0, DEPOSIT_DUST_VALUE, SIGHASH_ALL), dc.script, sigReceipt)) {
        strFail = "Signing the claimed receipt failed!"; return false;
    }
    UpdateTransaction(mtx, 0, sigReceipt);
    int nIn = 1 + (int)vEscrowSpend.size();
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing claim fee inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the deposit claim! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

//
// AMM pools (Phase 3.7)
//

struct WalletLpCoin {
    COutPoint outpoint;
    uint64_t units;
    std::vector<unsigned char> vchHolderPubKey;
    CScript script;
};

/** This wallet's live LP-share coins for pool nPoolID, grouped by holder key
 * (a REMOVE_LIQ burns coins of ONE declared provider). Tag decisions come
 * from the SAME payload-pure tagger consensus uses, so this cannot drift. */
static void CollectWalletLpCoins(CWallet* pwallet, uint32_t nPoolID,
                                 std::map<CKeyID, std::vector<WalletLpCoin>>& mapByHolder)
{
    for (const auto& entry : pwallet->mapWallet) {
        const uint256& wtxid = entry.first;
        const CWalletTx* pcoin = &entry.second;
        if (pcoin->tx->nVersion != TRANSACTION_POOL_VERSION)
            continue;
        // Same liveness filters as notes/deposits: conflicted, abandoned and
        // mempool-evicted txs must not offer coins (CommitTransaction hides
        // the resulting missing-inputs rejection).
        const int nDepth = pcoin->GetDepthInMainChain();
        if (nDepth < 0)
            continue;
        if (pcoin->isAbandoned())
            continue;
        if (nDepth == 0 && !pcoin->InMempool())
            continue;

        for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
            Coin probe;
            ApplyPoolCoinTags(*pcoin->tx, i, probe);
            if (!probe.fLpShare || probe.nHouseID != nPoolID)
                continue;
            if (pwallet->IsSpent(wtxid, i))
                continue;
            if (pwallet->IsMine(pcoin->tx->vout[i]) == ISMINE_NO)
                continue;
            CTxDestination dest;
            if (!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, dest))
                continue;
            const CKeyID* keyid = boost::get<CKeyID>(&dest);
            if (!keyid)
                continue;
            CPubKey pub;
            if (!pwallet->GetPubKey(*keyid, pub))
                continue;

            WalletLpCoin lc;
            lc.outpoint = COutPoint(wtxid, i);
            lc.units = probe.nLpUnits;
            lc.vchHolderPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
            lc.script = pcoin->tx->vout[i].scriptPubKey;
            mapByHolder[*keyid].push_back(lc);
        }
    }
}

void CWallet::CollectLpHoldings(std::map<uint32_t, WalletLpHolding>& out)
{
    // Caller holds cs_main + cs_wallet and has synced (CollectWalletLpCoins'
    // contract). Reuses the exact same per-pool collector the pool builders use,
    // so the hold view can never drift from what REMOVE_LIQ will burn.
    out.clear();
    if (!ppooltree) return;
    for (const CPool& pool : ppooltree->GetPools()) {
        std::map<CKeyID, std::vector<WalletLpCoin>> mapByHolder;
        CollectWalletLpCoins(this, pool.nPoolID, mapByHolder);
        WalletLpHolding h;
        for (const auto& kv : mapByHolder) {
            for (const WalletLpCoin& lc : kv.second) {
                h.units += lc.units;
                h.coins++;
            }
        }
        if (h.units > 0) out[pool.nPoolID] = h;
    }
}

/** True if the mempool already holds a pool op for nPoolID. One op per pool
 * per block: a second would be refused at ATMP ("pool-op-in-mempool" or a
 * custody-outpoint conflict), but CommitTransaction does NOT surface an ATMP
 * rejection - so every pool builder fails fast on this instead of handing the
 * caller a txid that can never confirm. */
static bool PoolOpPending(uint32_t nPoolID)
{
    LOCK(mempool.cs);
    for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); mi++) {
        const CTransaction& mtx = mi->GetTx();
        if (mtx.nVersion == TRANSACTION_POOL_VERSION && mtx.vchPoolPayload.size() >= 4) {
            uint32_t nTheirs = 0;
            memcpy(&nTheirs, mtx.vchPoolPayload.data(), 4);   // nPoolID leads every pool payload
            if (nTheirs == nPoolID)
                return true;
        }
    }
    return false;
}

/** True if the mempool holds a house-state-CHANGING op for nHouseID (governance,
 * note MINT/REDEEM/CLAIM, deposit ORIGINATE/WITHDRAW/CLAIM, pool RETIRE, or a
 * v11 bill DISCOUNT/HRETIRE/HCLAIM). A
 * pool CREATE is house-status-DEPENDENT (needs effective-Open), so co-residing
 * with one of these bricks our own BMM template at ConnectBlock's one-op rule -
 * the wallet fails fast (the ATMP guard would reject it too, but only opaquely
 * via CommitTransaction). Mirrors the ATMP scan. */
/** The one-op-per-house wallet fail-fast, with its regtest-only escape.
 *
 * WHY AN ESCAPE EXISTS AT ALL. The fail-fast is what stops an operator's op
 * from being built against a house whose slot is already taken: without it,
 * CommitTransaction AddToWallet's the doomed tx BEFORE ATMP refuses it, and
 * CWallet::IsSpent then treats that non-abandoned depth-0 spender as spending
 * its inputs - darkening real coins out of BOTH getbalance and listunspent
 * until someone abandons it. That is not theoretical: it cost ~179 ECX of
 * wallet visibility in the Gate 2z burn-in (C7c, root-caused 2026-08-04), and
 * the coin it swallowed was the largest in the wallet precisely because
 * SelectCoins reaches for it when the small ones are locked.
 *
 * But the consensus-side mirror guard needs an UNGUARDED op to prosecute it -
 * an incomer the wallet lets through so ATMP is the thing that refuses. Gate 2z
 * is built on exactly that. So regtest may disable the wallet layer.
 *
 * THIS IS NOT THE -attestcadence PATTERN (settle.h:54's fork hazard) and the
 * difference is worth stating: that knob changes what CONSENSUS accepts, so two
 * nodes set differently disagree about validity. This one changes only WHICH
 * LAYER refuses - never whether the op is refused. Consensus is untouched, so
 * no setting of it can fork anything. Regtest-gated anyway, out of caution.
 *
 * NAMED `-housefailfast` (default on), disabled as `-housefailfast=0`, and NOT
 * `-nohousefailfast`: ArgsManager RESERVES the `-no` prefix (util.cpp:431
 * rewrites `-nofoo` to `-foo` with the value inverted), so a literal
 * `-nohousefailfast` lookup can never match what the parser actually stored.
 * The first cut got this wrong and the flag silently did nothing - caught by
 * Gate 2z's vacuity guard, which turned a silent no-op into a named failure.
 * Naming it positively means `-nohousefailfast` ALSO works, for free, as the
 * parser's own alias. */
static bool HouseFailFastEnabled()
{
    static const bool fRegtest =
        Params().NetworkIDString() == CBaseChainParams::REGTEST;
    return !(fRegtest && !gArgs.GetBoolArg("-housefailfast", true));
}

static bool HouseStateChangePending(uint32_t nHouseID)
{
    LOCK(mempool.cs);
    for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); mi++) {
        const CTransaction& mtx = mi->GetTx();
        uint32_t nTheirs = 0;
        bool fMatch = false;
        if (mtx.nVersion == TRANSACTION_HOUSE_VERSION && mtx.nHouseOp != HOUSE_OP_REGISTER &&
                mtx.vchHousePayload.size() >= 4) {
            memcpy(&nTheirs, mtx.vchHousePayload.data(), 4); fMatch = true;
        } else if (mtx.nVersion == TRANSACTION_NOTE_VERSION &&
                (mtx.nNoteOp == NOTE_OP_MINT || mtx.nNoteOp == NOTE_OP_REDEEM ||
                 mtx.nNoteOp == NOTE_OP_CLAIM || mtx.nNoteOp == NOTE_OP_PROTEST) &&
                mtx.vchNotePayload.size() >= 4) {
            // PROTEST (B3 T-b3) writes the house's protest fields = takes the
            // slot; mirrored in GetHouseSlotIDs and the ATMP scan - the
            // triple-maintenance hazard Gate 2z exists to catch.
            memcpy(&nTheirs, mtx.vchNotePayload.data(), 4); fMatch = true;
        } else if (mtx.nVersion == TRANSACTION_DEPOSIT_VERSION &&
                (mtx.nDepositOp == DEPOSIT_OP_ORIGINATE || mtx.nDepositOp == DEPOSIT_OP_WITHDRAW ||
                 mtx.nDepositOp == DEPOSIT_OP_CLAIM) && mtx.vchDepositPayload.size() >= 4) {
            memcpy(&nTheirs, mtx.vchDepositPayload.data(), 4); fMatch = true;
        } else if (mtx.nVersion == TRANSACTION_POOL_VERSION && mtx.nPoolOp == POOL_OP_RETIRE &&
                mtx.vchPoolPayload.size() >= 4) {
            memcpy(&nTheirs, mtx.vchPoolPayload.data(), 4); fMatch = true;
        } else if (mtx.nVersion == TRANSACTION_BILL_VERSION &&
                (mtx.nBillOp == BILL_OP_DISCOUNT || mtx.nBillOp == BILL_OP_HRETIRE ||
                 mtx.nBillOp == BILL_OP_HCLAIM) && mtx.vchBillPayload.size() >= 8) {
            // B1: the three v11 ops that mutate a house record take its slot.
            // Bill payloads LEAD with nBillID and carry the house id in bytes
            // 4..8 - NOT 0..4 like every other family, which is exactly the
            // kind of near-miss that reads correct and silently matches house
            // id == bill id. RECOURSE is deliberately absent: it mutates no
            // house record and takes no slot.
            //
            // Without this arm the guard is not a mirror of anything - there is
            // no ATMP v11 slot check until T-d5, and CommitTransaction returns
            // true unconditionally - so this IS the guard. A pooled discount
            // invisible here means the buying house's next mintnote builds on a
            // template that ConnectBlock's one-op-per-house rule will refuse,
            // and the wallet records a phantom txid.
            memcpy(&nTheirs, mtx.vchBillPayload.data() + 4, 4); fMatch = true;
        } else if (mtx.nVersion == TRANSACTION_SETTLE_VERSION &&
                mtx.vchSettlePayload.size() >= 8) {
            // Dual-slot: a pooled settle takes BOTH houses' slots.
            uint32_t nTheirA = 0, nTheirB = 0;
            memcpy(&nTheirA, mtx.vchSettlePayload.data(), 4);
            memcpy(&nTheirB, mtx.vchSettlePayload.data() + 4, 4);
            if (nTheirA == nHouseID || nTheirB == nHouseID)
                return true;
        }
        if (fMatch && nTheirs == nHouseID)
            return true;
    }
    return false;
}

/** Pick one holder's UNDEMANDED note coins covering nUnits (pools accept only
 * undemanded notes - decision 4). Returns the chosen coins + the holder key. */
static bool SelectUndemandedNotes(CWallet* pwallet, uint32_t nHouseID, uint64_t nUnits,
                                  std::vector<WalletNoteCoin>& vSpend, uint64_t& nSpent,
                                  CKey& keyHolder, std::string& strFail)
{
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(pwallet, nHouseID, mapByHolder);
    for (const auto& kv : mapByHolder) {
        if (kv.first.second != 0)
            continue;   // demanded notes cannot enter a pool
        uint64_t sum = 0;
        for (const WalletNoteCoin& nc : kv.second) sum += nc.units;
        if (sum < nUnits)
            continue;
        std::vector<WalletNoteCoin> chosen = kv.second;
        std::sort(chosen.begin(), chosen.end(),
            [](const WalletNoteCoin& a, const WalletNoteCoin& b){ return a.units > b.units; });
        vSpend.clear();
        nSpent = 0;
        for (const WalletNoteCoin& nc : chosen) {
            vSpend.push_back(nc);
            nSpent += nc.units;
            if (nSpent >= nUnits) break;
        }
        if (!pwallet->GetKey(CPubKey(vSpend[0].vchHolderPubKey).GetID(), keyHolder)) {
            strFail = "Note holder key missing!";
            return false;
        }
        return true;
    }
    strFail = "No single holder has enough undemanded note units!";
    return false;
}

bool CWallet::CreatePool(std::string& strFail, uint256& txidOut, uint32_t nPoolID, uint32_t nFeeBps, uint64_t nInitNoteUnits, const CAmount& amountInitBtx, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    if (nFeeBps < POOL_FEE_BPS_MIN || nFeeBps > POOL_FEE_BPS_MAX) { strFail = "Pool fee out of bounds (1..100 bps)!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // Fail-fast mirrors of the consensus gates (CommitTransaction does not
    // surface an ATMP rejection to the caller).
    if (ppooltree->HavePool(nPoolID)) { strFail = "This house already has its pool (one per house)!"; return false; }
    if (PoolOpPending(nPoolID)) { strFail = "Another pool op for this pool is already pending (one op per pool per block) - retry next block!"; return false; }
    if (HouseStateChangePending(nPoolID)) { strFail = "A house/note/deposit op for this house is pending - a status-gated CREATE would brick the template; retry next block!"; return false; }
    CHouse house;
    if (!phousetree->GetHouse(nPoolID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, chainActive.Height() + 1) != HOUSE_STATUS_OPEN) { strFail = "House is not effectively open - cannot charter its pool!"; return false; }
    uint64_t nLpToCreator = 0, nLpSupply0 = 0;
    if (!PoolLpMintInitial(nInitNoteUnits, amountInitBtx, nLpToCreator, nLpSupply0)) {
        strFail = "Seed too small: sqrt(note*btx) must clear the locked liquidity floor!";
        return false;
    }

    // The creator's undemanded notes seed the note side; the creator key
    // receives the LP coin and any note change (the shape pins both outputs
    // to the DECLARED creator pubkey).
    std::vector<WalletNoteCoin> vSpend;
    uint64_t nSpentUnits = 0;
    CKey keyCreator;
    if (!SelectUndemandedNotes(this, nPoolID, nInitNoteUnits, vSpend, nSpentUnits, keyCreator, strFail))
        return false;
    const uint64_t nNoteChange = nSpentUnits - nInitNoteUnits;

    PoolCreate create;
    create.nPoolID = nPoolID;
    create.nFeeBps = nFeeBps;
    create.nInitNoteUnits = nInitNoteUnits;
    create.amountInitBtx = amountInitBtx;
    create.nNoteChangeUnits = nNoteChange;
    create.vchCreatorPubKey = vSpend[0].vchHolderPubKey;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_CREATE;
    mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(nPoolID)));
    mtx.vout.push_back(CTxOut(amountInitBtx, PoolEscrowScript(nPoolID)));
    mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(create.vchCreatorPubKey)));
    if (nNoteChange > 0)
        mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(create.vchCreatorPubKey)));

    // Fund the BTX side + dusts + fee (the spent note coins' dust becomes fee).
    const CAmount nTarget = amountInitBtx + (CAmount)(2 + (nNoteChange > 0 ? 1 : 0)) * POOL_DUST_VALUE + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the pool seed + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    // Finalize ALL inputs BEFORE signing: every pool sighash binds prevouts.
    for (const WalletNoteCoin& nc : vSpend)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const uint256 sighash = PoolCreateSigHash(nPoolID, nFeeBps, nInitNoteUnits, amountInitBtx,
            nNoteChange, PoolHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx));
    if (!keyCreator.Sign(sighash, create.vchCreatorSig)) { strFail = "Failed to sign as pool creator!"; return false; }
    if (!SignHouseApprovers(this, house, sighash, create.vApproverIndex, create.vApproverSig, strFail))
        return false;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << create;
    mtx.vchPoolPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const WalletNoteCoin& nc : vSpend) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, POOL_DUST_VALUE, SIGHASH_ALL), nc.script, sigdata)) {
            strFail = "Signing seed note inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing pool funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit pool create! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::AddPoolLiquidity(std::string& strFail, uint256& txidOut, uint32_t nPoolID, uint64_t nAddNoteUnits, const CAmount& amountAddBtx, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CPool pool;
    if (!ppooltree->GetPool(nPoolID, pool)) { strFail = "Unknown pool!"; return false; }
    if (PoolOpPending(nPoolID)) { strFail = "Another pool op for this pool is already pending (one op per pool per block) - retry next block!"; return false; }
    uint64_t nLpMinted = 0;
    if (!PoolLpMintProportional(nAddNoteUnits, amountAddBtx, pool.nNoteReserve,
            pool.amountBtxReserve, pool.nLpSupply, nLpMinted)) {
        strFail = "Add amounts too small (would mint zero LP units) or out of bounds!";
        return false;
    }

    std::vector<WalletNoteCoin> vSpend;
    uint64_t nSpentUnits = 0;
    CKey keyProvider;
    if (!SelectUndemandedNotes(this, nPoolID, nAddNoteUnits, vSpend, nSpentUnits, keyProvider, strFail))
        return false;
    const uint64_t nNoteChange = nSpentUnits - nAddNoteUnits;

    PoolAddLiq add;
    add.nPoolID = nPoolID;
    add.nPriorNoteReserve = pool.nNoteReserve;
    add.amountPriorBtxReserve = pool.amountBtxReserve;
    add.nPriorLpSupply = pool.nLpSupply;
    add.nAddNoteUnits = nAddNoteUnits;
    add.amountAddBtx = amountAddBtx;
    add.nLpMinted = nLpMinted;
    add.nNoteChangeUnits = nNoteChange;
    add.vchProviderPubKey = vSpend[0].vchHolderPubKey;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_ADD_LIQ;
    mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(nPoolID)));
    mtx.vout.push_back(CTxOut(pool.amountBtxReserve + amountAddBtx, PoolEscrowScript(nPoolID)));
    mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(add.vchProviderPubKey)));
    if (nNoteChange > 0)
        mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(add.vchProviderPubKey)));

    // The spent custody pair's dust covers the new note-escrow dust; fund the
    // added BTX + LP dust (+ change dust) + fee.
    const CAmount nTarget = amountAddBtx + (CAmount)(1 + (nNoteChange > 0 ? 1 : 0)) * POOL_DUST_VALUE + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the liquidity add + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    // vin[0/1] = THE canonical custody pair (no scriptSig - open-at-script,
    // guarded by tags), then the provider's notes, then funding. Inputs are
    // final BEFORE the payload signature (prevouts-bound).
    mtx.vin.push_back(CTxIn(pool.outNote, CScript()));
    mtx.vin.push_back(CTxIn(pool.outBtx, CScript()));
    for (const WalletNoteCoin& nc : vSpend)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    if (!keyProvider.Sign(PoolAddLiqSigHash(add, PoolHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx)),
            add.vchProviderSig)) {
        strFail = "Failed to sign liquidity add!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << add;
    mtx.vchPoolPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 2;   // custody pair needs no signatures
    for (const WalletNoteCoin& nc : vSpend) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, POOL_DUST_VALUE, SIGHASH_ALL), nc.script, sigdata)) {
            strFail = "Signing note inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit liquidity add! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::RemovePoolLiquidity(std::string& strFail, uint256& txidOut, uint32_t nPoolID, uint64_t nBurnLp, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CPool pool;
    if (!ppooltree->GetPool(nPoolID, pool)) { strFail = "Unknown pool!"; return false; }
    if (PoolOpPending(nPoolID)) { strFail = "Another pool op for this pool is already pending (one op per pool per block) - retry next block!"; return false; }
    uint64_t nNoteOut = 0;
    CAmount amountBtxOut = 0;
    if (!PoolLpRedeemAmounts(nBurnLp, pool.nNoteReserve, pool.amountBtxReserve, pool.nLpSupply,
            nNoteOut, amountBtxOut)) {
        strFail = "Burn refused: too small (dust payout), or it would breach the locked liquidity floor!";
        return false;
    }

    // One holder's LP coins covering the burn (whole coins; change re-issued).
    std::map<CKeyID, std::vector<WalletLpCoin>> mapByHolder;
    CollectWalletLpCoins(this, nPoolID, mapByHolder);
    std::vector<WalletLpCoin> vSpend;
    uint64_t nSpentLp = 0;
    CKey keyProvider;
    bool fFound = false;
    for (const auto& kv : mapByHolder) {
        uint64_t sum = 0;
        for (const WalletLpCoin& lc : kv.second) sum += lc.units;
        if (sum < nBurnLp)
            continue;
        std::vector<WalletLpCoin> chosen = kv.second;
        std::sort(chosen.begin(), chosen.end(),
            [](const WalletLpCoin& a, const WalletLpCoin& b){ return a.units > b.units; });
        vSpend.clear();
        nSpentLp = 0;
        for (const WalletLpCoin& lc : chosen) {
            vSpend.push_back(lc);
            nSpentLp += lc.units;
            if (nSpentLp >= nBurnLp) break;
        }
        if (vSpend.size() > MAX_POOL_LP_INPUTS) { strFail = "Too many LP coins for one remove!"; return false; }
        if (!GetKey(kv.first, keyProvider)) { strFail = "LP holder key missing!"; return false; }
        fFound = true;
        break;
    }
    if (!fFound) { strFail = "No single holder has enough LP units!"; return false; }
    const uint64_t nLpChange = nSpentLp - nBurnLp;

    PoolRemoveLiq rem;
    rem.nPoolID = nPoolID;
    rem.nPriorNoteReserve = pool.nNoteReserve;
    rem.amountPriorBtxReserve = pool.amountBtxReserve;
    rem.nPriorLpSupply = pool.nLpSupply;
    rem.nBurnLp = nBurnLp;
    rem.nNoteOut = nNoteOut;
    rem.amountBtxOut = amountBtxOut;
    rem.nLpChangeUnits = nLpChange;
    rem.vchProviderPubKey = vSpend[0].vchHolderPubKey;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_REMOVE_LIQ;
    mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(nPoolID)));
    mtx.vout.push_back(CTxOut(pool.amountBtxReserve - amountBtxOut, PoolEscrowScript(nPoolID)));
    // Zero-side companion: a payout side that floored to 0 is OMITTED (this matches
    // the consensus variable packing [note?, BTX?, LP-change?]). A full-position
    // burn in a swap-skewed pool can zero one side; the forgone dust stays in the
    // reserve for RETIRE to sweep.
    if (nNoteOut > 0)
        mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(rem.vchProviderPubKey)));
    if (amountBtxOut > 0)
        mtx.vout.push_back(CTxOut(amountBtxOut, PoolScriptForPubKey(rem.vchProviderPubKey)));
    if (nLpChange > 0)
        mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(rem.vchProviderPubKey)));

    // Fund the payout/change dusts + fee (the burned LP coins' dust helps but
    // is not counted - it becomes extra fee headroom). Only the note payout and
    // LP change are wallet-funded dusts; the BTX payout comes from the custody coin.
    const CAmount nTarget = (CAmount)((nNoteOut > 0 ? 1 : 0) + (nLpChange > 0 ? 1 : 0)) * POOL_DUST_VALUE + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the remove + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    mtx.vin.push_back(CTxIn(pool.outNote, CScript()));
    mtx.vin.push_back(CTxIn(pool.outBtx, CScript()));
    for (const WalletLpCoin& lc : vSpend)
        mtx.vin.push_back(CTxIn(lc.outpoint.hash, lc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    if (!keyProvider.Sign(PoolRemoveLiqSigHash(rem, PoolHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx)),
            rem.vchProviderSig)) {
        strFail = "Failed to sign liquidity remove!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << rem;
    mtx.vchPoolPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 2;
    for (const WalletLpCoin& lc : vSpend) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, POOL_DUST_VALUE, SIGHASH_ALL), lc.script, sigdata)) {
            strFail = "Signing LP inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit liquidity remove! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::RetirePool(std::string& strFail, uint256& txidOut, uint32_t nPoolID, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // Fail-fast mirrors of the consensus gates.
    CPool pool;
    if (!ppooltree->GetPool(nPoolID, pool)) { strFail = "Unknown pool!"; return false; }
    if (PoolOpPending(nPoolID)) { strFail = "Another pool op for this pool is already pending (one op per pool per block) - retry next block!"; return false; }
    if (HouseStateChangePending(nPoolID)) { strFail = "A house/note/deposit op for this house is pending (RETIRE burns units - one house change per block); retry next block!"; return false; }
    if (pool.nLpSupply != POOL_MIN_LIQUIDITY) { strFail = "Pool is not at the locked floor: remove ALL issued LP first (only the never-issued floor may remain)!"; return false; }
    CHouse house;
    if (!phousetree->GetHouse(nPoolID, house)) { strFail = "Unknown house!"; return false; }
    if (house.nMintedUnits < pool.nNoteReserve) { strFail = "House minted units are below the pool residual - cannot burn!"; return false; }
    if (house.vchRedemptionDestPK.empty()) { strFail = "House has no redemption destination key!"; return false; }

    const int nNextHeight = chainActive.Height() + 1;
    const char chEff = HouseEffectiveStatus(house, nNextHeight);

    PoolRetire ret;
    ret.nPoolID = nPoolID;
    ret.nPriorNoteReserve = pool.nNoteReserve;
    ret.amountPriorBtxReserve = pool.amountBtxReserve;
    ret.nPriorLpSupply = pool.nLpSupply;
    ret.nFeeBps = pool.nFeeBps;
    ret.nCreateHeight = pool.nCreateHeight;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_RETIRE;
    // vout[0]: the forced floor-BTX payout to P2PKH(vchRedemptionDestPK), value ==
    // Y (the custody BTX coin funds it exactly; the note-side dust becomes fee).
    mtx.vout.push_back(CTxOut(pool.amountBtxReserve, PoolScriptForPubKey(house.vchRedemptionDestPK)));

    // vout[0] is value-pinned to the whole custody BTX value, so the fee MUST come
    // from an added plain input (the note-side dust helps but is not counted).
    const CAmount nTarget = nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the retire fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    // vin[0/1] = THE canonical custody pair (open-at-script; guarded by tags),
    // then plain funding. Inputs final BEFORE the payload signature (prevouts-bound).
    mtx.vin.push_back(CTxIn(pool.outNote, CScript()));
    mtx.vin.push_back(CTxIn(pool.outBtx, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // Auth: a single non-settled partner triggers when the house is effectively
    // Insolvent (the liveness path - no M-of-N assembly required); otherwise the
    // charter M-of-N approves (valid at any status).
    const uint256 sighash = PoolRetireSigHash(ret, PoolHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx));
    if (chEff == HOUSE_STATUS_INSOLVENT) {
        bool fSigned = false;
        for (size_t j = 0; j < house.vPartner.size(); j++) {
            if (house.vPartner[j].status == HOUSE_PARTNER_SETTLED)
                continue;
            CKey keyPartner;
            if (!GetKey(CPubKey(house.vPartner[j].vchPubKey).GetID(), keyPartner))
                continue;
            if (!keyPartner.Sign(sighash, ret.vchTriggerSig))
                continue;
            ret.nTriggerPartnerIndex = (uint32_t)j;
            fSigned = true;
            break;
        }
        if (!fSigned) { strFail = "No non-settled partner key in this wallet to trigger the insolvency retire!"; return false; }
    } else {
        if (!SignHouseApprovers(this, house, sighash, ret.vApproverIndex, ret.vApproverSig, strFail))
            return false;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << ret;
    mtx.vchPoolPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 2;   // custody pair needs no signatures
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit pool retire! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::SwapNote(std::string& strFail, uint256& txidOut, uint32_t nPoolID, bool fNoteToBtx, uint64_t nAmountIn, uint64_t nMinOut, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CPool pool;
    if (!ppooltree->GetPool(nPoolID, pool)) { strFail = "Unknown pool!"; return false; }
    if (PoolOpPending(nPoolID)) { strFail = "Another pool op for this pool is already pending (one op per pool per block) - retry next block!"; return false; }
    uint64_t nAmountOut = 0;
    const bool fQuote = fNoteToBtx
        ? PoolSwapOut(nAmountIn, pool.nNoteReserve, (uint64_t)pool.amountBtxReserve, pool.nFeeBps, nAmountOut)
        : PoolSwapOut(nAmountIn, (uint64_t)pool.amountBtxReserve, pool.nNoteReserve, pool.nFeeBps, nAmountOut);
    if (!fQuote) { strFail = "Swap refused: amount too small or would drain the pool!"; return false; }
    if (nAmountOut < nMinOut) { strFail = "Price moved: the quoted out-amount is below your minimum!"; return false; }

    PoolSwap swap;
    swap.nPoolID = nPoolID;
    swap.nPriorNoteReserve = pool.nNoteReserve;
    swap.amountPriorBtxReserve = pool.amountBtxReserve;
    swap.nPriorLpSupply = pool.nLpSupply;
    swap.nDirection = fNoteToBtx ? POOL_SWAP_NOTE_TO_BTX : POOL_SWAP_BTX_TO_NOTE;
    swap.nAmountIn = nAmountIn;
    swap.nMinOut = nMinOut;
    swap.nAmountOut = nAmountOut;
    swap.nNoteChangeUnits = 0;

    std::vector<WalletNoteCoin> vSpendNotes;
    CKey keyTrader;
    CAmount nTarget = 0;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_POOL_VERSION;
    mtx.nPoolOp = POOL_OP_SWAP;
    mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolEscrowScript(nPoolID)));

    if (fNoteToBtx) {
        uint64_t nSpentUnits = 0;
        if (!SelectUndemandedNotes(this, nPoolID, nAmountIn, vSpendNotes, nSpentUnits, keyTrader, strFail))
            return false;
        swap.nNoteChangeUnits = nSpentUnits - nAmountIn;
        swap.vchTraderPubKey = vSpendNotes[0].vchHolderPubKey;
        mtx.vout.push_back(CTxOut(pool.amountBtxReserve - (CAmount)nAmountOut, PoolEscrowScript(nPoolID)));
        mtx.vout.push_back(CTxOut((CAmount)nAmountOut, PoolScriptForPubKey(swap.vchTraderPubKey)));
        if (swap.nNoteChangeUnits > 0)
            mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(swap.vchTraderPubKey)));
        nTarget = (CAmount)(swap.nNoteChangeUnits > 0 ? 1 : 0) * POOL_DUST_VALUE + nFee;
    } else {
        // Fresh key receives the note payout; the trader funds with plain sats.
        CPubKey pubTrader;
        if (!GetKeyFromPool(pubTrader)) { strFail = "Keypool ran out!"; return false; }
        if (!GetKey(pubTrader.GetID(), keyTrader)) { strFail = "Trader key missing!"; return false; }
        swap.vchTraderPubKey = std::vector<unsigned char>(pubTrader.begin(), pubTrader.end());
        mtx.vout.push_back(CTxOut(pool.amountBtxReserve + (CAmount)nAmountIn, PoolEscrowScript(nPoolID)));
        mtx.vout.push_back(CTxOut(POOL_DUST_VALUE, PoolScriptForPubKey(swap.vchTraderPubKey)));
        nTarget = (CAmount)nAmountIn + POOL_DUST_VALUE + nFee;
    }

    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nTarget > 0 && !SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the swap + fee!"; return false; }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }

    mtx.vin.push_back(CTxIn(pool.outNote, CScript()));
    mtx.vin.push_back(CTxIn(pool.outBtx, CScript()));
    for (const WalletNoteCoin& nc : vSpendNotes)
        mtx.vin.push_back(CTxIn(nc.outpoint.hash, nc.outpoint.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    if (!keyTrader.Sign(PoolSwapSigHash(swap, PoolHashPrevouts(CTransaction(mtx)), BillHashOutputs(mtx)),
            swap.vchTraderSig)) {
        strFail = "Failed to sign swap!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << swap;
    mtx.vchPoolPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 2;
    for (const WalletNoteCoin& nc : vSpendNotes) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, POOL_DUST_VALUE, SIGHASH_ALL), nc.script, sigdata)) {
            strFail = "Signing note inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit swap! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

// ---------------------------------------------------------------------------
// Settlement ceremony (Phase 3.7 pt2, T-s6). Wallet protocol, not consensus.

/** Sign the shared digest with this wallet's ACTIVE approver keys for `house`,
 * ascending indices, stopping at exactly thresholdM (VerifyHouseApprovers
 * demands exactly M). */
static bool SignSettleApprovers(CWallet* pwallet, const CHouse& house, const uint256& sighash,
                                std::vector<uint32_t>& vIdx,
                                std::vector<std::vector<unsigned char>>& vSig, std::string& strFail)
{
    for (size_t i = 0; i < house.vPartner.size() && vIdx.size() < house.nThresholdM; i++) {
        const HousePartner& p = house.vPartner[i];
        if (p.status != HOUSE_PARTNER_ACTIVE)
            continue;
        CKey key;
        if (!pwallet->GetKey(CPubKey(p.vchPubKey).GetID(), key))
            continue;
        std::vector<unsigned char> sig;
        if (!key.Sign(sighash, sig))
            continue;
        vIdx.push_back((uint32_t)i);
        vSig.push_back(sig);
    }
    if (vIdx.size() < house.nThresholdM) {
        strFail = strprintf("This wallet holds only %u of the %u approver keys house %u requires!",
                            (unsigned)vIdx.size(), house.nThresholdM, house.nHouseID);
        return false;
    }
    return true;
}

/** Advisory pre-flight shared by the ceremony steps: both houses exist,
 * par-eligible, cadence-clear, and no pooled house-slot op touches either
 * (the connect-time checks are the real gate; failing fast here beats an
 * opaque CommitTransaction reject). */
static bool SettlePreflight(uint32_t nA, uint32_t nB, CHouse& houseA, CHouse& houseB, std::string& strFail)
{
    if (!phousetree->GetHouse(nA, houseA) || !phousetree->GetHouse(nB, houseB)) {
        strFail = "Unknown house!"; return false;
    }
    const int nHeight = chainActive.Height();
    if (!HouseParEligible(houseA, nHeight) || !HouseParEligible(houseB, nHeight)) {
        strFail = "A house is not par-eligible (must be Open, at/above the reserve floor, and attested within one cadence)!";
        return false;
    }
    const uint32_t nSettleCadence = Params().GetConsensus().nSettleCadence;
    for (const CHouse* h : {&houseA, &houseB}) {
        if (h->nLastSettleHeight != 0 && (uint32_t)nHeight < h->nLastSettleHeight + nSettleCadence) {
            strFail = strprintf("House %u settled at height %u - cadence window (%u blocks) not yet open!",
                                h->nHouseID, h->nLastSettleHeight, nSettleCadence);
            return false;
        }
    }
    if (HouseStateChangePending(nA) || HouseStateChangePending(nB)) {
        strFail = "A house-state-changing op for one of these houses is already pending - retry next block!";
        return false;
    }
    return true;
}

/** A displaced/evicted settle (ATTEST-displaces at ATMP, the staleness sweep)
 * is re-signable by design - but the completer's wallet still holds the
 * unbroadcast copy, which encumbers the presented bundle coins until it is
 * abandoned. Free them: abandon any of OUR unconfirmed v16 txs touching either
 * house that is no longer in the mempool. (The responder never commits its
 * half, so only the completer's wallet needs this.) */
static void AbandonDisplacedSettles(CWallet* pwallet, uint32_t nHouseA, uint32_t nHouseB)
{
    std::vector<uint256> vAbandon;
    for (auto& entry : pwallet->mapWallet) {
        CWalletTx& wtx = entry.second;
        if (wtx.tx->nVersion != TRANSACTION_SETTLE_VERSION)
            continue;
        // Resync the cached mempool flag from the POOL ITSELF before trusting
        // it: removal notifications are scheduler-async (and CONFLICT/BLOCK
        // reasons never arrive at all), so a displaced settle can carry a
        // stale fInMempool == true - which would also wedge the
        // AbandonTransaction below via its own InMempool() guard.
        {
            LOCK(mempool.cs);
            wtx.fInMempool = mempool.exists(entry.first);
        }
        if (wtx.GetDepthInMainChain() != 0 || wtx.InMempool() || wtx.isAbandoned())
            continue;
        uint32_t nA = 0, nB = 0;
        if (wtx.tx->vchSettlePayload.size() >= 8) {
            memcpy(&nA, wtx.tx->vchSettlePayload.data(), 4);
            memcpy(&nB, wtx.tx->vchSettlePayload.data() + 4, 4);
        }
        if (nA == nHouseA || nA == nHouseB || nB == nHouseA || nB == nHouseB)
            vAbandon.push_back(entry.first);
    }
    for (const uint256& txid : vAbandon) {
        LogPrintf("%s: abandoning displaced settle %s\n", __func__, txid.ToString());
        pwallet->AbandonTransaction(txid);
    }
}

bool CWallet::ProposeSettle(std::string& strFail, std::string& strHexOut, uint256& txidConsolidate,
                            uint32_t nOwnHouseID, uint32_t nCounterpartyHouseID,
                            uint64_t nMaxUnits, uint32_t nExpiryBlocks, const CAmount& nFee)
{
    strFail = "Unknown error!";
    strHexOut.clear();
    txidConsolidate.SetNull();
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    if (nOwnHouseID == nCounterpartyHouseID) { strFail = "A house cannot settle with itself!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CHouse houseOwn, houseCtpy;
    if (!SettlePreflight(nOwnHouseID, nCounterpartyHouseID, houseOwn, houseCtpy, strFail))
        return false;
    AbandonDisplacedSettles(this, nOwnHouseID, nCounterpartyHouseID);

    // What we present: COUNTERPARTY-issued paper this wallet holds, on ONE key
    // (the v16 input rule). Prefer an exact-match key when a cap is given;
    // split/merge via TransferNote otherwise and report the consolidation.
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nCounterpartyHouseID, mapByHolder);
    const std::vector<WalletNoteCoin>* pBest = nullptr;
    uint64_t nBestUnits = 0;
    const std::vector<WalletNoteCoin>* pExact = nullptr;
    for (const auto& kv : mapByHolder) {
        if (kv.first.second != 0)
            continue;   // demanded notes cannot be presented
        uint64_t nTotal = 0;
        for (const WalletNoteCoin& c : kv.second)
            nTotal += c.units;
        if (nTotal == 0)
            continue;
        if (nMaxUnits > 0 && nTotal == nMaxUnits)
            pExact = &kv.second;
        if (nTotal > nBestUnits) { nBestUnits = nTotal; pBest = &kv.second; }
    }
    if (!pBest) { strFail = strprintf("No presentable (undemanded) notes of house %u held!", nCounterpartyHouseID); return false; }

    const std::vector<WalletNoteCoin>* pUse = pBest;
    uint64_t nUseUnits = nBestUnits;
    if (nMaxUnits > 0) {
        if (pExact) {
            pUse = pExact;
            nUseUnits = nMaxUnits;
        } else if (nBestUnits > nMaxUnits) {
            // Exact split: TransferNote sends EXACTLY nMaxUnits to a fresh key
            // (change returns to the source holder). Re-run once confirmed.
            CPubKey pubFresh;
            if (!GetKeyFromPool(pubFresh)) { strFail = "Keypool ran out!"; return false; }
            if (!TransferNote(strFail, txidConsolidate, nCounterpartyHouseID, nMaxUnits, nFee,
                              GetScriptForDestination(pubFresh.GetID())))
                return false;
            strFail = "Consolidating an exact-sum bundle - re-run proposesettle once the split confirms.";
            return false;
        }   // else: best-effort under the cap - present the largest key as-is
    }
    if (pUse->size() > SETTLE_MAX_BUNDLE_INPUTS) {
        // Merge the key's fragments into one coin (self-transfer of the full
        // holding re-issues it as a single note coin). Re-run once confirmed.
        if (!TransferNote(strFail, txidConsolidate, nCounterpartyHouseID, nUseUnits, nFee,
                          (*pUse)[0].script))
            return false;
        strFail = "Merging a fragmented bundle - re-run proposesettle once the merge confirms.";
        return false;
    }

    SettleProposalV1 prop;
    prop.nHouseInitiator = nOwnHouseID;
    prop.nHouseCounterparty = nCounterpartyHouseID;
    prop.nUnitsPresented = nUseUnits;
    prop.vchPresentKey = (*pUse)[0].vchHolderPubKey;
    for (const WalletNoteCoin& c : *pUse)
        prop.vBundle.push_back(c.outpoint);
    prop.nExpiryHeight = (uint32_t)chainActive.Height() + (nExpiryBlocks ? nExpiryBlocks : 72);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << prop;
    strHexOut = HexStr(ss.begin(), ss.end());
    return true;
}

bool CWallet::SignSettle(std::string& strFail, std::string& strHexTxOut,
                         const std::string& strHexProposal, const CAmount& nFee)
{
    strFail = "Unknown error!";
    strHexTxOut.clear();
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    SettleProposalV1 prop;
    if (!IsHex(strHexProposal)) { strFail = "Proposal is not hex!"; return false; }
    try {
        std::vector<unsigned char> vch = ParseHex(strHexProposal);
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> prop;
        if (!ss.empty()) { strFail = "Trailing bytes in proposal!"; return false; }
    } catch (const std::exception&) { strFail = "Undecodable proposal!"; return false; }
    if (prop.nVersion != 1) { strFail = "Unknown proposal version!"; return false; }
    if (prop.vBundle.empty() || prop.vBundle.size() > SETTLE_MAX_BUNDLE_INPUTS ||
            prop.nUnitsPresented == 0) { strFail = "Malformed proposal!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // We are the responder: prop.nHouseCounterparty is OUR house; the paper the
    // initiator presents is OUR issue, held on the initiator's presentment key.
    const uint32_t nOwn = prop.nHouseCounterparty;
    const uint32_t nCtpy = prop.nHouseInitiator;
    CHouse houseOwn, houseCtpy;
    if (!SettlePreflight(nOwn, nCtpy, houseOwn, houseCtpy, strFail))
        return false;
    AbandonDisplacedSettles(this, nOwn, nCtpy);
    if (prop.nExpiryHeight != 0 && (uint32_t)chainActive.Height() >= prop.nExpiryHeight) {
        strFail = "Proposal expired!"; return false;
    }

    // Verify the initiator's bundle against confirmed state: our issue, pure
    // fNote, undemanded, on the declared key, exact sum.
    const CScript scriptTheirs = NoteScriptForPubKey(prop.vchPresentKey);
    uint64_t nUnitsTheirs = 0;
    for (const COutPoint& out : prop.vBundle) {
        Coin coin;
        if (!pcoinsTip->GetCoin(out, coin) || coin.IsSpent()) { strFail = "A proposed bundle coin is missing/spent!"; return false; }
        if (!coin.fNote || coin.fPoolEscrow || coin.fLpShare || coin.fHouseEscrow ||
                coin.fBill || coin.fBillEscrow || coin.fDeposit || coin.nAssetID ||
                coin.nHouseID != nOwn || coin.nDemandHeight != 0 ||
                coin.out.scriptPubKey != scriptTheirs) {
            strFail = "A proposed bundle coin is not a clean presentable note of our issue!"; return false;
        }
        nUnitsTheirs += coin.nNoteUnits;
    }
    if (nUnitsTheirs != prop.nUnitsPresented) { strFail = "Proposed bundle sum mismatch!"; return false; }

    // Our side: the largest single-key holding of the INITIATOR's issue.
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nCtpy, mapByHolder);
    const std::vector<WalletNoteCoin>* pMine = nullptr;
    uint64_t nUnitsMine = 0;
    for (const auto& kv : mapByHolder) {
        if (kv.first.second != 0)
            continue;
        uint64_t nTotal = 0;
        for (const WalletNoteCoin& c : kv.second)
            nTotal += c.units;
        if (nTotal > nUnitsMine && kv.second.size() <= SETTLE_MAX_BUNDLE_INPUTS) {
            nUnitsMine = nTotal; pMine = &kv.second;
        }
    }
    if (!pMine) { strFail = strprintf("No presentable notes of house %u held - nothing to exchange!", nCtpy); return false; }

    // Canonical A/B by dense id; each bundle is keyed by its ISSUER, presented
    // by the OTHER side. Direction: dU = unitsA - unitsB; dU > 0 -> A debtor.
    const bool fOwnIsA = nOwn < nCtpy;
    const uint64_t nUnitsA = fOwnIsA ? nUnitsTheirs : nUnitsMine;   // A-issued
    const uint64_t nUnitsB = fOwnIsA ? nUnitsMine : nUnitsTheirs;   // B-issued
    const uint64_t dU = nUnitsA >= nUnitsB ? nUnitsA - nUnitsB : nUnitsB - nUnitsA;
    const uint8_t nMode = dU != 0 ? 1 : 0;
    if (nMode == 1) {
        const uint32_t nDebtor = nUnitsA > nUnitsB ? (fOwnIsA ? nOwn : nCtpy)
                                                   : (fOwnIsA ? nCtpy : nOwn);
        if (nDebtor != nOwn) {
            strFail = "This side would be the CREDITOR - the debtor must respond (initiate the settle from the creditor's wallet)!";
            return false;
        }
        if ((CAmount)dU < SETTLE_MIN_RESIDUAL) {
            strFail = strprintf("Residual %u sats is below the %d floor - adjust presented units toward a pure swap!",
                                (unsigned)dU, (int)SETTLE_MIN_RESIDUAL);
            return false;
        }
    }
    const CHouse& houseA = fOwnIsA ? houseOwn : houseCtpy;
    const CHouse& houseB = fOwnIsA ? houseCtpy : houseOwn;

    SettleExchange x;
    x.nHouseA = houseA.nHouseID;
    x.nHouseB = houseB.nHouseID;
    x.nMode = nMode;
    x.nUnitsANotes = nUnitsA;
    x.nUnitsBNotes = nUnitsB;
    x.nCountANotes = (uint16_t)(fOwnIsA ? prop.vBundle.size() : pMine->size());
    x.nCountBNotes = (uint16_t)(fOwnIsA ? pMine->size() : prop.vBundle.size());
    x.vchPresentKeyOfANotes = fOwnIsA ? prop.vchPresentKey : (*pMine)[0].vchHolderPubKey;
    x.vchPresentKeyOfBNotes = fOwnIsA ? (*pMine)[0].vchHolderPubKey : prop.vchPresentKey;
    x.amountResidual = nMode == 1 ? (CAmount)dU : 0;   // exact par
    x.nPrevMintedUnitsA = houseA.nMintedUnits;
    x.nPrevMintedUnitsB = houseB.nMintedUnits;
    x.nPrevLastSettleHeightA = houseA.nLastSettleHeight;
    x.nPrevLastSettleHeightB = houseB.nLastSettleHeight;
    x.nExpiryHeight = prop.nExpiryHeight;

    // Skeleton: A-bundle, B-bundle, then OUR funding (we are debtor-or-swap:
    // residual + fee). vout[0] = residual to the CREDITOR's declared key.
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_SETTLE_VERSION;
    mtx.nSettleOp = SETTLE_OP_EXCHANGE;
    const std::vector<COutPoint>* pFirst;   // the A-issued bundle's outpoints
    std::vector<COutPoint> vMineOut;
    for (const WalletNoteCoin& c : *pMine)
        vMineOut.push_back(c.outpoint);
    pFirst = fOwnIsA ? &prop.vBundle : &vMineOut;
    const std::vector<COutPoint>* pSecond = fOwnIsA ? &vMineOut : &prop.vBundle;
    for (const COutPoint& out : *pFirst)
        mtx.vin.push_back(CTxIn(out, CScript()));
    for (const COutPoint& out : *pSecond)
        mtx.vin.push_back(CTxIn(out, CScript()));

    if (nMode == 1) {
        const CHouse& creditor = nUnitsA > nUnitsB ? houseB : houseA;
        mtx.vout.push_back(CTxOut(x.amountResidual, NoteScriptForPubKey(creditor.vchRedemptionDestPK)));
    }

    const CAmount nTarget = (nMode == 1 ? x.amountResidual : 0) + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) { strFail = "Could not fund the residual + fee!"; return false; }
    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey pubChange;
        if (!reserveKey.GetReservedKey(pubChange)) { strFail = "Keypool ran out!"; return false; }
        CTxOut out(nChange, GetScriptForDestination(pubChange.GetID()));
        if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
    }
    reserveKey.KeepKey();
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // Payload signatures: OUR quorum + OUR presenter over the shared digest
    // (the skeleton is final; the initiator's signatures land later - the
    // digest excludes sig fields and P2PKH sighash excludes the trailer).
    const CTransaction ctxDigest(mtx);
    const uint256 sighash = SettleExchangeSigHash(x, SettleHashPrevouts(ctxDigest), BillHashOutputs(ctxDigest));
    {
        std::vector<uint32_t>& vIdx = fOwnIsA ? x.vApproverIndexA : x.vApproverIndexB;
        std::vector<std::vector<unsigned char>>& vSig = fOwnIsA ? x.vApproverSigA : x.vApproverSigB;
        if (!SignSettleApprovers(this, houseOwn, sighash, vIdx, vSig, strFail))
            return false;
    }
    {
        CKey keyPresent;
        if (!GetKey(CPubKey((*pMine)[0].vchHolderPubKey).GetID(), keyPresent)) { strFail = "Presenter key missing!"; return false; }
        std::vector<unsigned char>& vchSig = fOwnIsA ? x.vchPresentSigOfBNotes : x.vchPresentSigOfANotes;
        if (!keyPresent.Sign(sighash, vchSig)) { strFail = "Failed to sign as presenter!"; return false; }
        // Placeholder for the initiator's slots so the payload decodes with a
        // well-formed shape downstream (completesettle replaces them).
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << x;
    mtx.vchSettlePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // scriptSig-sign OUR bundle inputs + funding inputs on the final skeleton.
    const CTransaction txToSign(mtx);
    const size_t nMineStart = fOwnIsA ? prop.vBundle.size() : 0;
    size_t nIn = nMineStart;
    for (const WalletNoteCoin& c : *pMine) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, NOTE_DUST_VALUE, SIGHASH_ALL), c.script, sigdata)) {
            strFail = "Signing our bundle inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }
    nIn = prop.vBundle.size() + pMine->size();
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    strHexTxOut = EncodeHexTx(CTransaction(mtx));
    return true;
}

void CWallet::ListPresentableNotes(uint32_t nIssuerHouseID, std::vector<PresentableGroup>& vOut)
{
    LOCK2(cs_main, cs_wallet);
    std::map<std::pair<CKeyID, uint32_t>, std::vector<WalletNoteCoin>> mapByHolder;
    CollectWalletNoteCoins(this, nIssuerHouseID, mapByHolder);
    for (const auto& kv : mapByHolder) {
        if (kv.first.second != 0)
            continue;   // demanded notes are not presentable
        PresentableGroup g;
        g.vchHolderPubKey = kv.second[0].vchHolderPubKey;
        g.nCoins = kv.second.size();
        g.nUnits = 0;
        for (const WalletNoteCoin& c : kv.second)
            g.nUnits += c.units;
        if (g.nUnits > 0)
            vOut.push_back(g);
    }
    std::sort(vOut.begin(), vOut.end(),
              [](const PresentableGroup& a, const PresentableGroup& b) { return a.nUnits > b.nUnits; });
}

bool CWallet::CompleteSettle(std::string& strFail, uint256& txidOut, const std::string& strHexTx)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, strHexTx, true)) { strFail = "Undecodable transaction!"; return false; }
    if (mtx.nVersion != TRANSACTION_SETTLE_VERSION || mtx.nSettleOp != SETTLE_OP_EXCHANGE) {
        strFail = "Not a settle transaction!"; return false;
    }
    SettleExchange x;
    if (!DecodeSettlePayload(mtx.vchSettlePayload, x)) { strFail = "Undecodable settle payload!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // Our side = the one whose approver slots are still empty.
    const bool fSignA = x.vApproverSigA.empty();
    if (!fSignA && !x.vApproverSigB.empty()) { strFail = "Both sides already signed!"; return false; }
    const uint32_t nOwn = fSignA ? x.nHouseA : x.nHouseB;
    CHouse houseOwn, houseCtpy;
    if (!SettlePreflight(nOwn, fSignA ? x.nHouseB : x.nHouseA, houseOwn, houseCtpy, strFail))
        return false;

    // The initiator must be the CREDITOR in a residual settle (the debtor
    // responded and funded); verify the residual lands on OUR declared key.
    if (x.nMode == 1) {
        const bool fAIsCreditor = x.nUnitsBNotes > x.nUnitsANotes;
        if (fAIsCreditor != fSignA) { strFail = "This side is the debtor - the responder should have finalized!"; return false; }
        if (mtx.vout.empty() ||
                mtx.vout[0].scriptPubKey != NoteScriptForPubKey(houseOwn.vchRedemptionDestPK)) {
            strFail = "The residual does not pay this house's redemption key!"; return false;
        }
    }

    // Counter-sign: our quorum + our presenter (we present the OTHER house's
    // issue, so our presenter slot is the ctpy-issued side's key).
    const CTransaction ctxDigest(mtx);
    const uint256 sighash = SettleExchangeSigHash(x, SettleHashPrevouts(ctxDigest), BillHashOutputs(ctxDigest));
    {
        std::vector<uint32_t>& vIdx = fSignA ? x.vApproverIndexA : x.vApproverIndexB;
        std::vector<std::vector<unsigned char>>& vSig = fSignA ? x.vApproverSigA : x.vApproverSigB;
        vIdx.clear(); vSig.clear();
        if (!SignSettleApprovers(this, houseOwn, sighash, vIdx, vSig, strFail))
            return false;
    }
    const std::vector<unsigned char>& vchPresentKey = fSignA ? x.vchPresentKeyOfBNotes : x.vchPresentKeyOfANotes;
    std::vector<unsigned char>& vchPresentSig = fSignA ? x.vchPresentSigOfBNotes : x.vchPresentSigOfANotes;
    {
        CKey keyPresent;
        if (!GetKey(CPubKey(vchPresentKey).GetID(), keyPresent)) { strFail = "Presenter key missing from this wallet!"; return false; }
        if (!keyPresent.Sign(sighash, vchPresentSig)) { strFail = "Failed to sign as presenter!"; return false; }
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << x;
    mtx.vchSettlePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // scriptSig-sign OUR bundle region (the ctpy-issued side): positions are
    // [0, countA) for the A-issued bundle, [countA, countA+countB) for B's.
    const CTransaction txToSign(mtx);
    const size_t nStart = fSignA ? x.nCountANotes : 0;
    const size_t nCount = fSignA ? x.nCountBNotes : x.nCountANotes;
    const CScript scriptMine = NoteScriptForPubKey(vchPresentKey);
    for (size_t k = 0; k < nCount; k++) {
        const size_t nIn = nStart + k;
        if (nIn >= mtx.vin.size()) { strFail = "Truncated bundle region!"; return false; }
        if (!mtx.vin[nIn].scriptSig.empty())
            continue;
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, (unsigned int)nIn, NOTE_DUST_VALUE, SIGHASH_ALL), scriptMine, sigdata)) {
            strFail = "Signing our bundle inputs failed!"; return false;
        }
        UpdateTransaction(mtx, (unsigned int)nIn, sigdata);
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CReserveKey reserveKey(this);
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit settle! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}


//
// Phase 3.9 (B1) - the discount ceremony, recourse, and the house-held twins of
// RETIRE / CLAIM. All of it lives here rather than beside the shipped bill ops
// because all of it needs SignHouseApprovers (the M-of-N gather) and
// HouseStateChangePending (the one-op-per-house fail-fast), both defined above
// this point and below those.
//

/** Gather the rho-at-mint reserve proof set (R-i7 / DR-1) and the DISJOINT
 * funding pool it must not spend.
 *
 * Prove the FEWEST LARGEST plain single-key candidates that cover needUnits, and
 * fund from what is left. Both halves are load-bearing: proving everything
 * sweeps the small coins into the proof set and starves the transaction of
 * anything to pay dust + fee with, and VerifyReserveProofs rejects outright a
 * transaction that spends a coin it proves ("-spends-reserve").
 *
 * MintNote and AttestHouse still carry their own inline copies of this. Routing
 * them through it is a shipped-path refactor, tracked as A8 rather than done
 * mid-B1 - and unlike the coin tagger, a drifted copy here fails LOUDLY (at
 * ATMP, on a reject string) because consensus re-verifies every proof itself. */
static bool GatherHouseReserveProofs(CWallet* pwallet, const CHouse& house, uint64_t needUnits,
                                     uint32_t nAsOfHeight, const uint256& hashAsOf, int nNextH,
                                     std::vector<AttestProof>& vProofsOut,
                                     std::vector<COutput>& vFeePoolOut,
                                     CAmount& amountProvenOut, std::string& strFail)
{
    vProofsOut.clear();
    vFeePoolOut.clear();
    amountProvenOut = 0;

    std::vector<COutput> vCoins;
    pwallet->AvailableCoins(vCoins, true /* fOnlySafe */);

    struct ReserveCand { COutPoint outpoint; CTxOut txout; CKeyID keyid; };
    std::vector<ReserveCand> vCand;
    for (const COutput& out : vCoins) {
        const COutPoint outpoint(out.tx->GetHash(), out.i);
        const CTxOut& txout = out.tx->tx->vout[out.i];
        Coin coin;
        bool fReserve = out.nDepth >= 1 && out.fSpendable &&
                pcoinsTip->GetCoin(outpoint, coin) && !coin.IsSpent() &&
                coin.nHeight <= nAsOfHeight &&
                !(coin.fBitAsset || coin.fBitAssetControl || coin.fBill ||
                  coin.fBillEscrow || coin.fHouseEscrow || coin.fNote) &&
                !(coin.IsCoinBase() && nNextH - (int)coin.nHeight < COINBASE_MATURITY);
        CKeyID keyid;
        if (fReserve) {
            CTxDestination dest;
            fReserve = ExtractDestination(txout.scriptPubKey, dest);
            if (fReserve) {
                if (const CKeyID* id = boost::get<CKeyID>(&dest)) keyid = *id;
                else if (const WitnessV0KeyHash* wid = boost::get<WitnessV0KeyHash>(&dest)) keyid = CKeyID(*wid);
                else fReserve = false;
            }
            CKey probe;
            if (fReserve) fReserve = pwallet->GetKey(keyid, probe);
            if (fReserve)
                fReserve = txout.scriptPubKey == GetScriptForDestination(keyid) ||
                           txout.scriptPubKey == GetScriptForDestination(WitnessV0KeyHash(keyid));
        }
        if (fReserve) { ReserveCand c; c.outpoint = outpoint; c.txout = txout; c.keyid = keyid; vCand.push_back(c); }
        else vFeePoolOut.push_back(out);
    }
    std::sort(vCand.begin(), vCand.end(),
        [](const ReserveCand& a, const ReserveCand& b) { return a.txout.nValue > b.txout.nValue; });

    size_t nProven = 0;
    for (; nProven < vCand.size() && nProven < MAX_ATTEST_PROOFS; nProven++) {
        if (((uint64_t)amountProvenOut * 100) / HOUSE_RESERVE_FLOOR_PCT >= needUnits)
            break;
        const ReserveCand& c = vCand[nProven];
        CKey key;
        if (!pwallet->GetKey(c.keyid, key)) { strFail = "Lost a reserve key mid-build!"; return false; }
        AttestProof proof;
        proof.outpoint = c.outpoint;
        const CPubKey pub = key.GetPubKey();
        proof.vchPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
        const uint256 challenge = HouseAttestChallenge(house.houseID, nAsOfHeight, hashAsOf, c.outpoint);
        if (!key.Sign(challenge, proof.vchSig)) { strFail = "Failed to sign a reserve proof!"; return false; }
        vProofsOut.push_back(proof);
        amountProvenOut += c.txout.nValue;
    }
    // The unproven (smaller) candidates rejoin the fee pool.
    std::set<COutPoint> setProven;
    for (const AttestProof& pr : vProofsOut) setProven.insert(pr.outpoint);
    for (size_t i = nProven; i < vCand.size(); i++) {
        const COutPoint& op = vCand[i].outpoint;
        if (setProven.count(op))
            continue;
        for (const COutput& out : vCoins) {
            if (COutPoint(out.tx->GetHash(), out.i) == op) { vFeePoolOut.push_back(out); break; }
        }
    }
    // Shape check 10 refuses an empty proof set before any DB read, so catch it
    // here with a diagnosis rather than as an opaque commit failure.
    if (vProofsOut.empty()) {
        strFail = "The house holds no confirmed plain reserve coin to prove - a discount MINTS, "
                  "so the rho-at-mint proof set can never be empty!";
        return false;
    }
    return true;
}

bool CWallet::ProposeDiscount(std::string& strFail, std::string& strHexOut, uint32_t nBillID,
                              uint32_t nHouseID, const CAmount& amountPrice, uint32_t nExpiryBlocks)
{
    strFail = "Unknown error!";
    strHexOut.clear();
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    if (nBillID == 0 || nHouseID == 0) { strFail = "Bill id and house id must both be nonzero!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CBill bill;
    if (!pbilltree->GetBill(nBillID, bill)) { strFail = "Unknown bill!"; return false; }
    if (bill.status != BILL_STATUS_ACTIVE) { strFail = "Bill is not active!"; return false; }
    if (bill.nOwnerHouseID != 0) {
        strFail = strprintf("Bill %u is already in house %u's loan book - it can only leave by HRETIRE or HCLAIM!",
                            nBillID, bill.nOwnerHouseID);
        return false;
    }
    const int nNextHeight = chainActive.Height() + 1;
    if ((uint32_t)nNextHeight >= bill.nMaturityHeight) {
        strFail = "Bill has matured - a discount buys UNMATURED paper (present it for payment instead)!";
        return false;
    }

    // We must be the seller: the discount's title spend and both seller
    // signatures come from the holder key.
    CKey keyProbe;
    if (!GetKey(CPubKey(bill.vchHolderPubKey).GetID(), keyProbe)) {
        strFail = "This wallet does not hold the bill (holder key missing) - propose from the SELLER's wallet!";
        return false;
    }

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, nNextHeight) != HOUSE_STATUS_OPEN) {
        strFail = "House is not effectively open - a stressed or deferred house may not expand its book!";
        return false;
    }
    // Shape check 4: the custody key may not sell to itself.
    if (bill.vchHolderPubKey == house.vchRedemptionDestPK) {
        strFail = "This house's own custody key holds the bill - a house cannot buy paper from itself!";
        return false;
    }
    if (amountPrice <= 0 || amountPrice > bill.amount) {
        strFail = strprintf("Price must be positive and at or below the face (%d sats) - a house may never book a bill above face!",
                            (int64_t)bill.amount);
        return false;
    }

    DiscountProposalV1 prop;
    prop.nBillID = nBillID;
    prop.nHouseID = nHouseID;
    prop.amountPrice = amountPrice;
    prop.vchSellerPubKey = bill.vchHolderPubKey;
    prop.outTitle = bill.outTitle;
    prop.nExpiryHeight = (uint32_t)chainActive.Height() +
            (nExpiryBlocks ? nExpiryBlocks : BILL_DISCOUNT_MAX_EXPIRY_AHEAD / 4);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << prop;
    strHexOut = HexStr(ss.begin(), ss.end());
    return true;
}

bool CWallet::SignDiscount(std::string& strFail, std::string& strHexTxOut,
                           const std::string& strHexProposal, const CAmount& nFee)
{
    strFail = "Unknown error!";
    strHexTxOut.clear();
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    DiscountProposalV1 prop;
    if (!IsHex(strHexProposal)) { strFail = "Proposal is not hex!"; return false; }
    try {
        std::vector<unsigned char> vch = ParseHex(strHexProposal);
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> prop;
        if (!ss.empty()) { strFail = "Trailing bytes in proposal!"; return false; }
    } catch (const std::exception&) { strFail = "Undecodable proposal!"; return false; }
    if (prop.nVersion != 1) { strFail = "Unknown proposal version!"; return false; }
    if (prop.nBillID == 0 || prop.nHouseID == 0 || prop.amountPrice <= 0) {
        strFail = "Malformed proposal!"; return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // This fail-fast is the layer that tells the OPERATOR. ATMP now carries the
    // slot guard too (◄T-d5, the mirror guard keyed on GetHouseSlotIDs both
    // sides), but CommitTransaction returns true unconditionally, so without
    // this check the collision would surface to the caller as a successful
    // txid for a transaction that was never admitted. Both layers are
    // load-bearing: this one for the message, ATMP's for every other
    // implementation and for hostile peers.
    if (HouseStateChangePending(prop.nHouseID)) {
        strFail = "A house-state-changing op for this house is already in the mempool "
                  "(a second one would brick our own BMM template) - retry next block!";
        return false;
    }

    const int nNextHeight = chainActive.Height() + 1;

    CBill bill;
    if (!pbilltree->GetBill(prop.nBillID, bill)) { strFail = "Unknown bill!"; return false; }
    if (bill.status != BILL_STATUS_ACTIVE) { strFail = "Bill is not active!"; return false; }
    if (bill.nOwnerHouseID != 0) {
        strFail = strprintf("Bill %u is already in house %u's loan book!", prop.nBillID, bill.nOwnerHouseID);
        return false;
    }
    if ((uint32_t)nNextHeight >= bill.nMaturityHeight) { strFail = "Bill has matured!"; return false; }
    // The proposal is unsigned, so every one of its claims is re-derived from
    // the record here; only the price and the expiry are the seller's to set.
    if (prop.vchSellerPubKey != bill.vchHolderPubKey) {
        strFail = "Proposal's seller key is not the bill's current holder - the offer is stale!";
        return false;
    }
    if (prop.outTitle != bill.outTitle) {
        strFail = "Proposal's title outpoint does not match the record - the offer is stale!";
        return false;
    }
    if (prop.amountPrice > bill.amount) {
        strFail = "Proposed price exceeds the bill's face - a house may never book a bill above face!";
        return false;
    }

    CHouse house;
    if (!phousetree->GetHouse(prop.nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, nNextHeight) != HOUSE_STATUS_OPEN) {
        strFail = "House is not effectively open (stressed/deferred/insolvent/wounddown) - discounting blocked!";
        return false;
    }
    if ((uint32_t)nNextHeight < house.nLastAttestHeight ||
            (uint32_t)nNextHeight - house.nLastAttestHeight > HOUSE_ATTEST_CADENCE) {
        strFail = "Attestation is stale - attest the house's reserves before discounting!";
        return false;
    }
    if (bill.vchHolderPubKey == house.vchRedemptionDestPK) {
        strFail = "This house's own custody key holds the bill - a house cannot buy paper from itself!";
        return false;
    }

    // -- consensus fail-fasts, in check order ---------------------------------
    const uint64_t nPrice = (uint64_t)prop.amountPrice;
    if (house.nMintedUnits > (uint64_t)MAX_MONEY - nPrice ||
            house.nMintedUnits + nPrice > (uint64_t)MAX_MONEY - house.nDepositUnits ||
            house.nMintedUnits + nPrice + house.nDepositUnits > HouseCapitalCapUnits(house)) {
        strFail = "Discount would exceed the capital cap (N + D + price <= lambda * active escrow)!";
        return false;
    }
    if (house.nLoanBookFace > LOAN_BOOK_MAX_FACE - (uint64_t)bill.amount) {
        strFail = "Discount would overflow the loan-book envelope!";
        return false;
    }
    // Tx-4's endorsement fee floor: a discount IS an endorsement.
    const CAmount nFeeFloor = BillEndorseFeeFloor(bill.vEndorsement.size() + 1);
    if (nFee < nFeeFloor) {
        strFail = strprintf("Fee %d is below the endorsement fee floor %d for a chain of %u links!",
                            (int64_t)nFee, (int64_t)nFeeFloor, (unsigned)(bill.vEndorsement.size() + 1));
        return false;
    }

    // -- reserve proofs, and the disjoint funding pool -------------------------
    const uint32_t nAsOfHeight = (uint32_t)chainActive.Height();
    const uint256 hashAsOf = chainActive.Tip()->GetBlockHash();
    std::vector<AttestProof> vReserveProofs;
    std::vector<COutput> vFeePool;
    CAmount amountProven = 0;
    if (!GatherHouseReserveProofs(this, house, house.nMintedUnits + nPrice, nAsOfHeight, hashAsOf,
                                  nNextHeight, vReserveProofs, vFeePool, amountProven, strFail))
        return false;
    const CAmount amountEffReserves = std::min(house.amountLastAttestReserves, amountProven);
    if (house.nMintedUnits + nPrice > ((uint64_t)amountEffReserves * 100) / HOUSE_RESERVE_FLOOR_PCT) {
        strFail = "Discount would exceed the reserve cap (N + price <= min(attested, live) reserves / rho) - "
                  "attest and hold more liquid reserve coins first!";
        return false;
    }

    // -- match funding on the POST state (check 22) ----------------------------
    // Derived and self-curing, but a silent reject otherwise: consensus applies
    // the deltas and then tests, so the fail-fast must do exactly the same.
    {
        CHouse post = house;
        post.nMintedUnits += nPrice;
        post.nLoanBookFace += (uint64_t)bill.amount;
        post.SetLoanWtMaturity(post.LoanWtMaturity() +
                (unsigned __int128)(uint64_t)bill.amount * (unsigned __int128)bill.nMaturityHeight);
        if (!HouseMatchFundingOK(post, nNextHeight)) {
            strFail = "Discount would leave the house funding a longer book with shorter money "
                      "(match funding) - lengthen deposits or let the book run off first!";
            return false;
        }
    }

    // -- build the transaction: inputs AND outputs final before ANY signature --
    // The shared digest binds hashPrevouts and hashOutputs, so unlike AttestHouse
    // (whose digest binds outputs only) nothing may be appended after signing.
    BillDiscount d;
    d.nBillID = prop.nBillID;
    d.nHouseID = prop.nHouseID;
    d.amountPrice = prop.amountPrice;
    d.amountFace = bill.amount;
    d.nBillMaturityHeight = bill.nMaturityHeight;
    // One note coin for the whole price. The seller splits it with transfernote
    // if they want to; minting a fixed fan-out here would only guess wrong.
    d.nNoteOutputs = 1;
    d.vUnits.push_back(nPrice);
    d.vchCustodyPubKey = house.vchRedemptionDestPK;
    d.nExpiryHeight = prop.nExpiryHeight;
    if (d.nExpiryHeight == 0 ||
            (uint64_t)d.nExpiryHeight > (uint64_t)nNextHeight + BILL_DISCOUNT_MAX_EXPIRY_AHEAD ||
            (uint32_t)nNextHeight > d.nExpiryHeight) {
        strFail = "Proposal expiry is absent, already passed, or too far ahead - ask for a fresh proposal!";
        return false;
    }
    d.nAsOfHeight = nAsOfHeight;
    d.vReserveProofs = vReserveProofs;
    d.nPrevMintedUnits = house.nMintedUnits;
    d.nPrevLoanBookFace = house.nLoanBookFace;
    d.nPrevLoanWtMatHi = house.nLoanWtMatHi;
    d.nPrevLoanWtMatLo = house.nLoanWtMatLo;
    // The stored link is the CLASSIC endorsement, so the chain stays verifiable
    // from CBill alone. Its height and signature are the SELLER's to set in
    // round 3 (the shared digest excludes the whole endorsement, so patching it
    // later cannot invalidate our quorum signature), which also keeps the
    // BILL_ENDORSE_HEIGHT_SLACK window as fresh as possible.
    d.endorsement.vchFrom = bill.vchHolderPubKey;
    d.endorsement.vchTo = house.vchRedemptionDestPK;

    const CScript scriptSeller = BillScriptForPubKey(bill.vchHolderPubKey);

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_DISCOUNT;

    // vout[0] = the title into custody, vout[1..n] = the priced note leg to the
    // seller. The layout is PINNED by the shape gate, so change is appended
    // last and explicitly - CreateTransaction's random change position would
    // land inside it and produce a signed transaction that can never confirm.
    mtx.vout.push_back(CTxOut(BILL_TITLE_VALUE, BillScriptForPubKey(house.vchRedemptionDestPK)));
    for (size_t i = 0; i < d.vUnits.size(); i++)
        mtx.vout.push_back(CTxOut(NOTE_DUST_VALUE, scriptSeller));

    // The title passes through at par, so funding covers the note dust + fee.
    const CAmount nTarget = NOTE_DUST_VALUE * (CAmount)d.nNoteOutputs + nFee;
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vFeePool, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not fund the note dust + fee separately from the reserve proof - "
                  "the house needs a spare liquid coin the discount is not proving as reserve!";
        return false;
    }
    // Change is drawn with GetKeyFromPool, not CReserveKey, because it may have
    // to be re-keyed: CReserveKey reserves ONCE and hands back the same pubkey on
    // every later call, so a collision loop over it would spin on one key.
    // reserveKey exists only to satisfy CommitTransaction (the ClaimBillEscrow
    // precedent).
    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey pubChange;
        CTxOut outChange;
        // Check 16's no-side-payment rule rejects ANY output past the note leg
        // paying the seller. In a single-wallet regtest - and on the demo - both
        // keys come out of one keypool, so re-key rather than emit a transaction
        // both parties will sign and consensus will refuse.
        for (int nTry = 0; nTry < 8; nTry++) {
            if (!GetKeyFromPool(pubChange)) { strFail = "Keypool ran out, please call keypoolrefill first!"; return false; }
            outChange = CTxOut(nChange, GetScriptForDestination(pubChange.GetID()));
            if (outChange.scriptPubKey != scriptSeller)
                break;
        }
        if (outChange.scriptPubKey == scriptSeller) {
            strFail = "Could not find a change key distinct from the seller's - keypoolrefill and retry!";
            return false;
        }
        if (!IsDust(outChange, ::dustRelayFee))
            mtx.vout.push_back(outChange);
    }

    // vin[0] = the title (the SELLER signs this one in round 3), then our funding.
    mtx.vin.push_back(CTxIn(bill.outTitle.hash, bill.outTitle.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // -- our authority: the house quorum over the shared digest ----------------
    {
        const CTransaction ctxDigest(mtx);
        const uint256 sighash = BillDiscountSigHash(d, bill.billID,
                BillHashPrevouts(ctxDigest), BillHashOutputs(ctxDigest));
        if (!SignHouseApprovers(this, house, sighash, d.vApproverIndex, d.vApproverSig, strFail))
            return false;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << d;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // scriptSig-sign OUR funding inputs only. The legacy sighash covers neither
    // the v11 trailer nor another input's scriptSig, so round 3 may patch the
    // payload and sign vin[0] without invalidating any of these.
    const CTransaction txToSign(mtx);
    unsigned int nIn = 1;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing the house's funding inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    strHexTxOut = EncodeHexTx(CTransaction(mtx));
    return true;
}

bool CWallet::CompleteDiscount(std::string& strFail, uint256& txidOut, const std::string& strHexTx)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, strHexTx, true)) { strFail = "Undecodable transaction!"; return false; }
    if (mtx.nVersion != TRANSACTION_BILL_VERSION || mtx.nBillOp != BILL_OP_DISCOUNT) {
        strFail = "Not a bill discount transaction!"; return false;
    }
    BillDiscount d;
    if (!DecodeBillPayload(mtx.vchBillPayload, d)) { strFail = "Undecodable discount payload!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    const int nNextHeight = chainActive.Height() + 1;

    CBill bill;
    if (!pbilltree->GetBill(d.nBillID, bill)) { strFail = "Unknown bill!"; return false; }
    if (bill.status != BILL_STATUS_ACTIVE) { strFail = "Bill is not active!"; return false; }
    if (bill.nOwnerHouseID != 0) {
        strFail = strprintf("Bill %u is already in house %u's loan book!", d.nBillID, bill.nOwnerHouseID);
        return false;
    }
    if ((uint32_t)nNextHeight >= bill.nMaturityHeight) { strFail = "Bill has matured!"; return false; }

    // We are the seller. Everything below re-derives the house's claims from the
    // chain: this is the ONLY point at which the seller is protected, because
    // the round-1 proposal carried no signature of ours.
    CKey keyHolder;
    if (!GetKey(CPubKey(bill.vchHolderPubKey).GetID(), keyHolder)) {
        strFail = "This wallet does not hold the bill (holder key missing) - complete from the SELLER's wallet!";
        return false;
    }
    if (d.endorsement.vchFrom != bill.vchHolderPubKey) {
        strFail = "The transaction endorses from a key that is not the current holder!"; return false;
    }
    CHouse house;
    if (!phousetree->GetHouse(d.nHouseID, house)) { strFail = "Unknown buying house!"; return false; }
    if (d.vchCustodyPubKey != house.vchRedemptionDestPK ||
            d.endorsement.vchTo != house.vchRedemptionDestPK) {
        strFail = "The title would not land on house's consensus-known custody key - REFUSING to sign!";
        return false;
    }
    if (d.amountFace != bill.amount || d.nBillMaturityHeight != bill.nMaturityHeight) {
        strFail = "The transaction states a face or maturity that is not this bill's - REFUSING to sign!";
        return false;
    }
    if (d.amountPrice <= 0 || d.amountPrice > d.amountFace) {
        strFail = "Price is out of range!"; return false;
    }

    // The money. Check 16 requires every unit of the price to reach the seller
    // and nothing else in the transaction to pay them; verifying it here is what
    // keeps "the seller walks away with working capital" true rather than
    // assumed. vout[0] is the title and is exempt by construction.
    const CScript scriptSeller = BillScriptForPubKey(bill.vchHolderPubKey);
    if (mtx.vout.size() < (size_t)1 + d.nNoteOutputs ||
            (size_t)d.nNoteOutputs != d.vUnits.size()) {
        strFail = "Malformed note leg!"; return false;
    }
    uint64_t nUnitsToSeller = 0;
    for (size_t j = 1; j <= (size_t)d.nNoteOutputs; j++) {
        if (mtx.vout[j].nValue != NOTE_DUST_VALUE) { strFail = "A note output is not at the dust base!"; return false; }
        if (mtx.vout[j].scriptPubKey == scriptSeller)
            nUnitsToSeller += d.vUnits[j - 1];
    }
    if (nUnitsToSeller != (uint64_t)d.amountPrice) {
        strFail = strprintf("The note leg pays this wallet %d of the %d units offered - REFUSING to sign!",
                            nUnitsToSeller, (int64_t)d.amountPrice);
        return false;
    }
    for (size_t j = (size_t)d.nNoteOutputs + 1; j < mtx.vout.size(); j++) {
        if (mtx.vout[j].scriptPubKey == scriptSeller) {
            strFail = "An output past the note leg also pays the seller - consensus rejects this as a "
                      "side payment (the house must re-key its change and re-sign)!";
            return false;
        }
    }
    if (mtx.vout[0].nValue != BILL_TITLE_VALUE ||
            mtx.vout[0].scriptPubKey != BillScriptForPubKey(d.vchCustodyPubKey)) {
        strFail = "The title output is malformed!"; return false;
    }
    if (mtx.vin.empty() || mtx.vin[0].prevout != bill.outTitle) {
        strFail = "vin[0] is not this bill's title outpoint!"; return false;
    }

    // Both clocks the house started in round 2 can run out while the proposal
    // sits with us; neither would be surfaced by CommitTransaction.
    if (d.nAsOfHeight >= (uint32_t)nNextHeight ||
            (uint32_t)nNextHeight - d.nAsOfHeight > HOUSE_ATTEST_STALENESS) {
        strFail = "The house's reserve proof is stale - ask for a fresh signdiscount!";
        return false;
    }
    if ((uint32_t)nNextHeight > d.nExpiryHeight) {
        strFail = "This discount has expired - ask for a fresh signdiscount!"; return false;
    }
    for (const AttestProof& p : d.vReserveProofs) {
        Coin coin;
        if (!pcoinsTip->GetCoin(p.outpoint, coin) || coin.IsSpent()) {
            strFail = "A coin the house proves as reserve has been spent - ask for a fresh signdiscount!";
            return false;
        }
    }
    // The house checked this in round 2, but rounds are separated in time and it
    // is US who broadcast. A v11 op co-pooling with another op of the same house
    // bricks that house's own BMM template, and nothing downstream would say so.
    if (HouseStateChangePending(d.nHouseID)) {
        strFail = "A house-state-changing op for the buying house is now in the mempool "
                  "(broadcasting would brick its BMM template) - retry next block!";
        return false;
    }

    // -- our two signatures ---------------------------------------------------
    // The link first: the classic endorse digest, which the shared digest does
    // NOT cover, so its height stays ours to set as late as possible.
    d.endorsement.nAtHeight = (uint32_t)chainActive.Height();
    if (!keyHolder.Sign(BillEndorseSigHash(bill.billID, d.endorsement.vchTo, d.endorsement.nAtHeight),
                        d.endorsement.vchSig)) {
        strFail = "Failed to sign the endorsement link!"; return false;
    }
    {
        const CTransaction ctxDigest(mtx);
        const uint256 sighash = BillDiscountSigHash(d, bill.billID,
                BillHashPrevouts(ctxDigest), BillHashOutputs(ctxDigest));
        if (!keyHolder.Sign(sighash, d.vchSellerSig)) {
            strFail = "Failed to sign the discount!"; return false;
        }
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << d;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // Finally the title input. The house's funding scriptSigs are untouched:
    // SIGHASH_ALL blanks every other input's scriptSig, and the legacy sighash
    // does not reach the v11 trailer we just rewrote.
    {
        const CTransaction txToSign(mtx);
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, 0, BILL_TITLE_VALUE, SIGHASH_ALL), scriptSeller, sigdata)) {
            strFail = "Signing the title input failed!"; return false;
        }
        UpdateTransaction(mtx, 0, sigdata);
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CReserveKey reserveKey(this);
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the discount! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::RecourseBill(std::string& strFail, uint256& txidOut, const uint32_t nBillID, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CBill bill;
    if (!pbilltree->GetBill(nBillID, bill)) { strFail = "Unknown bill!"; return false; }
    // Check 30: a bill in a loan book leaves it only through HRETIRE or HCLAIM.
    if (bill.nOwnerHouseID != 0) {
        strFail = strprintf("Bill %u is house-held (house %u) - recourse is never legal on paper in a loan book!",
                            nBillID, bill.nOwnerHouseID);
        return false;
    }
    if (bill.status != BILL_STATUS_ACTIVE && bill.status != BILL_STATUS_DEFAULTED) {
        strFail = "Bill is neither active nor defaulted - nothing to take recourse on!"; return false;
    }
    const int nNextHeight = chainActive.Height() + 1;
    if (bill.status == BILL_STATUS_ACTIVE &&
            (uint64_t)nNextHeight <= (uint64_t)bill.nMaturityHeight + bill.nGraceBlocks) {
        strFail = "Bill has not passed maturity + grace yet - recourse cures a DISHONOURED bill!"; return false;
    }

    // The liable set (check 32), computed exactly as consensus does: the drawer,
    // plus every endorser up to and INCLUDING the link that delivered the bill to
    // the current holder. A holder who arrived by an earlier recourse has no
    // delivering link, so the whole chain answers. The acceptor is deliberately
    // out: its escrow bond already answers, and including it enabled a
    // default-then-self-recourse expropriation (E-1).
    size_t nLiableEnd = bill.vEndorsement.size();
    for (size_t j = bill.vEndorsement.size(); j-- > 0; ) {
        if (bill.vEndorsement[j].vchTo == bill.vchHolderPubKey) { nLiableEnd = j + 1; break; }
    }
    std::vector<std::vector<unsigned char>> vLiable;
    vLiable.push_back(bill.vchDrawerPubKey);
    for (size_t j = 0; j < nLiableEnd; j++)
        vLiable.push_back(bill.vEndorsement[j].vchFrom);

    std::vector<unsigned char> vchPayer;
    CKey keyPayer;
    for (const std::vector<unsigned char>& vch : vLiable) {
        if (vch == bill.vchHolderPubKey)
            continue;   // one key paying itself is not a cure (check 31)
        CKey key;
        if (GetKey(CPubKey(vch).GetID(), key)) { vchPayer = vch; keyPayer = key; break; }
    }
    if (vchPayer.empty()) {
        strFail = "This wallet holds no key in the bill's liable set (drawer, or an endorser up to the "
                  "one that delivered it to the holder)!";
        return false;
    }

    // The floor (check 33) must beat the holder's best alternative under the
    // WHOLE op set, which is why it differs by status.
    CAmount amountFloor = 0;
    if (bill.status == BILL_STATUS_ACTIVE) {
        amountFloor = std::max(bill.amount, bill.amountEscrow);
    } else {
        if (bill.amount <= bill.amountEscrow) {
            strFail = "The escrow already covered the face - there is no deficiency to buy!"; return false;
        }
        amountFloor = bill.amount - bill.amountEscrow;
    }

    const CScript scriptHolder = BillScriptForPubKey(bill.vchHolderPubKey);

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_RECOURSE;

    // vout[0] = the cure, paid straight to the holder's key. No title spend and
    // no holder signature - that is what makes this work against an
    // uncooperative holder.
    mtx.vout.push_back(CTxOut(amountFloor, scriptHolder));

    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vCoins, amountFloor + nFee, setCoins, nAmountRet)) {
        strFail = "Could not fund the recourse payment + fee!"; return false;
    }
    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - amountFloor - nFee;
    if (nChange > 0) {
        CPubKey pubChange;
        CTxOut outChange;
        // BillValuePaidTo SUMS every output on the holder's script, so change
        // landing there is not rejected - it is simply given away. Re-keying
        // needs GetKeyFromPool: CReserveKey would hand back the same key.
        for (int nTry = 0; nTry < 8; nTry++) {
            if (!GetKeyFromPool(pubChange)) { strFail = "Keypool ran out, please call keypoolrefill first!"; return false; }
            outChange = CTxOut(nChange, GetScriptForDestination(pubChange.GetID()));
            if (outChange.scriptPubKey != scriptHolder)
                break;
        }
        if (outChange.scriptPubKey == scriptHolder) {
            strFail = "Could not find a change key distinct from the holder's - keypoolrefill and retry!";
            return false;
        }
        if (!IsDust(outChange, ::dustRelayFee))
            mtx.vout.push_back(outChange);
    }
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // The digest binds prevouts AND outputs, so both are final before we sign.
    BillRecourse r;
    r.nBillID = nBillID;
    r.vchPayerPubKey = vchPayer;
    r.vchPrevHolderPubKey = bill.vchHolderPubKey;
    {
        const CTransaction ctxDigest(mtx);
        if (!keyPayer.Sign(BillRecourseSigHash(r, bill.billID,
                BillHashPrevouts(ctxDigest), BillHashOutputs(ctxDigest)), r.vchPayerSig)) {
            strFail = "Failed to sign the recourse!"; return false;
        }
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << r;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign(mtx);
    unsigned int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing recourse inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the recourse! Reject reason: " + FormatStateMessage(state); return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::HouseHeldRetireBill(std::string& strFail, uint256& txidOut,
                                  const CBill& bill, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    if (HouseStateChangePending(bill.nOwnerHouseID)) {
        strFail = "A house-state-changing op for the owning house is already in the mempool - retry next block!";
        return false;
    }
    CHouse house;
    if (!phousetree->GetHouse(bill.nOwnerHouseID, house)) { strFail = "Unknown owning house!"; return false; }
    // No status gate, deliberately - matching consensus. The drawee must always
    // be able to discharge its debt, even into an insolvent house, and the
    // destination is consensus-pinned to that house's custody key.

    CKey keyAcceptor;
    if (!GetKey(CPubKey(bill.vchAcceptorPubKey).GetID(), keyAcceptor)) {
        strFail = "This wallet is not the bill's acceptor (drawee key missing)!";
        return false;
    }

    const CAmount nNeeded = bill.amount + nFee;
    const CAmount nTargetFunding = nNeeded > bill.amountEscrow ? nNeeded - bill.amountEscrow : CAmount(0);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (nTargetFunding > 0) {
        std::vector<COutput> vCoins;
        AvailableCoins(vCoins, true /* fOnlySafe */);
        if (!SelectCoins(vCoins, nTargetFunding, setCoins, nAmountRet)) {
            strFail = "Could not collect enough coins to pay the bill face + fee!"; return false;
        }
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_HRETIRE;

    // vout[0] = face to the current holder, which the discount pinned to the
    // house's custody key.
    const CScript scriptHolder = BillScriptForPubKey(bill.vchHolderPubKey);
    mtx.vout.push_back(CTxOut(bill.amount, scriptHolder));

    CReserveKey reserveKey(this);
    const CAmount nChange = bill.amountEscrow + nAmountRet - bill.amount - nFee;
    if (nChange < 0) { strFail = "Escrow + funding does not cover face + fee!"; return false; }
    if (nChange > 0) {
        CPubKey pubChange;
        CTxOut outChange;
        // BillValuePaidTo sums the holder's script, so change landing there is
        // not rejected - it is simply handed to the house. Re-keying needs
        // GetKeyFromPool: CReserveKey would hand back the same key.
        for (int nTry = 0; nTry < 8; nTry++) {
            if (!GetKeyFromPool(pubChange)) { strFail = "Keypool ran out, please call keypoolrefill first!"; return false; }
            outChange = CTxOut(nChange, GetScriptForDestination(pubChange.GetID()));
            if (outChange.scriptPubKey != scriptHolder)
                break;
        }
        if (outChange.scriptPubKey == scriptHolder) {
            strFail = "Could not find a change key distinct from the custody key - keypoolrefill and retry!";
            return false;
        }
        if (!IsDust(outChange, ::dustRelayFee))
            mtx.vout.push_back(outChange);
    }

    mtx.vin.push_back(CTxIn(bill.outEscrow.hash, bill.outEscrow.n, CScript()));
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    BillHRetire h;
    h.nBillID = bill.nBillID;
    h.nOwnerHouseID = bill.nOwnerHouseID;
    h.amountFace = bill.amount;
    h.nBillMaturityHeight = bill.nMaturityHeight;
    h.nPrevLoanBookFace = house.nLoanBookFace;
    h.nPrevLoanWtMatHi = house.nLoanWtMatHi;
    h.nPrevLoanWtMatLo = house.nLoanWtMatLo;
    // The shipped retire digest, unchanged: cross-op replay is already dead
    // because op 3 rejects house-held bills and op 7 requires them.
    if (!keyAcceptor.Sign(BillRetireSigHash(bill.billID, BillHashOutputs(mtx)), h.vchAcceptorSig)) {
        strFail = "Failed to sign the house-held retirement!"; return false;
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << h;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign(mtx);
    unsigned int nIn = 1;   // vin[0] is the escrow - empty scriptSig by design
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing retirement inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the house-held retirement! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::HouseHeldClaimBillEscrow(std::string& strFail, uint256& txidOut,
                                       const CBill& bill, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    if (HouseStateChangePending(bill.nOwnerHouseID)) {
        strFail = "A house-state-changing op for this house is already in the mempool - retry next block!";
        return false;
    }
    if ((uint64_t)chainActive.Height() + 1 <= (uint64_t)bill.nMaturityHeight + bill.nGraceBlocks) {
        strFail = "Bill has not passed maturity + grace yet!"; return false;
    }
    CHouse house;
    if (!phousetree->GetHouse(bill.nOwnerHouseID, house)) { strFail = "Unknown owning house!"; return false; }
    if (nFee <= 0 || nFee >= bill.amountEscrow) {
        strFail = "Fee must be positive and below the escrow value!"; return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_BILL_VERSION;
    mtx.nBillOp = BILL_OP_HCLAIM;

    mtx.vin.push_back(CTxIn(bill.outEscrow.hash, bill.outEscrow.n, CScript()));
    // The proceeds belong to the HOUSE, so they go to its consensus-known
    // custody key - not to a fresh key of whichever partner happened to run the
    // RPC. Consensus pins no destination here (the quorum signature binds the
    // output set, which is enough for it), so this is a wallet-layer choice:
    // the quorum authorizes, therefore the quorum's house is paid.
    mtx.vout.push_back(CTxOut(bill.amountEscrow - nFee, BillScriptForPubKey(house.vchRedemptionDestPK)));

    BillHClaim h;
    h.nBillID = bill.nBillID;
    h.nOwnerHouseID = bill.nOwnerHouseID;
    h.amountFace = bill.amount;
    h.nBillMaturityHeight = bill.nMaturityHeight;
    h.nPrevLoanBookFace = house.nLoanBookFace;
    h.nPrevLoanWtMatHi = house.nLoanWtMatHi;
    h.nPrevLoanWtMatLo = house.nLoanWtMatLo;
    // The QUORUM replaces op 4's single holder signature - the custody key alone
    // must never direct the escrow payout, nor take a bill out of the book.
    if (!SignHouseApprovers(this, house, BillClaimSigHash(bill.billID, BillHashOutputs(mtx)),
                            h.vApproverIndex, h.vApproverSig, strFail))
        return false;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << h;
    mtx.vchBillPayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CReserveKey reserveKey(this);
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the house-held escrow claim! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::RegisterHouse(std::string& strFail, uint256& txidOut, uint8_t nTier, uint32_t nThresholdM, const std::string& strClassID, uint64_t nDenomMgGold, const std::vector<CAmount>& vPledge, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }
    if (!IsValidHouseClassID(strClassID)) {
        strFail = "Invalid class id (lowercase [a-z0-9], 1-16 chars)!";
        return false;
    }
    if (vPledge.empty() || vPledge.size() > MAX_HOUSE_PARTNERS) {
        strFail = "Invalid partner count!";
        return false;
    }
    for (const CAmount& amount : vPledge) {
        if (amount < HOUSE_MIN_PLEDGE) {
            strFail = "Pledge below the consensus minimum!";
            return false;
        }
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    if (phousetree->HaveClassID(strClassID)) {
        strFail = "Class id already registered!";
        return false;
    }

    // Fresh key per partner + the redemption key (Tx-9 hygiene)
    HouseRegister reg;
    reg.nTier = nTier;
    reg.nThresholdM = nThresholdM;
    reg.strClassID = strClassID;
    reg.nDenomMgGold = nDenomMgGold;
    reg.vPledgeAmount = vPledge;

    CPubKey pubRedemption;
    if (!GetKeyFromPool(pubRedemption)) {
        strFail = "Keypool ran out, please call keypoolrefill first!";
        return false;
    }
    reg.vchRedemptionDestPK = std::vector<unsigned char>(pubRedemption.begin(), pubRedemption.end());

    std::vector<CKey> vPartnerKey;
    for (size_t i = 0; i < vPledge.size(); i++) {
        CPubKey pub;
        if (!GetKeyFromPool(pub)) {
            strFail = "Keypool ran out, please call keypoolrefill first!";
            return false;
        }
        CKey key;
        if (!GetKey(pub.GetID(), key)) {
            strFail = "Failed to load partner key!";
            return false;
        }
        reg.vPartnerPubKey.push_back(std::vector<unsigned char>(pub.begin(), pub.end()));
        vPartnerKey.push_back(key);
    }

    const uint256 declDigest = HouseDeclarationDigest(reg);
    for (size_t i = 0; i < vPartnerKey.size(); i++) {
        std::vector<unsigned char> vchSig;
        if (!vPartnerKey[i].Sign(HouseRegisterSigHash(declDigest, i, vPledge[i]), vchSig)) {
            strFail = "Failed to sign house registration!";
            return false;
        }
        reg.vPartnerSig.push_back(vchSig);
    }

    const uint256 houseID = HouseIDFromDeclaration(reg);

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_REGISTER;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << reg;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // vout[i] = partner i's pledge escrow
    CAmount nPledgeTotal = 0;
    for (const CAmount& amount : vPledge) {
        mtx.vout.push_back(CTxOut(amount, HouseEscrowScript(houseID)));
        nPledgeTotal += amount;
    }

    const CAmount nTarget = nPledgeTotal + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to fund the pledges + fee!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) {
            strFail = "Keypool ran out, please call keypoolrefill first!";
            return false;
        }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing house registration inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit house registration! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::TopupHouse(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const uint32_t nPartnerIndex, const CAmount& nAmount, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }
    if (nAmount <= 0) {
        strFail = "Invalid top-up amount!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) {
        strFail = "Unknown house!";
        return false;
    }
    // ◄A8 (2026-08-04): TOPUP takes the house's one-op-per-block slot but had NO
    // fail-fast, unlike every other slot-taking wallet op (MintNote, CreatePool,
    // RetirePool, settle, signdiscount, retirebill, claimbillescrow). An
    // operator topping up while any house op was pooled therefore built a tx
    // ATMP would refuse - and the refusal silently darkened their wallet (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op for this house is already in the mempool - retry next block!";
        return false;
    }
    {
        // Top-up is recovery capital: open at Open, Stressed AND Deferred
        // (restoring the house is the entire purpose of the suspension window).
        const char chEff = HouseEffectiveStatus(house, chainActive.Height() + 1);
        if ((chEff != HOUSE_STATUS_OPEN && chEff != HOUSE_STATUS_STRESSED &&
                chEff != HOUSE_STATUS_DEFERRED) || nPartnerIndex >= house.vPartner.size()) {
            strFail = "House closed or invalid partner index!";
            return false;
        }
    }

    CKey keyPartner;
    if (!GetKey(CPubKey(house.vPartner[nPartnerIndex].vchPubKey).GetID(), keyPartner)) {
        strFail = "This wallet does not hold that partner's key!";
        return false;
    }

    // The payload signature binds the full output set, so outputs (escrow +
    // change) are finalized before the payload is signed.
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_TOPUP;
    mtx.vout.push_back(CTxOut(nAmount, HouseEscrowScript(house.houseID)));

    const CAmount nTarget = nAmount + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to fund the top-up + fee!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) {
            strFail = "Keypool ran out, please call keypoolrefill first!";
            return false;
        }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    HouseTopup topup;
    topup.nHouseID = nHouseID;
    topup.nPartnerIndex = nPartnerIndex;
    const uint256 sighash = HouseTopupSigHash(house.houseID, nPartnerIndex, BillHashOutputs(mtx));
    if (!keyPartner.Sign(sighash, topup.vchSig)) {
        strFail = "Failed to sign house top-up!";
        return false;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << topup;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing house top-up inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit house top-up! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::AdmitPartner(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const CAmount& nPledge, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }
    if (nPledge < HOUSE_MIN_PLEDGE) {
        strFail = "Pledge below the consensus minimum!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) {
        strFail = "Unknown house!";
        return false;
    }
    if (HouseEffectiveStatus(house, chainActive.Height() + 1) != HOUSE_STATUS_OPEN || house.nTier != HOUSE_TIER_MULTI_PARTNER) {
        strFail = "House closed or not tier 3 (admission gate)!";
        return false;
    }
    // ◄A8: same as TOPUP above - ADMIT mutates the house record, so it takes the
    // slot and must not be built against a pooled op.
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op for this house is already in the mempool - retry next block!";
        return false;
    }

    CPubKey pubNew;
    if (!GetKeyFromPool(pubNew)) {
        strFail = "Keypool ran out, please call keypoolrefill first!";
        return false;
    }
    CKey keyNew;
    if (!GetKey(pubNew.GetID(), keyNew)) {
        strFail = "Failed to load new partner key!";
        return false;
    }

    HouseAdmit admit;
    admit.nHouseID = nHouseID;
    admit.vchNewPubKey = std::vector<unsigned char>(pubNew.begin(), pubNew.end());

    const uint256 sighash = HouseAdmitSigHash(house.houseID, admit.vchNewPubKey, nPledge);
    if (!keyNew.Sign(sighash, admit.vchNewSig)) {
        strFail = "Failed to sign admission (new partner)!";
        return false;
    }
    if (!SignHouseApprovers(this, house, sighash, admit.vApproverIndex, admit.vApproverSig, strFail))
        return false;

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_ADMIT;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << admit;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    mtx.vout.push_back(CTxOut(nPledge, HouseEscrowScript(house.houseID)));

    const CAmount nTarget = nPledge + nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to fund the pledge + fee!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    if (nChange > 0) {
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey)) {
            strFail = "Keypool ran out, please call keypoolrefill first!";
            return false;
        }
        CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing admission inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit admission! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::ExitPartner(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const uint32_t nPartnerIndex, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) {
        strFail = "Unknown house!";
        return false;
    }
    if (HouseEffectiveStatus(house, chainActive.Height() + 1) != HOUSE_STATUS_OPEN || nPartnerIndex >= house.vPartner.size()) {
        strFail = "House closed or invalid partner index!";
        return false;
    }
    if (house.nTier != HOUSE_TIER_MULTI_PARTNER) {
        strFail = "Individual exit is tier-3 only (tier-2 sets are fixed; solo houses wind down)!";
        return false;
    }
    if (house.ActivePartnerCount() - 1 < (int)house.nThresholdM) {
        strFail = "Exit would drop the house below its approval threshold - wind down instead!";
        return false;
    }

    CKey keyPartner;
    if (!GetKey(CPubKey(house.vPartner[nPartnerIndex].vchPubKey).GetID(), keyPartner)) {
        strFail = "This wallet does not hold that partner's key!";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_EXIT;

    // Fee-only funding; a dust marker output keeps the tx standard. Outputs are
    // finalized BEFORE the payload signature, which now binds BillHashOutputs.
    const CAmount nTarget = nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to pay the fee!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    CPubKey vchPubKey;
    if (!reserveKey.GetReservedKey(vchPubKey)) {
        strFail = "Keypool ran out, please call keypoolrefill first!";
        return false;
    }
    mtx.vout.push_back(CTxOut(nChange > 0 ? nChange : CAmount(546), GetScriptForDestination(vchPubKey.GetID())));

    HouseExit ex;
    ex.nHouseID = nHouseID;
    ex.nPartnerIndex = nPartnerIndex;
    const uint256 sighash = HouseExitSigHash(house.houseID, nPartnerIndex, BillHashOutputs(mtx));
    if (!keyPartner.Sign(sighash, ex.vchPartnerSig)) {
        strFail = "Failed to sign exit!";
        return false;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << ex;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing exit inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit exit! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::WinddownHouse(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) {
        strFail = "Unknown house!";
        return false;
    }
    if (HouseEffectiveStatus(house, chainActive.Height() + 1) != HOUSE_STATUS_OPEN) {
        strFail = "House is not effectively open!";
        return false;
    }
    // Fail-fast: a house cannot abandon outstanding liabilities - notes (N) OR
    // term deposits (D). Consensus enforces this via GetHouseLiabilities (N + D),
    // but CommitTransaction does not surface the ATMP rejection to the RPC caller,
    // so without this the RPC would hand back a txid for a tx that can never
    // confirm (and a wound-down house is neither Open for withdraw nor Insolvent
    // for claim, so its depositors would be orphaned).
    if (house.nMintedUnits != 0) {
        strFail = "House has notes outstanding; redeem them before winding down!";
        return false;
    }
    if (house.nDepositUnits != 0) {
        strFail = "House has term deposits outstanding; they must mature and be withdrawn before winding down!";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_WINDDOWN;

    // Outputs finalized before the approver signatures, which now bind
    // BillHashOutputs (freshness).
    const CAmount nTarget = nFee;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nTarget, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to pay the fee!";
        return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nTarget;
    CPubKey vchPubKey;
    if (!reserveKey.GetReservedKey(vchPubKey)) {
        strFail = "Keypool ran out, please call keypoolrefill first!";
        return false;
    }
    mtx.vout.push_back(CTxOut(nChange > 0 ? nChange : CAmount(546), GetScriptForDestination(vchPubKey.GetID())));

    HouseWinddown wd;
    wd.nHouseID = nHouseID;
    const uint256 sighash = HouseWinddownSigHash(house.houseID, BillHashOutputs(mtx));
    if (!SignHouseApprovers(this, house, sighash, wd.vApproverIndex, wd.vApproverSig, strFail))
        return false;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << wd;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing wind-down inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit wind-down! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

/** DEFER / RENEW share a shape: M-of-N approved, no escrow touched, one change
 * output, and the approver signature binds the exact output set. fRenew picks
 * the op. */
bool CWallet::BuildDeferOrRenew(std::string& strFail, uint256& txidOut,
                                const uint32_t nHouseID, const CAmount& nFee, bool fRenew)
{
    CWallet* const pwallet = this;
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }

    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }

    // Fail-fast mirrors of consensus (CommitTransaction does not surface an
    // ATMP rejection to the RPC caller).
    const int nNextHeight = chainActive.Height() + 1;
    const char chEff = HouseEffectiveStatus(house, nNextHeight);
    if (!fRenew) {
        if (chEff != HOUSE_STATUS_STRESSED) {
            strFail = "The option clause is a STRESSED-state tool: the house must be stressed "
                      "(and not already deferring, wound down, or insolvent).";
            return false;
        }
        if (HouseConfidenceDead(house, nNextHeight)) {
            strFail = "Confidence death: this house has already spent its option clause "
                      "(a second activation inside the window, or too much cumulative suspension).";
            return false;
        }
    } else {
        if (chEff != HOUSE_STATUS_DEFERRED) {
            strFail = "The house is not currently deferring - nothing to renew.";
            return false;
        }
        if (house.nDeferRenewals >= HOUSE_DEFER_MAX_RENEWALS) {
            strFail = "The one permitted renewal has already been used.";
            return false;
        }
        if (house.DeferSuspendedBlocks(nNextHeight) >= HOUSE_CD_MAX_SUSPENDED) {
            strFail = "Renewing would carry the house past the cumulative-suspension cap.";
            return false;
        }
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = fRenew ? HOUSE_OP_RENEW : HOUSE_OP_DEFER;

    // A DEFER must LOCK THE TILL (3.5 D11): vout[0] puts at least the house's
    // attested reserves into consensus custody, where the holders it has stopped
    // paying can reach them. Suspension is not free.
    const CAmount amountLock = fRenew ? 0 : house.amountLastAttestReserves;

    // Outputs finalized before the approver signatures (which bind them).
    std::vector<COutput> vCoins;
    pwallet->AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!pwallet->SelectCoins(vCoins, amountLock + nFee, setCoins, nAmountRet)) {
        strFail = fRenew ? "Could not collect enough coins to pay the fee!"
                         : "Could not fund the till lock: invoking the option clause requires locking "
                           "the house's ATTESTED reserves into consensus custody. Re-attest (truthfully, "
                           "lower) if the till has shrunk since the last attestation.";
        return false;
    }
    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - amountLock - nFee;
    CPubKey vchPubKey;
    if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
    if (!fRenew)
        mtx.vout.push_back(CTxOut(amountLock, HouseEscrowScript(house.houseID)));
    mtx.vout.push_back(CTxOut(nChange > 0 ? nChange : CAmount(546), GetScriptForDestination(vchPubKey.GetID())));

    // Inputs must be in place before the approver sighash: RENEW binds the tx
    // prevouts (anti-replay across deferral episodes), mirroring MINT/consensus.
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const uint256 hashOutputs = BillHashOutputs(mtx);
    const uint256 hashPrevouts = NoteHashPrevouts(mtx);
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    if (fRenew) {
        HouseRenew ren;
        ren.nHouseID = nHouseID;
        const uint256 sighash = HouseRenewSigHash(house.houseID, house.nDeferRenewals, hashPrevouts, hashOutputs);
        if (!SignHouseApprovers(pwallet, house, sighash, ren.vApproverIndex, ren.vApproverSig, strFail))
            return false;
        ssPayload << ren;
    } else {
        HouseDefer def;
        def.nHouseID = nHouseID;
        def.nPrevLastActivation = house.nDeferLastActivation;
        // Bind the anti-replay anchor (the prior activation height), NOT the
        // invocation height - see HouseDeferSigHash. A crisis tool must not be
        // valid in only one block.
        const uint256 sighash = HouseDeferSigHash(house.houseID, def.nPrevLastActivation, hashOutputs);
        if (!SignHouseApprovers(pwallet, house, sighash, def.vApproverIndex, def.vApproverSig, strFail))
            return false;
        ssPayload << def;
    }
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(pwallet);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!pwallet->CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = std::string(fRenew ? "Failed to commit renewal! " : "Failed to commit deferral! ")
                + "Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::DeferHouse(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const CAmount& nFee)
{
    return BuildDeferOrRenew(strFail, txidOut, nHouseID, nFee, false /* fRenew */);
}

bool CWallet::RenewDeferral(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const CAmount& nFee)
{
    return BuildDeferOrRenew(strFail, txidOut, nHouseID, nFee, true /* fRenew */);
}

bool CWallet::ReleaseReserves(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house!"; return false; }
    if (HouseEffectiveStatus(house, chainActive.Height() + 1) != HOUSE_STATUS_OPEN) {
        strFail = "The locked till is released only once the clause has been LIFTED - while the "
                  "house is stressed, suspended or insolvent it stays where the holders can reach it.";
        return false;
    }
    if (house.vOutReserveLock.empty()) { strFail = "Nothing is locked."; return false; }

    CAmount amountLocked = 0;
    std::vector<COutPoint> vSpend;
    {
        LOCK(mempool.cs);
        CCoinsViewMemPool viewMempool(pcoinsTip.get(), mempool);
        for (const COutPoint& out : house.vOutReserveLock) {
            Coin coin;
            if (viewMempool.GetCoin(out, coin) && !coin.IsSpent() && coin.fHouseEscrow) {
                vSpend.push_back(out);
                amountLocked += coin.out.nValue;
            }
        }
    }
    if (vSpend.empty() || amountLocked <= nFee) {
        strFail = "The locked till no longer covers the fee.";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_RELEASE;
    for (const COutPoint& out : vSpend)
        mtx.vin.push_back(CTxIn(out, CScript()));

    CReserveKey reserveKey(this);
    CPubKey vchPubKey;
    if (!reserveKey.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
    mtx.vout.push_back(CTxOut(amountLocked - nFee, GetScriptForDestination(vchPubKey.GetID())));

    HouseRelease rel;
    rel.nHouseID = nHouseID;
    const uint256 sighash = HouseReleaseSigHash(house.houseID, NoteHashPrevouts(mtx), BillHashOutputs(mtx));
    if (!SignHouseApprovers(this, house, sighash, rel.vApproverIndex, rel.vApproverSig, strFail))
        return false;
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << rel;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // Escrow inputs need no scriptSig (the guard + payload signature authorize).
    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the release! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

// ---------------------------------------------------------------------------
// Gold oracle (Phase G-1, T-o4). Consensus-INERT: these build and broadcast
// v17 ops that maintain the fix and the submitter records; nothing reads them.
// ---------------------------------------------------------------------------

/** True if the mempool holds an oracle op for nSubmitterID that the incoming op
 * cannot displace. Mirrors the ATMP slot guards exactly (validation.cpp): one
 * oracle op per submitter per block, EXCEPT that a newer SUBMIT displaces a
 * pooled SUBMIT for the same submitter - so for an incoming SUBMIT only a
 * pooled BOND blocks. Failing fast here beats an opaque CommitTransaction
 * reject (the house-review precedent). */
static bool OracleOpPending(uint32_t nSubmitterID, bool fIncomingSubmit)
{
    LOCK(mempool.cs);
    for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); mi++) {
        const CTransaction& mtx = mi->GetTx();
        if (mtx.nVersion != TRANSACTION_ORACLE_VERSION || mtx.vchOraclePayload.size() < 4)
            continue;
        uint32_t nTheirs = 0;
        memcpy(&nTheirs, mtx.vchOraclePayload.data(), 4);   // nSubmitterID leads both payloads
        if (nTheirs != nSubmitterID || nTheirs == 0)
            continue;
        if (fIncomingSubmit && mtx.nOracleOp == ORACLE_OP_SUBMIT)
            continue;                                       // displaceable, not blocking
        return true;
    }
    return false;
}

/** True if the mempool already holds a FRESH registration (id 0). Consensus
 * allows one per block, so a second would brick our own template. */
static bool OracleFreshBondPending()
{
    LOCK(mempool.cs);
    for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); mi++) {
        const CTransaction& mtx = mi->GetTx();
        if (mtx.nVersion != TRANSACTION_ORACLE_VERSION || mtx.nOracleOp != ORACLE_OP_BOND ||
                mtx.vchOraclePayload.size() < 4)
            continue;
        uint32_t nTheirs = 0;
        memcpy(&nTheirs, mtx.vchOraclePayload.data(), 4);
        if (nTheirs == 0)
            return true;
    }
    return false;
}

/** A v17 op survives up to nOracleOpWindow heights, so - unlike under the old
 * one-block rule - it is NOT stranded by the next tip change and its inputs
 * stay encumbered across several blocks. It leaves the pool when the window
 * exhausts, its branch moves, its priors are overtaken, or a re-sign displaces
 * it at ATMP. Any of those leaves this wallet holding an unconfirmed copy whose
 * inputs are still reserved - the AbandonDisplacedSettles wedge, which bites
 * harder here because a submitter re-signs every block. Free them: abandon any
 * of OUR unconfirmed v17 txs no longer in the mempool.
 *
 * Note this does NOT abandon a still-pooled predecessor, which is deliberate:
 * it may yet confirm inside its window. That is precisely why
 * CollectPlainOracleFunding must refuse to fund the next re-sign from its
 * change - chaining onto a tx that displacement is about to evict is the
 * node-abort path (see the ATMP displacement guard). */
static void AbandonStaleOracleOps(CWallet* pwallet)
{
    std::vector<uint256> vAbandon;
    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin();
            it != pwallet->mapWallet.end(); ++it) {
        CWalletTx& wtx = it->second;
        if (wtx.tx->nVersion != TRANSACTION_ORACLE_VERSION)
            continue;
        // Resync the cached flag from the POOL itself first: removal
        // notifications are scheduler-async, so a displaced op can carry a
        // stale fInMempool == true, which would also wedge AbandonTransaction
        // via its own InMempool() guard.
        {
            LOCK(mempool.cs);
            wtx.fInMempool = mempool.exists(it->first);
        }
        if (wtx.GetDepthInMainChain() != 0 || wtx.InMempool() || wtx.isAbandoned())
            continue;
        vAbandon.push_back(it->first);
    }
    for (const uint256& txid : vAbandon) {
        LogPrintf("%s: abandoning stale oracle op %s\n", __func__, txid.ToString());
        pwallet->AbandonTransaction(txid);
    }
}

/** Fund nTarget from PLAIN coins only. Oracle txs may not spend any tagged coin
 * (consensus: "bad-oracle-colored-input"), and the bond escrow itself is
 * anyone-can-spend so it never appears in AvailableCoins at all - it is reached
 * only through the submitter record's tracked outpoint. */
static void CollectPlainOracleFunding(CWallet* pwallet, std::vector<COutput>& vPlainOut)
{
    std::vector<COutput> vCoins;
    pwallet->AvailableCoins(vCoins, true);
    for (const COutput& out : vCoins) {
        if (!out.fSpendable)
            continue;
        // Tags live in the UTXO set, so they can only be READ for a CONFIRMED
        // coin. Do not require the lookup to succeed: an unconfirmed coin is
        // absent from pcoinsTip by definition, and dropping those starved every
        // oracle op in a wallet whose spare coins were still in the mempool -
        // which is the normal state on a chain making blocks every few seconds.
        // Unconfirmed coins are safe to accept here because AvailableCoins has
        // already skipped the tagged output classes that are IsMine (notes,
        // deposit receipts, pool/LP), and the bond escrow is anyone-can-spend so
        // it never appears in this list at all.
        // Never fund an oracle op from an UNCONFIRMED oracle op's change. Under
        // the validity window a predecessor survives in the mempool for up to k
        // blocks, and its own inputs are already spent-in-wallet, so this change
        // output is exactly what AvailableCoins would offer a re-sign. Chaining
        // onto it makes the re-sign a descendant of the tx the ATMP guard is
        // about to displace - which consensus now refuses outright, and which
        // used to abort the node. Keep the two ops independent so displacement
        // stays a clean swap.
        if (out.tx->tx->nVersion == TRANSACTION_ORACLE_VERSION &&
                out.tx->GetDepthInMainChain() == 0)
            continue;

        Coin coin;
        const COutPoint outpoint(out.tx->GetHash(), out.i);
        if (pcoinsTip->GetCoin(outpoint, coin) && !coin.IsSpent() &&
                (coin.fBitAsset || coin.fBitAssetControl || coin.fBill || coin.fBillEscrow ||
                 coin.fHouseEscrow || coin.fNote || coin.fDeposit || coin.fPoolEscrow ||
                 coin.fLpShare || coin.fOracleBond))
            continue;
        vPlainOut.push_back(out);
    }
}

static const char* ORACLE_FUNDING_FAIL =
    "Could not fund the oracle op from plain coins - the wallet needs a spare "
    "untagged coin (oracle txs cannot spend notes, escrow, receipts or bonds)!";

bool CWallet::BondOracleSubmitter(std::string& strFail, uint256& txidOut, uint32_t& nAssignedIDOut,
                                  uint32_t nSubmitterID, const CAmount& amountBond, const CAmount& nFee)
{
    strFail = "Unknown error!";
    nAssignedIDOut = 0;
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    if (amountBond <= 0) { strFail = "Bond amount must be positive!"; return false; }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);
    AbandonStaleOracleOps(this);

    const int nHeight = chainActive.Height() + 1;
    const bool fFresh = (nSubmitterID == 0);
    if (fFresh && OracleFreshBondPending()) {
        strFail = "A fresh oracle registration is already in the mempool (one per block) - retry next block!";
        return false;
    }
    if (!fFresh && OracleOpPending(nSubmitterID, false /* fIncomingSubmit */)) {
        strFail = "An oracle op for this submitter is already in the mempool (one per submitter per block) - retry next block!";
        return false;
    }

    // Resolve the submitter key and the priors this op will bind.
    CKey key;
    std::vector<unsigned char> vchPubKey;
    COracleSubmitter sub;                 // zero-valued for a fresh registration
    CAmount amountCarried = 0;
    COutPoint outBondPrev;
    if (fFresh) {
        CPubKey pub;
        if (!GetKeyFromPool(pub)) { strFail = "Keypool ran out, please call keypoolrefill first!"; return false; }
        vchPubKey.assign(pub.begin(), pub.end());
        if (!GetKey(pub.GetID(), key)) { strFail = "Lost the fresh submitter key!"; return false; }
    } else {
        if (!phousetree->GetOracleSubmitter(nSubmitterID, sub)) { strFail = "Unknown oracle submitter!"; return false; }
        vchPubKey = sub.vchPubKey;
        if (!GetKey(CPubKey(vchPubKey).GetID(), key)) {
            strFail = "This wallet does not hold the submitter's key!"; return false;
        }
        // Consolidate the existing bond: only a same-key BOND may spend that
        // coin, and the record repoints to THIS tx's vout[0], so leaving it
        // behind would orphan the value from the record that tracks it.
        Coin coinBond;
        if (pcoinsTip->GetCoin(sub.bondOutpoint, coinBond) && !coinBond.IsSpent()) {
            if (!coinBond.fOracleBond) { strFail = "Recorded bond outpoint is not a bond coin!"; return false; }
            if (coinBond.out.scriptPubKey != OracleBondScript(vchPubKey)) {
                strFail = "Recorded bond coin does not carry this submitter's key!"; return false;
            }
            amountCarried = coinBond.out.nValue;
            outBondPrev = sub.bondOutpoint;
        }
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_ORACLE_VERSION;
    mtx.nOracleOp = ORACLE_OP_BOND;
    // vout[0] = the bond escrow, pinned by consensus. Built before the payload
    // signature, which binds hashOutputs.
    mtx.vout.push_back(CTxOut(amountCarried + amountBond, OracleBondScript(vchPubKey)));

    std::vector<COutput> vPlain;
    CollectPlainOracleFunding(this, vPlain);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vPlain, amountBond + nFee, setCoins, nAmountRet)) {
        strFail = ORACLE_FUNDING_FAIL; return false;
    }

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - amountBond - nFee;
    if (nChange > 0) {
        CPubKey pubChange;
        if (!reserveKey.GetReservedKey(pubChange)) { strFail = "Keypool ran out!"; return false; }
        CTxOut outChange(nChange, GetScriptForDestination(pubChange.GetID()));
        if (!IsDust(outChange, ::dustRelayFee)) mtx.vout.push_back(outChange);
    }
    // Inputs before the payload signature - it binds hashPrevouts (R-i6). The
    // consolidated bond rides first; its script is anyone-can-spend, so it
    // takes an empty scriptSig and is skipped by the signing loop below.
    if (!outBondPrev.IsNull())
        mtx.vin.push_back(CTxIn(outBondPrev));
    for (const CInputCoin& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    OracleBond payload;
    payload.nSubmitterID = nSubmitterID;
    payload.nTargetHeight = (uint32_t)nHeight;
    payload.vchSubmitterPubKey = vchPubKey;
    payload.nPrevBondHeight = sub.nBondHeight;
    payload.nPrevLastSubmitHeight = sub.nLastSubmitHeight;
    payload.nPrevUnbondRequestHeight = sub.nUnbondRequestHeight;
    payload.outPrevBond = sub.bondOutpoint;   // null for a fresh registration
    {
        const CTransaction txForSig(mtx);
        if (!key.Sign(OracleBondSigHash(payload, OracleHashPrevouts(txForSig), BillHashOutputs(txForSig)),
                      payload.vchSig)) {
            strFail = "Failed to sign the oracle bond!"; return false;
        }
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << payload;
    mtx.vchOraclePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign(mtx);
    unsigned int nIn = outBondPrev.IsNull() ? 0 : 1;   // skip the anyone-can-spend bond input
    for (const CInputCoin& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL),
                              coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing oracle bond inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the oracle bond! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();
    // A fresh id is assigned by CONSENSUS at connect (last id + 1). Report the
    // value this op will take if it connects next - callers must re-read it
    // from listoraclesubmitters once confirmed rather than trust it blindly,
    // since another fresh bond could land first on a competing branch.
    if (fFresh) {
        uint32_t nLast = 0;
        phousetree->GetLastOracleSubmitterID(nLast);
        nAssignedIDOut = nLast + 1;
    } else {
        nAssignedIDOut = nSubmitterID;
    }
    return true;
}

bool CWallet::SubmitOraclePrice(std::string& strFail, uint256& txidOut,
                                uint32_t nSubmitterID, uint64_t nPriceMilligrams, const CAmount& nFee)
{
    strFail = "Unknown error!";
    if (vpwallets.empty()) { strFail = "No active wallet!"; return false; }
    if (nSubmitterID == 0) { strFail = "Invalid submitter id!"; return false; }
    if (nPriceMilligrams < ORACLE_PRICE_MIN || nPriceMilligrams > ORACLE_PRICE_MAX) {
        strFail = "Price out of range (milligrams of gold per 1000 ECX)!"; return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);
    // Every prior submission is stale the moment the tip moved, and a re-sign
    // for THIS height displaces our own pooled one - free their inputs first or
    // the wallet starves itself of funding within a few blocks.
    AbandonStaleOracleOps(this);

    if (OracleOpPending(nSubmitterID, true /* fIncomingSubmit */)) {
        strFail = "A bond for this submitter is already in the mempool - retry next block!";
        return false;
    }

    const int nHeight = chainActive.Height() + 1;
    if (!chainActive.Tip()) { strFail = "No chain tip!"; return false; }
    const uint256 hashPrevBlock = chainActive.Tip()->GetBlockHash();

    COracleSubmitter sub;
    if (!phousetree->GetOracleSubmitter(nSubmitterID, sub)) { strFail = "Unknown oracle submitter!"; return false; }
    if (sub.nBondHeight == 0 || sub.nBondHeight >= (uint32_t)nHeight) {
        strFail = "Submitter bonded in this very block - a submission must reference a bond from a PRIOR block; retry next block!";
        return false;
    }
    CKey key;
    if (!GetKey(CPubKey(sub.vchPubKey).GetID(), key)) {
        strFail = "This wallet does not hold the submitter's key!"; return false;
    }

    CGoldFix fixPrev;
    phousetree->GetGoldFix(fixPrev);      // stays null before the first fix

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_ORACLE_VERSION;
    mtx.nOracleOp = ORACLE_OP_SUBMIT;

    // A submission moves no value: it needs only a fee and one output to exist
    // (CheckTransaction rejects an empty vout). Fund fee + a dust-clearing
    // change output back to ourselves.
    const CAmount nChangeFloor = NOTE_DUST_VALUE;
    std::vector<COutput> vPlain;
    CollectPlainOracleFunding(this, vPlain);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = 0;
    if (!SelectCoins(vPlain, nFee + nChangeFloor, setCoins, nAmountRet)) {
        strFail = ORACLE_FUNDING_FAIL; return false;
    }

    CReserveKey reserveKey(this);
    CPubKey pubChange;
    if (!reserveKey.GetReservedKey(pubChange)) { strFail = "Keypool ran out!"; return false; }
    mtx.vout.push_back(CTxOut(nAmountRet - nFee, GetScriptForDestination(pubChange.GetID())));
    for (const CInputCoin& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    OracleSubmit payload;
    payload.nSubmitterID = nSubmitterID;
    payload.nTargetHeight = (uint32_t)nHeight;
    payload.nPriceMilligrams = nPriceMilligrams;
    payload.nPrevRaw = fixPrev.nRaw;
    payload.nPrevBraked = fixPrev.nBraked;
    payload.nPrevFixHeight = fixPrev.nFixHeight;
    payload.nPrevOwnLastSubmitHeight = sub.nLastSubmitHeight;
    payload.hashPrevBlockBind = hashPrevBlock;
    {
        const CTransaction txForSig(mtx);
        if (!key.Sign(OracleSubmitSigHash(payload, OracleHashPrevouts(txForSig), BillHashOutputs(txForSig)),
                      payload.vchSig)) {
            strFail = "Failed to sign the oracle submission!"; return false;
        }
    }
    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << payload;
    mtx.vchOraclePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    const CTransaction txToSign(mtx);
    unsigned int nIn = 0;
    for (const CInputCoin& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL),
                              coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing oracle submission inputs failed!"; return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit the oracle submission! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

bool CWallet::AttestHouse(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) {
        strFail = "Unknown house!";
        return false;
    }
    // Fail-fast mirrors of the consensus gates (CommitTransaction does not
    // surface ATMP rejection to the RPC caller).
    const int nNextHeight = chainActive.Height() + 1;
    const char chEff = HouseEffectiveStatus(house, nNextHeight);
    if (chEff != HOUSE_STATUS_OPEN && chEff != HOUSE_STATUS_STRESSED &&
            chEff != HOUSE_STATUS_DEFERRED) {
        strFail = "House is wound down or insolvent - attestation closed!";
        return false;
    }
    const uint32_t nAsOfHeight = (uint32_t)chainActive.Height();
    if (nAsOfHeight <= house.nLastAttestHeight) {
        strFail = "Already attested at this chain height - wait for the next block!";
        return false;
    }
    const uint256 hashAsOf = chainActive.Tip()->GetBlockHash();

    // Gather reserve-proof candidates: confirmed, PLAIN (no consensus tags),
    // single-key P2PKH/P2WPKH coins this wallet can sign for. Exactly mirrors
    // the consensus proof rules.
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);

    struct ReserveCandidate {
        COutPoint outpoint;
        CTxOut txout;
        CKeyID keyid;
    };
    std::vector<ReserveCandidate> vCandidate;
    std::vector<COutput> vFeePool;
    for (const COutput& out : vCoins) {
        const COutPoint outpoint(out.tx->GetHash(), out.i);
        const CTxOut& txout = out.tx->tx->vout[out.i];

        Coin coin;
        bool fReserve = out.nDepth >= 1 && out.fSpendable &&
                pcoinsTip->GetCoin(outpoint, coin) && !coin.IsSpent() &&
                coin.nHeight <= nAsOfHeight &&
                !(coin.fBitAsset || coin.fBitAssetControl || coin.fBill ||
                  coin.fBillEscrow || coin.fHouseEscrow || coin.fNote) &&
                !(coin.IsCoinBase() && nNextHeight - (int)coin.nHeight < COINBASE_MATURITY);

        CKeyID keyid;
        if (fReserve) {
            CTxDestination dest;
            fReserve = ExtractDestination(txout.scriptPubKey, dest);
            if (fReserve) {
                if (const CKeyID* id = boost::get<CKeyID>(&dest))
                    keyid = *id;
                else if (const WitnessV0KeyHash* wid = boost::get<WitnessV0KeyHash>(&dest))
                    keyid = CKeyID(*wid);
                else
                    fReserve = false;
            }
            CKey key;
            if (fReserve)
                fReserve = GetKey(keyid, key);
            // Mirror the consensus rule EXACTLY: the coin's script must BE the
            // canonical P2PKH/P2WPKH for that key. ExtractDestination also maps
            // e.g. bare P2PK to a CKeyID, and such coins would be rejected at
            // connect ("bad-house-attest-coin-script").
            if (fReserve)
                fReserve = txout.scriptPubKey == GetScriptForDestination(keyid) ||
                           txout.scriptPubKey == GetScriptForDestination(WitnessV0KeyHash(keyid));
        }

        if (fReserve) {
            ReserveCandidate cand;
            cand.outpoint = outpoint;
            cand.txout = txout;
            cand.keyid = keyid;
            vCandidate.push_back(cand);
        } else {
            vFeePool.push_back(out);
        }
    }
    // Largest first; the proof list is capped, so attest the deepest value
    std::sort(vCandidate.begin(), vCandidate.end(),
        [](const ReserveCandidate& a, const ReserveCandidate& b) { return a.txout.nValue > b.txout.nValue; });
    if (vCandidate.size() > MAX_ATTEST_PROOFS)
        vCandidate.resize(MAX_ATTEST_PROOFS);

    // Fund the fee from coins OUTSIDE the proof set (consensus rejects an
    // attest that spends its own reserves). If the non-proof pool cannot
    // cover the fee, release the smallest proof coins until it can.
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    while (true) {
        setCoins.clear();
        nAmountRet = 0;
        if (SelectCoins(vFeePool, nFee, setCoins, nAmountRet))
            break;
        if (vCandidate.empty()) {
            strFail = "Could not collect enough coins to pay the attestation fee!";
            return false;
        }
        // Release the smallest proof candidate into the fee pool
        const ReserveCandidate released = vCandidate.back();
        vCandidate.pop_back();
        for (const COutput& out : vCoins) {
            if (COutPoint(out.tx->GetHash(), out.i) == released.outpoint) {
                vFeePool.push_back(out);
                break;
            }
        }
    }

    CAmount amountReserves = 0;
    for (const ReserveCandidate& cand : vCandidate)
        amountReserves += cand.txout.nValue;

    // Outputs finalized before the approver signatures (they bind
    // BillHashOutputs).
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_ATTEST;

    CReserveKey reserveKey(this);
    const CAmount nChange = nAmountRet - nFee;
    CPubKey vchPubKey;
    if (!reserveKey.GetReservedKey(vchPubKey)) {
        strFail = "Keypool ran out, please call keypoolrefill first!";
        return false;
    }
    mtx.vout.push_back(CTxOut(nChange > 0 ? nChange : CAmount(546), GetScriptForDestination(vchPubKey.GetID())));

    HouseAttest att;
    att.nHouseID = nHouseID;
    att.nSchemaVersion = 1;
    att.nAsOfHeight = nAsOfHeight;
    att.nPrevLastAttestHeight = house.nLastAttestHeight;
    att.nPrevStressSince = house.nStressSinceHeight;
    att.amountPrevReserves = house.amountLastAttestReserves;
    att.nPrevDeferInvokedHeight = house.nDeferInvokedHeight;
    att.nPrevDeferRenewals = house.nDeferRenewals;
    att.nPrevDeferCumBlocks = house.nDeferCumBlocks;
    att.nPrevDeferEndedHeight = house.nDeferEndedHeight;
    att.amountReserves = amountReserves;

    for (const ReserveCandidate& cand : vCandidate) {
        CKey key;
        if (!GetKey(cand.keyid, key)) {
            strFail = "Lost a reserve key mid-build!";
            return false;
        }
        AttestProof proof;
        proof.outpoint = cand.outpoint;
        const CPubKey pub = key.GetPubKey();
        proof.vchPubKey = std::vector<unsigned char>(pub.begin(), pub.end());
        const uint256 challenge = HouseAttestChallenge(house.houseID, nAsOfHeight, hashAsOf, cand.outpoint);
        if (!key.Sign(challenge, proof.vchSig)) {
            strFail = "Failed to sign a reserve proof!";
            return false;
        }
        att.vProofs.push_back(proof);
    }

    const uint256 sighash = HouseAttestSigHash(house.houseID, nAsOfHeight, amountReserves,
        HouseAttestProofSetHash(att.vProofs), BillHashOutputs(mtx));
    if (!SignHouseApprovers(this, house, sighash, att.vApproverIndex, att.vApproverSig, strFail))
        return false;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << att;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
            strFail = "Signing attestation inputs failed!";
            return false;
        }
        UpdateTransaction(mtx, nIn, sigdata);
        nIn++;
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit attestation! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::ReclaimPledge(std::string& strFail, uint256& txidOut, const uint32_t nHouseID, const uint32_t nPartnerIndex, const CAmount& nFee)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!";
        return false;
    }
    // A8-b fail-fast (knob-gated like TOPUP/ADMIT): this op takes the house
    // slot, so building it against a pooled house-state op makes a tx ATMP
    // will refuse - and CommitTransaction does not surface that; the refused
    // phantom pins its inputs out of both wallet views until abandoned (C7c).
    if (HouseFailFastEnabled() && HouseStateChangePending(nHouseID)) {
        strFail = "A house-state-changing op (or a pending settle) for this house is already in the mempool - retry next block!";
        return false;
    }

    BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, cs_wallet);

    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) {
        strFail = "Unknown house!";
        return false;
    }
    if (nPartnerIndex >= house.vPartner.size()) {
        strFail = "Invalid partner index!";
        return false;
    }
    const HousePartner& partner = house.vPartner[nPartnerIndex];

    CKey keyPartner;
    if (!GetKey(CPubKey(partner.vchPubKey).GetID(), keyPartner)) {
        strFail = "This wallet does not hold that partner's key!";
        return false;
    }

    const char chEffReclaim = HouseEffectiveStatus(house, chainActive.Height() + 1);
    if (chEffReclaim == HOUSE_STATUS_STRESSED) {
        strFail = "House is stressed - no escrow leaves during the stress window!";
        return false;
    }

    if (chEffReclaim == HOUSE_STATUS_INSOLVENT) {
        // WHOLE-HOUSE RESIDUAL SETTLE: spends every live pledge coin, pays
        // each partner their pro-rata residual at forced P2PKH outputs
        // (mirrors the consensus layout exactly).
        if (partner.status == HOUSE_PARTNER_SETTLED) {
            strFail = "Partner already settled!";
            return false;
        }
        if (house.nMintedUnits != 0) {
            strFail = "Notes still outstanding - holders claim first (holders senior)!";
            return false;
        }
        if (house.nDepositUnits != 0) {
            strFail = "Term deposits still outstanding - depositors claim first (deposits senior to partners)!";
            return false;
        }

        LOCK(mempool.cs);
        CCoinsViewMemPool viewSettle(pcoinsTip.get(), mempool);
        CAmount amountLive = 0;
        std::vector<COutPoint> vSpend;
        std::vector<COutPoint> vSettleOutpoints;
        for (const HousePartner& p : house.vPartner)
            vSettleOutpoints.insert(vSettleOutpoints.end(), p.vOutPledge.begin(), p.vOutPledge.end());
        vSettleOutpoints.insert(vSettleOutpoints.end(), house.vOutEscrowChange.begin(), house.vOutEscrowChange.end());
        for (const COutPoint& out : vSettleOutpoints) {
            Coin coin;
            if (viewSettle.GetCoin(out, coin) && !coin.IsSpent() && coin.fHouseEscrow) {
                vSpend.push_back(out);
                amountLive += coin.out.nValue;
            }
        }
        // Snapshot (or what the self-materializing settle will snapshot). Partners
        // are LAST in the loss order (escrow -> deposits -> notes), so the residual
        // is the pot MINUS both senior tranches: the note par snapshot AND the
        // junior deposit snapshot - exactly the consensus amountSenior. (Both D and
        // N are 0 here by the gate above, so a self-materializing settle snapshots
        // both seniors to 0; a settle after claims uses the frozen snapshots.)
        const uint64_t nNoteSnap = house.status == HOUSE_STATUS_INSOLVENT ? house.nInsolventUnits : house.nMintedUnits;
        const uint64_t nDepSnap = house.status == HOUSE_STATUS_INSOLVENT ? house.nInsolventDepositPrincipal : house.nDepositUnits;
        const CAmount amountSenior = (CAmount)nNoteSnap + (CAmount)nDepSnap;
        const CAmount amountPot = house.status == HOUSE_STATUS_INSOLVENT ? house.amountInsolventPot : amountLive;
        const CAmount amountResidual = amountPot > amountSenior ? amountPot - amountSenior : 0;
        if (amountResidual <= 0 || vSpend.empty()) {
            strFail = "No residual to settle (pot fully consumed by note + deposit claims)!";
            return false;
        }

        // Weights mirror consensus: per-partner LIVE escrow frozen at
        // materialization. If the settle will self-materialize (zero-liability
        // lazy-insolvent house), compute what that snapshot WILL be.
        std::vector<CAmount> vWeight(house.vPartner.size(), 0);
        for (size_t j = 0; j < house.vPartner.size(); j++) {
            if (house.status == HOUSE_STATUS_INSOLVENT) {
                vWeight[j] = house.vPartner[j].amountInsolventPledge;
            } else {
                for (const COutPoint& out : house.vPartner[j].vOutPledge) {
                    Coin coin;
                    if (viewSettle.GetCoin(out, coin) && !coin.IsSpent() && coin.fHouseEscrow)
                        vWeight[j] += coin.out.nValue;
                }
            }
        }
        CAmount amountPledgeSum = 0;
        for (size_t j = 0; j < house.vPartner.size(); j++) {
            if (house.vPartner[j].status != HOUSE_PARTNER_SETTLED)
                amountPledgeSum += vWeight[j];
        }
        std::vector<std::pair<size_t, CAmount>> vShare;
        CAmount amountShareSum = 0;
        for (size_t j = 0; j < house.vPartner.size(); j++) {
            if (house.vPartner[j].status == HOUSE_PARTNER_SETTLED)
                continue;
            const CAmount s = HouseResidualShare(vWeight[j], amountResidual, amountPledgeSum);
            if (s > 0) {
                vShare.push_back(std::make_pair(j, s));
                amountShareSum += s;
            }
        }
        if (vShare.empty() || amountLive < amountShareSum) {
            strFail = "Residual share computation failed (pot drained)!";
            return false;
        }
        vShare.back().second += amountLive - amountShareSum;

        CMutableTransaction mtx;
        mtx.nVersion = TRANSACTION_HOUSE_VERSION;
        mtx.nHouseOp = HOUSE_OP_RECLAIM;
        for (const COutPoint& out : vSpend)
            mtx.vin.push_back(CTxIn(out, CScript()));
        for (const auto& sh : vShare)
            mtx.vout.push_back(CTxOut(sh.second, NoteScriptForPubKey(house.vPartner[sh.first].vchPubKey)));

        // Fee from plain coins; change appended after the forced outputs
        std::vector<COutput> vCoins;
        AvailableCoins(vCoins, true);
        std::set<CInputCoin> setCoins;
        CAmount nAmountRet = 0;
        if (!SelectCoins(vCoins, nFee, setCoins, nAmountRet)) {
            strFail = "Could not fund the settle fee!";
            return false;
        }
        CReserveKey reserveKeySettle(this);
        const CAmount nChange = nAmountRet - nFee;
        if (nChange > 0) {
            CPubKey vchPubKey;
            if (!reserveKeySettle.GetReservedKey(vchPubKey)) { strFail = "Keypool ran out!"; return false; }
            CTxOut out(nChange, GetScriptForDestination(vchPubKey.GetID()));
            if (!IsDust(out, ::dustRelayFee)) mtx.vout.push_back(out);
        }

        HouseReclaim rec;
        rec.nHouseID = nHouseID;
        rec.nPartnerIndex = nPartnerIndex;
        const uint256 sighash = HouseReclaimSigHash(house.houseID, nPartnerIndex, BillHashOutputs(mtx));
        if (!keyPartner.Sign(sighash, rec.vchSig)) {
            strFail = "Failed to sign settle!";
            return false;
        }
        CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
        ssPayload << rec;
        mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

        // Fee inputs join vin AFTER the escrow inputs
        for (const auto& coin : setCoins)
            mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

        // Escrow inputs stay unsigned; sign the fee inputs (they follow the
        // escrow inputs in vin order)
        const CTransaction txToSign = mtx;
        int nIn = (int)vSpend.size();
        for (const auto& coin : setCoins) {
            SignatureData sigdata;
            if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), coin.txout.scriptPubKey, sigdata)) {
                strFail = "Signing settle fee inputs failed!";
                return false;
            }
            UpdateTransaction(mtx, nIn, sigdata);
            nIn++;
        }

        CWalletTx walletTx;
        walletTx.fTimeReceivedIsTxTime = true;
        walletTx.fFromMe = true;
        walletTx.BindWallet(this);
        walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
        CValidationState state;
        if (!CommitTransaction(walletTx, reserveKeySettle, g_connman.get(), state)) {
            strFail = "Failed to commit settle! Reject reason: " + FormatStateMessage(state);
            return false;
        }
        txidOut = walletTx.tx->GetHash();
        return true;
    }

    if (partner.status != HOUSE_PARTNER_TAIL) {
        strFail = "Partner pledge is not reclaimable (still active)!";
        return false;
    }
    if ((uint32_t)chainActive.Height() < partner.nTailUnlockHeight) {
        strFail = "Tail lock has not expired yet!";
        return false;
    }
    if (partner.vOutPledge.empty()) {
        strFail = "No pledge outputs left to reclaim!";
        return false;
    }

    // Spend every remaining pledge outpoint; pay the partner key minus fee
    CAmount nPledgeIn = 0;
    {
        LOCK(mempool.cs);
        CCoinsViewMemPool viewMempool(pcoinsTip.get(), mempool);
        for (const COutPoint& out : partner.vOutPledge) {
            Coin coin;
            if (!viewMempool.GetCoin(out, coin) || coin.IsSpent()) {
                strFail = "Pledge output missing or already spent!";
                return false;
            }
            nPledgeIn += coin.out.nValue;
        }
    }
    if (nPledgeIn <= nFee) {
        strFail = "Pledge value does not cover the fee!";
        return false;
    }

    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = HOUSE_OP_RECLAIM;
    for (const COutPoint& out : partner.vOutPledge)
        mtx.vin.push_back(CTxIn(out, CScript()));
    mtx.vout.push_back(CTxOut(nPledgeIn - nFee, GetScriptForDestination(CPubKey(partner.vchPubKey).GetID())));

    HouseReclaim rec;
    rec.nHouseID = nHouseID;
    rec.nPartnerIndex = nPartnerIndex;
    const uint256 sighash = HouseReclaimSigHash(house.houseID, nPartnerIndex, BillHashOutputs(mtx));
    if (!keyPartner.Sign(sighash, rec.vchSig)) {
        strFail = "Failed to sign reclaim!";
        return false;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << rec;
    mtx.vchHousePayload = std::vector<unsigned char>(ssPayload.begin(), ssPayload.end());

    // The escrow script is <house_id> OP_DROP OP_TRUE: no input signatures
    // needed (the consensus spend guard + payload signature authorize).

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));

    CReserveKey reserveKey(this);
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit reclaim! Reject reason: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::TransferAsset(std::string& strFail, uint256& txidOut, const uint256& txid, const CTxDestination& dest, const CAmount& nFee, const CAmount& nAmount)
{
    strFail = "Unknown error!";

    if (vpwallets.empty()) {
        strFail = "No active wallet!\n";
        return false;
    }

    if (txid.IsNull()) {
        strFail = "Invalid txid";
        return false;
    }

    if (!IsValidDestination(dest)) {
        strFail = "Invalid destination";
        return false;
    }

    BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, cs_wallet);

    // Get our asset outputs from txid
    std::vector<COutput> vOut;
    AvailableAssets(vOut, txid);

    if (vOut.empty()) {
        strFail = "No BitAssets of this type available!";
        return false;
    }

    CMutableTransaction mtx;

    // Choose asset outputs to cover transfer
    uint32_t nAssetID = vOut[0].tx->nAssetID;
    CAmount nAmountAsset = CAmount(0);
    std::vector<COutput> vAssetSpent;
    for (const COutput& out : vOut) {
        mtx.vin.push_back(CTxIn(txid, out.i, CScript()));
        vAssetSpent.push_back(out);

        // Have we found enough?
        nAmountAsset += out.tx->tx->vout[out.i].nValue;
        if (nAmountAsset >= nAmount)
            break;
    }

    if (nAmountAsset < nAmount) {
        strFail = "Insufficient asset funds!";
        return false;
    }

    // Handle asset change
    const CAmount nAssetChange = nAmountAsset - nAmount;
    CReserveKey reserveKeyAsset(this);
    if (nAssetChange > 0) {
        CScript scriptAssetChange;

        // Reserve a new key pair from key pool
        CPubKey vchPubKey;
        if (!reserveKeyAsset.GetReservedKey(vchPubKey))
        {
            strFail = "Keypool ran out, please call keypoolrefill first!\n";
            return false;
        }
        scriptAssetChange = GetScriptForDestination(vchPubKey.GetID());

        CTxOut out(nAssetChange, scriptAssetChange);
        mtx.vout.push_back(out);
    }

    // Add asset transfer output
    mtx.vout.push_back(CTxOut(nAmount, GetScriptForDestination(dest)));

    // Select coins to cover fee
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountCoins = CAmount(0);
    if (!SelectCoins(vCoins, nFee, setCoins, nAmountCoins)) {
        strFail = "Could not collect enough coins to cover fee!\n";
        return false;
    }

    // Handle fee input change if there is any
    const CAmount nChange = nAmountCoins - nFee;
    CReserveKey reserveKey(this);
    if (nChange > 0) {
        CScript scriptChange;

        // Reserve a new key pair from key pool
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey))
        {
            strFail = "Keypool ran out, please call keypoolrefill first!\n";
            return false;
        }
        scriptChange = GetScriptForDestination(vchPubKey.GetID());

        CTxOut out(nChange, scriptChange);
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    // Add inputs for fee
    for (const auto& coin : setCoins)
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));

    // Dummy sign the transaction to calculate minimum fee
    std::set<CInputCoin> setCoinsTemp = setCoins;
    if (!DummySignTx(mtx, setCoinsTemp)) {
        strFail = "Dummy signing transaction for required fee calculation failed!";
        return false;
    }

    // Get transaction size with dummy signatures
    unsigned int nBytes = GetVirtualTransactionSize(mtx);

    // Calculate fee
    CCoinControl coinControl;
    FeeCalculation feeCalc;
    CAmount nFeeNeeded = GetMinimumFee(nBytes, coinControl, ::mempool, ::feeEstimator, &feeCalc);

    // Check that the fee is valid for relay
    if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
        strFail = "Transaction too large for fee policy";
        return false;
    }

    // Check the user set fee
    if (nFee < nFeeNeeded) {
        strFail = "The fee you have set is too small!";
        return false;
    }

    // Remove dummy signatures
    for (auto& vin : mtx.vin) {
        vin.scriptSig = CScript();
        vin.scriptWitness.SetNull();
    }

    // Sign asset & fee inputs

    const CTransaction txToSign = mtx;
    int nIn = 0;

    // Sign the asset inputs
    for (const COutput& out : vAssetSpent) {
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        SignatureData sigdata;

        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, out.tx->tx->vout[out.i].nValue, SIGHASH_ALL), scriptPubKey, sigdata))
        {
            strFail = "Signing asset inputs failed!\n";
            return false;
        } else {
            UpdateTransaction(mtx, nIn, sigdata);
        }
        nIn++;
    }

    // Sign the fee inputs
    for (const auto& coin : setCoins) {
        const CScript& scriptPubKey = coin.txout.scriptPubKey;
        SignatureData sigdata;

        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nIn, coin.txout.nValue, SIGHASH_ALL), scriptPubKey, sigdata))
        {
            strFail = "Signing inputs failed!\n";
            return false;
        } else {
            UpdateTransaction(mtx, nIn, sigdata);
        }

        nIn++;
    }

    // Broadcast transaction
    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);

    walletTx.amountAssetIn = nAmountAsset;
    walletTx.nAssetID = nAssetID;

    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit BitAsset creation transaction! Reject reason: " + FormatStateMessage(state) + "\n";
        return false;
    }

    txidOut = walletTx.tx->GetHash();

    return true;
}

bool CWallet::TransferAssetControl(std::string& strFail, const uint256& txid, const CTxDestination& dest, const CAmount& nFee)
{
    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman, CValidationState& state)
{
    {
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitTransaction:\n%s", wtxNew.tx->ToString());
        {
            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            for (const CTxIn& txin : wtxNew.tx->vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }
        }

        // Get the inserted-CWalletTx from mapWallet so that the
        // fInMempool flag is cached properly
        CWalletTx& wtx = mapWallet[wtxNew.GetHash()];

        if (fBroadcastTransactions)
        {
            // Broadcast
            if (!wtx.AcceptToMemoryPool(maxTxFee, state)) {
                LogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", FormatStateMessage(state));
                // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
            } else {
                wtx.RelayWalletTransaction(connman);
            }
        }
    }
    return true;
}

void CWallet::ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries) {
    CWalletDB walletdb(*dbw);
    return walletdb.ListAccountCreditDebit(strAccount, entries);
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry)
{
    CWalletDB walletdb(*dbw);

    return AddAccountingEntry(acentry, &walletdb);
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry, CWalletDB *pwalletdb)
{
    if (!pwalletdb->WriteAccountingEntry(++nAccountingEntryNumber, acentry)) {
        return false;
    }

    laccentries.push_back(acentry);
    CAccountingEntry & entry = laccentries.back();
    wtxOrdered.insert(std::make_pair(entry.nOrderPos, TxPair(nullptr, &entry)));

    return true;
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    LOCK2(cs_main, cs_wallet);

    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(*dbw,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (dbw->Rewrite("\x04pool"))
        {
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    // This wallet is in its first run if all of these are empty
    fFirstRunRet = mapKeys.empty() && mapCryptedKeys.empty() && mapWatchKeys.empty() && setWatchOnly.empty() && mapScripts.empty();

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;

    uiInterface.LoadWallet(this);

    return DB_LOAD_OK;
}

DBErrors CWallet::ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut)
{
    AssertLockHeld(cs_wallet); // mapWallet
    DBErrors nZapSelectTxRet = CWalletDB(*dbw,"cr+").ZapSelectTx(vHashIn, vHashOut);
    for (uint256 hash : vHashOut)
        mapWallet.erase(hash);

    if (nZapSelectTxRet == DB_NEED_REWRITE)
    {
        if (dbw->Rewrite("\x04pool"))
        {
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapSelectTxRet != DB_LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DB_LOAD_OK;

}

DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    DBErrors nZapWalletTxRet = CWalletDB(*dbw,"cr+").ZapWalletTx(vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (dbw->Rewrite("\x04pool"))
        {
            LOCK(cs_wallet);
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& strPurpose)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW) );
    if (!strPurpose.empty() && !CWalletDB(*dbw).WritePurpose(EncodeDestination(address), strPurpose))
        return false;
    return CWalletDB(*dbw).WriteName(EncodeDestination(address), strName);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        // Delete destdata tuples associated with address
        std::string strAddress = EncodeDestination(address);
        for (const std::pair<std::string, std::string> &item : mapAddressBook[address].destdata)
        {
            CWalletDB(*dbw).EraseDestData(strAddress, item.first);
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    CWalletDB(*dbw).ErasePurpose(EncodeDestination(address));
    return CWalletDB(*dbw).EraseName(EncodeDestination(address));
}

const std::string& CWallet::GetAccountName(const CScript& scriptPubKey) const
{
    CTxDestination address;
    if (ExtractDestination(scriptPubKey, address) && !scriptPubKey.IsUnspendable()) {
        auto mi = mapAddressBook.find(address);
        if (mi != mapAddressBook.end()) {
            return mi->second.name;
        }
    }
    // A scriptPubKey that doesn't have an entry in the address book is
    // associated with the default account ("").
    const static std::string DEFAULT_ACCOUNT_NAME;
    return DEFAULT_ACCOUNT_NAME;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(*dbw);

        for (int64_t nIndex : setInternalKeyPool) {
            walletdb.ErasePool(nIndex);
        }
        setInternalKeyPool.clear();

        for (int64_t nIndex : setExternalKeyPool) {
            walletdb.ErasePool(nIndex);
        }
        setExternalKeyPool.clear();

        m_pool_key_to_index.clear();

        if (!TopUpKeyPool()) {
            return false;
        }
        LogPrintf("CWallet::NewKeyPool rewrote keypool\n");
    }
    return true;
}

size_t CWallet::KeypoolCountExternalKeys()
{
    AssertLockHeld(cs_wallet); // setExternalKeyPool
    return setExternalKeyPool.size();
}

void CWallet::LoadKeyPool(int64_t nIndex, const CKeyPool &keypool)
{
    AssertLockHeld(cs_wallet);
    if (keypool.fInternal) {
        setInternalKeyPool.insert(nIndex);
    } else {
        setExternalKeyPool.insert(nIndex);
    }
    m_max_keypool_index = std::max(m_max_keypool_index, nIndex);
    m_pool_key_to_index[keypool.vchPubKey.GetID()] = nIndex;

    // If no metadata exists yet, create a default with the pool key's
    // creation time. Note that this may be overwritten by actually
    // stored metadata for that key later, which is fine.
    CKeyID keyid = keypool.vchPubKey.GetID();
    if (mapKeyMetadata.count(keyid) == 0)
        mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = std::max(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);

        // count amount of available keys (internal, external)
        // make sure the keypool of external and internal keys fits the user selected target (-keypool)
        int64_t missingExternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setExternalKeyPool.size(), (int64_t) 0);
        int64_t missingInternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setInternalKeyPool.size(), (int64_t) 0);

        if (!IsHDEnabled() || !CanSupportFeature(FEATURE_HD_SPLIT))
        {
            // don't create extra internal keys
            missingInternal = 0;
        }
        bool internal = false;
        CWalletDB walletdb(*dbw);
        for (int64_t i = missingInternal + missingExternal; i--;)
        {
            if (i < missingInternal) {
                internal = true;
            }

            assert(m_max_keypool_index < std::numeric_limits<int64_t>::max()); // How in the hell did you use so many keys?
            int64_t index = ++m_max_keypool_index;

            CPubKey pubkey(GenerateNewKey(walletdb, internal));
            if (!walletdb.WritePool(index, CKeyPool(pubkey, internal))) {
                throw std::runtime_error(std::string(__func__) + ": writing generated key failed");
            }

            if (internal) {
                setInternalKeyPool.insert(index);
            } else {
                setExternalKeyPool.insert(index);
            }
            m_pool_key_to_index[pubkey.GetID()] = index;
        }
        if (missingInternal + missingExternal > 0) {
            LogPrintf("keypool added %d keys (%d internal), size=%u (%u internal)\n", missingInternal + missingExternal, missingInternal, setInternalKeyPool.size() + setExternalKeyPool.size(), setInternalKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fRequestedInternal)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        bool fReturningInternal = IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT) && fRequestedInternal;
        std::set<int64_t>& setKeyPool = fReturningInternal ? setInternalKeyPool : setExternalKeyPool;

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(*dbw);

        auto it = setKeyPool.begin();
        nIndex = *it;
        setKeyPool.erase(it);
        if (!walletdb.ReadPool(nIndex, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read failed");
        }
        if (!HaveKey(keypool.vchPubKey.GetID())) {
            throw std::runtime_error(std::string(__func__) + ": unknown key in key pool");
        }
        if (keypool.fInternal != fReturningInternal) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry misclassified");
        }

        assert(keypool.vchPubKey.IsValid());
        m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        LogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    CWalletDB walletdb(*dbw);
    walletdb.ErasePool(nIndex);
    LogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex, bool fInternal, const CPubKey& pubkey)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        if (fInternal) {
            setInternalKeyPool.insert(nIndex);
        } else {
            setExternalKeyPool.insert(nIndex);
        }
        m_pool_key_to_index[pubkey.GetID()] = nIndex;
    }
    LogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool internal)
{
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        int64_t nIndex = 0;
        ReserveKeyFromKeyPool(nIndex, keypool, internal);
        if (nIndex == -1)
        {
            if (IsLocked()) return false;
            CWalletDB walletdb(*dbw);
            result = GenerateNewKey(walletdb, internal);
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

static int64_t GetOldestKeyTimeInPool(const std::set<int64_t>& setKeyPool, CWalletDB& walletdb) {
    if (setKeyPool.empty()) {
        return GetTime();
    }

    CKeyPool keypool;
    int64_t nIndex = *(setKeyPool.begin());
    if (!walletdb.ReadPool(nIndex, keypool)) {
        throw std::runtime_error(std::string(__func__) + ": read oldest key in keypool failed");
    }
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    LOCK(cs_wallet);

    CWalletDB walletdb(*dbw);

    // load oldest key from keypool, get time and return
    int64_t oldestKey = GetOldestKeyTimeInPool(setExternalKeyPool, walletdb);
    if (IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT)) {
        oldestKey = std::max(GetOldestKeyTimeInPool(setInternalKeyPool, walletdb), oldestKey);
    }

    return oldestKey;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        for (const auto& walletEntry : mapWallet)
        {
            const CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->tx->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->tx->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : mapWallet)
    {
        const CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->tx->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (CTxIn txin : pcoin->tx->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].tx->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               for (CTxOut txout : pcoin->tx->vout)
                   if (IsChange(txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : pcoin->tx->vout)
            if (IsMine(txout))
            {
                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (std::set<CTxDestination> _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (CTxDestination address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (CTxDestination element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CWallet::GetAccountAddresses(const std::string& strAccount) const
{
    LOCK(cs_wallet);
    std::set<CTxDestination> result;
    for (const std::pair<CTxDestination, CAddressBookData>& item : mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey, bool internal)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool, internal);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            return false;
        }
        fInternal = keypool.fInternal;
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1) {
        pwallet->ReturnKey(nIndex, fInternal, vchPubKey);
    }
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::MarkReserveKeysAsUsed(int64_t keypool_id)
{
    AssertLockHeld(cs_wallet);
    bool internal = setInternalKeyPool.count(keypool_id);
    if (!internal) assert(setExternalKeyPool.count(keypool_id));
    std::set<int64_t> *setKeyPool = internal ? &setInternalKeyPool : &setExternalKeyPool;
    auto it = setKeyPool->begin();

    CWalletDB walletdb(*dbw);
    while (it != std::end(*setKeyPool)) {
        const int64_t& index = *(it);
        if (index > keypool_id) break; // set*KeyPool is ordered

        CKeyPool keypool;
        if (walletdb.ReadPool(index, keypool)) { //TODO: This should be unnecessary
            m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        }
        LearnAllRelatedScripts(keypool.vchPubKey);
        walletdb.ErasePool(index);
        LogPrintf("keypool index %d removed\n", index);
        it = setKeyPool->erase(it);
    }
}

void CWallet::GetScriptForMining(std::shared_ptr<CReserveScript> &script)
{
    std::shared_ptr<CReserveKey> rKey = std::make_shared<CReserveKey>(this);
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;

    script = rKey;
    script->reserveScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
}

void CWallet::LockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

void CWallet::GetKeyBirthTimes(std::map<CTxDestination, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (const auto& entry : mapKeyMetadata) {
        if (entry.second.nCreateTime) {
            mapKeyBirth[entry.first] = entry.second.nCreateTime;
        }
    }

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = chainActive[std::max(0, chainActive.Height() - 144)]; // the tip can be reorganized; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    for (const CKeyID &keyid : GetKeys()) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (const auto& entry : mapWallet) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = entry.second;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second)) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            for (const CTxOut &txout : wtx.tx->vout) {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                for (const CKeyID &keyid : vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (const auto& entry : mapKeyFirstBlock)
        mapKeyBirth[entry.first] = entry.second->GetBlockTime() - TIMESTAMP_WINDOW; // block times can be 2h off
}

/**
 * Compute smart timestamp for a transaction being added to the wallet.
 *
 * Logic:
 * - If sending a transaction, assign its timestamp to the current time.
 * - If receiving a transaction outside a block, assign its timestamp to the
 *   current time.
 * - If receiving a block with a future timestamp, assign all its (not already
 *   known) transactions' timestamps to the current time.
 * - If receiving a block with a past timestamp, before the most recent known
 *   transaction (that we care about), assign all its (not already known)
 *   transactions' timestamps to the same timestamp as that most-recent-known
 *   transaction.
 * - If receiving a block with a past timestamp, but after the most recent known
 *   transaction, assign all its (not already known) transactions' timestamps to
 *   the block time.
 *
 * For more information see CWalletTx::nTimeSmart,
 * https://bitcointalk.org/?topic=54527, or
 * https://github.com/bitcoin/bitcoin/pull/1393.
 */
unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx) const
{
    unsigned int nTimeSmart = wtx.nTimeReceived;
    if (!wtx.hashUnset()) {
        if (mapBlockIndex.count(wtx.hashBlock)) {
            int64_t latestNow = wtx.nTimeReceived;
            int64_t latestEntry = 0;

            // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
            int64_t latestTolerated = latestNow + 300;
            const TxItems& txOrdered = wtxOrdered;
            for (auto it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                CWalletTx* const pwtx = it->second.first;
                if (pwtx == &wtx) {
                    continue;
                }
                CAccountingEntry* const pacentry = it->second.second;
                int64_t nSmartTime;
                if (pwtx) {
                    nSmartTime = pwtx->nTimeSmart;
                    if (!nSmartTime) {
                        nSmartTime = pwtx->nTimeReceived;
                    }
                } else {
                    nSmartTime = pacentry->nTime;
                }
                if (nSmartTime <= latestTolerated) {
                    latestEntry = nSmartTime;
                    if (nSmartTime > latestNow) {
                        latestNow = nSmartTime;
                    }
                    break;
                }
            }

            int64_t blocktime = mapBlockIndex[wtx.hashBlock]->GetBlockTime();
            nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
        } else {
            LogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), wtx.hashBlock.ToString());
        }
    }
    return nTimeSmart;
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return CWalletDB(*dbw).WriteDestData(EncodeDestination(dest), key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    return CWalletDB(*dbw).EraseDestData(EncodeDestination(dest), key);
}

bool CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if(i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if(j != i->second.destdata.end())
        {
            if(value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

std::vector<std::string> CWallet::GetDestValues(const std::string& prefix) const
{
    LOCK(cs_wallet);
    std::vector<std::string> values;
    for (const auto& address : mapAddressBook) {
        for (const auto& data : address.second.destdata) {
            if (!data.first.compare(0, prefix.size(), prefix)) {
                values.emplace_back(data.second);
            }
        }
    }
    return values;
}

CWallet* CWallet::CreateWalletFromFile(const std::string walletFile)
{
    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector<CWalletTx> vWtx;

    if (gArgs.GetBoolArg("-zapwallettxes", false)) {
        uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, walletFile));
        std::unique_ptr<CWallet> tempWallet = MakeUnique<CWallet>(std::move(dbw));
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DB_LOAD_OK) {
            InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return nullptr;
        }
    }

    uiInterface.InitMessage(_("Loading wallet..."));

    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, walletFile));
    CWallet *walletInstance = new CWallet(std::move(dbw));
    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT) {
            InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return nullptr;
        }
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            InitWarning(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                         " or address book entries might be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DB_TOO_NEW) {
            InitError(strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, _(PACKAGE_NAME)));
            return nullptr;
        }
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            InitError(strprintf(_("Wallet needed to be rewritten: restart %s to complete"), _(PACKAGE_NAME)));
            return nullptr;
        }
        else {
            InitError(strprintf(_("Error loading %s"), walletFile));
            return nullptr;
        }
    }

    if (gArgs.GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = gArgs.GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < walletInstance->GetVersion())
        {
            InitError(_("Cannot downgrade wallet"));
            return nullptr;
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun)
    {
        // ensure this wallet.dat can only be opened by clients supporting HD with chain split and expects no default key
        if (!gArgs.GetBoolArg("-usehd", true)) {
            InitError(strprintf(_("Error creating %s: You can't create non-HD wallets with this version."), walletFile));
            return nullptr;
        }
        walletInstance->SetMinVersion(FEATURE_NO_DEFAULT_KEY);

        // generate a new master key
        CPubKey masterPubKey = walletInstance->GenerateNewHDMasterKey();
        if (!walletInstance->SetHDMasterKey(masterPubKey))
            throw std::runtime_error(std::string(__func__) + ": Storing master key failed");

        // Top up the keypool
        if (!walletInstance->TopUpKeyPool()) {
            InitError(_("Unable to generate initial keys") += "\n");
            return nullptr;
        }

        walletInstance->SetBestChain(chainActive.GetLocator());
    }
    else if (gArgs.IsArgSet("-usehd")) {
        bool useHD = gArgs.GetBoolArg("-usehd", true);
        if (walletInstance->IsHDEnabled() && !useHD) {
            InitError(strprintf(_("Error loading %s: You can't disable HD on an already existing HD wallet"), walletFile));
            return nullptr;
        }
        if (!walletInstance->IsHDEnabled() && useHD) {
            InitError(strprintf(_("Error loading %s: You can't enable HD on an already existing non-HD wallet"), walletFile));
            return nullptr;
        }
    }

    LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    CBlockIndex *pindexRescan = chainActive.Genesis();
    if (!gArgs.GetBoolArg("-rescan", false))
    {
        CWalletDB walletdb(*walletInstance->dbw);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = FindForkInGlobalIndex(chainActive, locator);
    }

    walletInstance->m_last_block_processed = chainActive.Tip();
    RegisterValidationInterface(walletInstance);

    if (chainActive.Tip() && chainActive.Tip() != pindexRescan)
    {
        //We can't rescan beyond non-pruned blocks, stop and throw an error
        //this might happen if a user uses an old wallet within a pruned node
        // or if he ran -disablewallet for a longer time, then decided to re-enable
        if (fPruneMode)
        {
            CBlockIndex *block = chainActive.Tip();
            while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->nTx > 0 && pindexRescan != block)
                block = block->pprev;

            if (pindexRescan != block) {
                InitError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
                return nullptr;
            }
        }

        uiInterface.InitMessage(_("Rescanning..."));
        LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight);

        // No need to read and scan block if block was created before
        // our wallet birthday (as adjusted for block time variability)
        while (pindexRescan && walletInstance->nTimeFirstKey && (pindexRescan->GetBlockTime() < (walletInstance->nTimeFirstKey - TIMESTAMP_WINDOW))) {
            pindexRescan = chainActive.Next(pindexRescan);
        }

        nStart = GetTimeMillis();
        {
            WalletRescanReserver reserver(walletInstance);
            if (!reserver.reserve()) {
                InitError(_("Failed to rescan the wallet during initialization"));
                return nullptr;
            }
            walletInstance->ScanForWalletTransactions(pindexRescan, nullptr, reserver, true);
        }
        LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
        walletInstance->SetBestChain(chainActive.GetLocator());
        walletInstance->dbw->IncrementUpdateCounter();

        // Restore wallet transaction metadata after -zapwallettxes=1
        if (gArgs.GetBoolArg("-zapwallettxes", false) && gArgs.GetArg("-zapwallettxes", "1") != "2")
        {
            CWalletDB walletdb(*walletInstance->dbw);

            for (const CWalletTx& wtxOld : vWtx)
            {
                uint256 hash = wtxOld.GetHash();
                std::map<uint256, CWalletTx>::iterator mi = walletInstance->mapWallet.find(hash);
                if (mi != walletInstance->mapWallet.end())
                {
                    const CWalletTx* copyFrom = &wtxOld;
                    CWalletTx* copyTo = &mi->second;
                    copyTo->mapValue = copyFrom->mapValue;
                    copyTo->vOrderForm = copyFrom->vOrderForm;
                    copyTo->nTimeReceived = copyFrom->nTimeReceived;
                    copyTo->nTimeSmart = copyFrom->nTimeSmart;
                    copyTo->fFromMe = copyFrom->fFromMe;
                    copyTo->strFromAccount = copyFrom->strFromAccount;
                    copyTo->nOrderPos = copyFrom->nOrderPos;
                    walletdb.WriteTx(*copyTo);
                }
            }
        }
    }
    walletInstance->SetBroadcastTransactions(gArgs.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    {
        LOCK(walletInstance->cs_wallet);
        LogPrintf("setKeyPool.size() = %u\n",      walletInstance->GetKeyPoolSize());
        LogPrintf("mapWallet.size() = %u\n",       walletInstance->mapWallet.size());
        LogPrintf("mapAddressBook.size() = %u\n",  walletInstance->mapAddressBook.size());
    }

    return walletInstance;
}

std::atomic<bool> CWallet::fFlushScheduled(false);

void CWallet::postInitProcess(CScheduler& scheduler)
{
    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ReacceptWalletTransactions();

    // Run a thread to flush wallet periodically
    if (!CWallet::fFlushScheduled.exchange(true)) {
        scheduler.scheduleEvery(MaybeCompactWalletDB, 500);
    }
}

bool CWallet::BackupWallet(const std::string& strDest)
{
    return dbw->Backup(strDest);
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
    fInternal = false;
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
    fInternal = internalIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

void CMerkleTx::SetMerkleBranch(const CBlockIndex* pindex, int posInBlock)
{
    // Update the tx's hashBlock
    hashBlock = pindex->GetBlockHash();

    // set the position of the transaction in the block
    nIndex = posInBlock;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex* &pindexRet) const
{
    if (hashUnset())
        return 0;

    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return std::max(0, (COINBASE_MATURITY+1) - GetDepthInMainChain());
}

bool CWalletTx::AcceptToMemoryPool(const CAmount& nAbsurdFee, CValidationState& state)
{
    // We must set fInMempool here - while it will be re-set to true by the
    // entered-mempool callback, if we did not there would be a race where a
    // user could call sendmoney in a loop and hit spurious out of funds errors
    // because we think that the transaction they just generated's change is
    // unavailable as we're not yet aware its in mempool.
    bool ret = ::AcceptToMemoryPool(mempool, state, tx, nullptr /* pfMissingInputs */,
                                nullptr /* plTxnReplaced */, false /* bypass_limits */, nAbsurdFee);
    fInMempool |= ret;
    return ret;
}

static const std::string OUTPUT_TYPE_STRING_LEGACY = "legacy";
static const std::string OUTPUT_TYPE_STRING_P2SH_SEGWIT = "p2sh-segwit";
static const std::string OUTPUT_TYPE_STRING_BECH32 = "bech32";

OutputType ParseOutputType(const std::string& type, OutputType default_type)
{
    if (type.empty()) {
        return default_type;
    } else if (type == OUTPUT_TYPE_STRING_LEGACY) {
        return OUTPUT_TYPE_LEGACY;
    } else if (type == OUTPUT_TYPE_STRING_P2SH_SEGWIT) {
        return OUTPUT_TYPE_P2SH_SEGWIT;
    } else if (type == OUTPUT_TYPE_STRING_BECH32) {
        return OUTPUT_TYPE_BECH32;
    } else {
        return OUTPUT_TYPE_NONE;
    }
}

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OUTPUT_TYPE_LEGACY: return OUTPUT_TYPE_STRING_LEGACY;
    case OUTPUT_TYPE_P2SH_SEGWIT: return OUTPUT_TYPE_STRING_P2SH_SEGWIT;
    case OUTPUT_TYPE_BECH32: return OUTPUT_TYPE_STRING_BECH32;
    default: assert(false);
    }
}

void CWallet::LearnRelatedScripts(const CPubKey& key, OutputType type)
{
    if (key.IsCompressed() && (type == OUTPUT_TYPE_P2SH_SEGWIT || type == OUTPUT_TYPE_BECH32)) {
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        // Make sure the resulting program is solvable.
        assert(IsSolvable(*this, witprog));
        AddCScript(witprog);
    }
}

void CWallet::LearnAllRelatedScripts(const CPubKey& key)
{
    // OUTPUT_TYPE_P2SH_SEGWIT always adds all necessary scripts for all types.
    LearnRelatedScripts(key, OUTPUT_TYPE_P2SH_SEGWIT);
}

CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type)
{
    switch (type) {
    case OUTPUT_TYPE_LEGACY: return key.GetID();
    case OUTPUT_TYPE_P2SH_SEGWIT:
    case OUTPUT_TYPE_BECH32: {
        if (!key.IsCompressed()) return key.GetID();
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        if (type == OUTPUT_TYPE_P2SH_SEGWIT) {
            return CScriptID(witprog);
        } else {
            return witdest;
        }
    }
    default: assert(false);
    }
}

std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key)
{
    CKeyID keyid = key.GetID();
    if (key.IsCompressed()) {
        CTxDestination segwit = WitnessV0KeyHash(keyid);
        CTxDestination p2sh = CScriptID(GetScriptForDestination(segwit));
        return std::vector<CTxDestination>{std::move(keyid), std::move(p2sh), std::move(segwit)};
    } else {
        return std::vector<CTxDestination>{std::move(keyid)};
    }
}

CTxDestination CWallet::AddAndGetDestinationForScript(const CScript& script, OutputType type)
{
    // Note that scripts over 520 bytes are not yet supported.
    switch (type) {
    case OUTPUT_TYPE_LEGACY:
        return CScriptID(script);
    case OUTPUT_TYPE_P2SH_SEGWIT:
    case OUTPUT_TYPE_BECH32: {
        WitnessV0ScriptHash hash;
        CSHA256().Write(script.data(), script.size()).Finalize(hash.begin());
        CTxDestination witdest = hash;
        CScript witprog = GetScriptForDestination(witdest);
        // Check if the resulting program is solvable (i.e. doesn't use an uncompressed key)
        if (!IsSolvable(*this, witprog)) return CScriptID(script);
        // Add the redeemscript, so that P2WSH and P2SH-P2WSH outputs are recognized as ours.
        AddCScript(witprog);
        if (type == OUTPUT_TYPE_BECH32) {
            return witdest;
        } else {
            return CScriptID(witprog);
        }
    }
    default: assert(false);
    }
}

bool CWallet::CreateWithdrawal(const CAmount& nAmount, const CAmount& nFee, const CAmount& nMainchainFee, const std::string& strDestination, const std::string& strRefundDestination, std::string& strFail, uint256& txid, uint256& id)
{
    if (!(nAmount > 0)) {
        strFail = "Invalid amount - must be greater than 0.";
        return false;
    }
    if (!(nFee > 0)) {
        strFail = "Invalid fee - must be greater than 0.";
        return false;
    }
    if (!(nMainchainFee > 0)) {
        strFail = "Invalid mainchain fee - must be greater than 0.";
        return false;
    }
    if (nAmount <= nFee) {
        strFail = "Invalid amount - must be greater than fee.";
        return false;
    }

    CTxDestination dest = DecodeDestination(strDestination, true /*fMainchain */);
    if (!IsValidDestination(dest)) {
        strFail = "Invalid destination";
        return false;
    }

    CTxDestination refundDest = DecodeDestination(strRefundDestination, false /*fMainchain */);
    if (!IsValidDestination(refundDest)) {
        strFail = "Invalid refund destination";
        return false;
    }

    CAmount nTotal = nAmount + nFee + nMainchainFee;

    LOCK2(cs_main, cs_wallet);

    // Select coins to cover withdrawal
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true /* fOnlySafe */);
    std::set<CInputCoin> setCoins;
    CAmount nAmountRet = CAmount(0);
    if (!SelectCoins(vCoins, nTotal, setCoins, nAmountRet)) {
        strFail = "Could not collect enough coins to cover withdrawal!\n";
        return false;
    }

    CMutableTransaction mtx;

    // Handle change
    const CAmount nChange = nAmountRet - nTotal;
    CReserveKey reserveKey(this);
    if (nChange > 0) {
        CScript scriptChange;

        // Reserve a new keypair from the pool
        CPubKey vchPubKey;
        if (!reserveKey.GetReservedKey(vchPubKey))
        {
            strFail = "Keypool ran out, please call keypoolrefill first!\n";
            return false;
        }
        scriptChange = GetScriptForDestination(vchPubKey.GetID());

        CTxOut out(nChange, scriptChange);
        if (!IsDust(out, ::dustRelayFee))
            mtx.vout.push_back(out);
    }

    // Add Withdrawalinputs
    for (const auto& coin : setCoins) {
        mtx.vin.push_back(CTxIn(coin.outpoint.hash, coin.outpoint.n, CScript()));
    }

    // Add Withdrawalburn output
    mtx.vout.push_back(CTxOut(nAmount + nMainchainFee, CScript() << OP_RETURN));

    // Withdrawaldata ouput
    SidechainWithdrawal wt;
    wt.nSidechain = THIS_SIDECHAIN;
    wt.strDestination = strDestination;
    wt.strRefundDestination = strRefundDestination;
    wt.amount = nAmount + nMainchainFee;
    wt.hashBlindTx = CTransaction(mtx).GetHash();
    wt.mainchainFee = nMainchainFee;

    id = wt.GetID();

    mtx.vout.push_back(CTxOut(CAmount(0), wt.GetScript()));

    // Dummy sign txn to calculate required feees
    std::set<CInputCoin> setCoinsTemp = setCoins;
    if (!DummySignTx(mtx, setCoinsTemp)) {
        strFail = "Dummy signing transaction for required fee calculation failed!\n";
        return false;
    }

    // Get transaction size with dummy signatures
    unsigned int nBytes = GetVirtualTransactionSize(mtx);

    // Calculate fee
    CCoinControl coinControl;
    FeeCalculation feeCalc;
    CAmount nFeeNeeded = GetMinimumFee(nBytes, coinControl, ::mempool, ::feeEstimator, &feeCalc);

    // Check that the fee is valid for relay
    if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
        strFail = "Transaction too large for fee policy!\n";
        return false;
    }

    if (nFee < nFeeNeeded) {
        strFail = "The fee you have set is too small!\n";
        return false;
    }

    // Remove dummy signatures
    for (auto& vin : mtx.vin) {
        vin.scriptSig = CScript();
        vin.scriptWitness.SetNull();
    }

    // Sign inputs
    const CTransaction txToSign = mtx;
    int nIn = 0;
    for (const auto& coin : setCoins) {
        const CScript& scriptPubKey = coin.txout.scriptPubKey;
        SignatureData sigdata;

        if (!ProduceSignature(
                    TransactionSignatureCreator(this, &txToSign, nIn,
                        coin.txout.nValue, SIGHASH_ALL),
                    scriptPubKey, sigdata)) {
            strFail = "Signing inputs failed!\n";
            return false;
        } else {
            UpdateTransaction(mtx, nIn, sigdata);
        }

        nIn++;
    }

    // Broadcast transaction
    CWalletTx wtx;
    wtx.mapValue["comment"] = "WT";
    wtx.fTimeReceivedIsTxTime = true;
    wtx.fFromMe = true;
    wtx.BindWallet(this);

    wtx.SetTx(MakeTransactionRef(std::move(mtx)));

    CValidationState state;
    if (!CommitTransaction(wtx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit withdrawal transaction! Reject reason: " + FormatStateMessage(state) + "\n";
        return false;
    }

    txid = wtx.GetHash();

    return true;
}

bool CWallet::CreateWithdrawalRefundRequest(const uint256& id, const std::vector<unsigned char>& vchSig, std::string& strFail, uint256& txid)
{
    if (mempool.WithdrawalRefundExists(id)) {
        strFail = "A refund request is already in the mempool for this withdrawal!";
        return false;
    }

    CScript script = GenerateWithdrawalRefundRequest(id, vchSig);

    CWalletTx wtx;
    wtx.mapValue["comment"] = "WithdrawalRefund Request";
    wtx.fTimeReceivedIsTxTime = true;
    wtx.fFromMe = true;
    wtx.BindWallet(this);

    CReserveKey reserveKey(this);
    CRecipient recipient = {script, 0, false};
    CCoinControl coinControl;
    int nChangePosRet = -1;
    CAmount nFeeRequired = 0;
    std::string strError = "";
    if (!CreateTransaction(std::vector<CRecipient> { recipient }, wtx, reserveKey, nFeeRequired, nChangePosRet, strError, coinControl)) {
        strFail = "Failed to create refund tx! Reason: " + strError + "\n";
        return false;
    }

    CValidationState state;
    if (!CommitTransaction(wtx, reserveKey, g_connman.get(), state)) {
        strFail = "Failed to commit refund tx! Reject reason: " + FormatStateMessage(state) + "\n";
        return false;
    }

    txid = wtx.GetHash();

    return true;
}
