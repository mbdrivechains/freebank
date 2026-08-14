// Copyright (c) 2017-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain.h>

#include <clientversion.h>
#include <core_io.h>
#include <base58.h>
#include <script/standard.h>
#include <hash.h>
#include <streams.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>

#include <algorithm>
#include <sstream>

const uint32_t nType = 1;
const uint32_t nVersion = 1;

uint256 SidechainObj::GetHash(void) const
{
    uint256 ret;
    if (sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP)
        ret = SerializeHash(*(SidechainWithdrawal *) this);
    else
    if (sidechainop == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP)
        ret = SerializeHash(*(SidechainWithdrawalBundle *) this);
    else
    if (sidechainop == DB_SIDECHAIN_DEPOSIT_OP)
        ret = SerializeHash(*(SidechainDeposit *) this);

    return ret;
}

std::string SidechainObj::ToString(void) const
{
    std::stringstream str;
    str << "sidechainop=" << sidechainop << std::endl;
    return str.str();
}

std::string SidechainWithdrawal::ToString() const
{
    std::stringstream str;
    str << "sidechainop=" << sidechainop << std::endl;
    str << "nSidechain=" << std::to_string(nSidechain) << std::endl;
    str << "destination=" << strDestination << std::endl;
    str << "amount=" << FormatMoney(amount) << std::endl;
    str << "mainchainFee=" << FormatMoney(mainchainFee) << std::endl;
    str << "status=" << GetStatusStr() << std::endl;
    str << "hashBlindTx=" << hashBlindTx.ToString() << std::endl;
    return str.str();
}

std::string SidechainWithdrawal::GetStatusStr(void) const
{
    if (status == WITHDRAWAL_UNSPENT) {
        return "Unspent";
    }
    else
    if (status == WITHDRAWAL_IN_BUNDLE) {
        return "Pending - in WithdrawalBundle";
    }
    else
    if (status == WITHDRAWAL_SPENT) {
        return "Spent";
    }
    return "Unknown";
}

std::string SidechainWithdrawalBundle::ToString() const
{
    std::stringstream str;
    str << "sidechainop=" << sidechainop << std::endl;
    str << "nSidechain=" << std::to_string(nSidechain) << std::endl;
    str << "tx=" << CTransaction(tx).ToString() << std::endl;
    str << "status=" << GetStatusStr() << std::endl;
    return str.str();
}

std::string SidechainWithdrawalBundle::GetStatusStr(void) const
{
    if (status == WITHDRAWAL_BUNDLE_CREATED) {
        return "Created";
    }
    else
    if (status == WITHDRAWAL_BUNDLE_FAILED) {
        return "Failed";
    }
    else
    if (status == WITHDRAWAL_BUNDLE_SPENT) {
        return "Spent";
    }
    return "Unknown";
}

std::string SidechainDeposit::ToString() const
{
    std::stringstream str;
    str << "sidechainop=" << sidechainop << std::endl;
    str << "nSidechain=" << std::to_string(nSidechain) << std::endl;
    str << "strDest=" << strDest << std::endl;
    str << "payout=" << FormatMoney(amtUserPayout) << std::endl;
    str << "mainchaintxid=" << dtx.GetHash().ToString() << std::endl;
    str << "nBurnIndex=" << std::to_string(nBurnIndex) << std::endl;
    str << "nTx=" << std::to_string(nTx) << std::endl;
    str << "hashMainchainBlock=" << hashMainchainBlock.ToString() << std::endl;
    str << "inputs:\n";
    for (const CTxIn& in : dtx.vin) {
        str << in.prevout.ToString() << std::endl;
    }
    return str.str();
}

SidechainObj* ParseSidechainObj(const std::vector<unsigned char>& vch)
{
    if (vch.size() == 0)
        return NULL;

    const char *vch0 = (const char *) &vch.begin()[0];
    CDataStream ds(vch0, vch0+vch.size(), SER_DISK, CLIENT_VERSION);

    // Unserialize can throw on a malformed/truncated payload. These objects are
    // heap-allocated before the throw, and this function is reached pre-cost from
    // an unauthenticated peer's OP_RETURN at ATMP (validation.cpp), so an
    // un-freed throw is a repeatable, unbanned memory leak. Fail closed instead:
    // delete and return NULL, which every caller already treats as "reject".
    if (*vch0 == DB_SIDECHAIN_WITHDRAWAL_OP) {
        SidechainWithdrawal *obj = new SidechainWithdrawal;
        try {
            obj->Unserialize(ds);
        } catch (const std::exception&) {
            delete obj;
            return NULL;
        }
        return obj;
    }
    else
    if (*vch0 == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP) {
        SidechainWithdrawalBundle *obj = new SidechainWithdrawalBundle;
        try {
            obj->Unserialize(ds);
        } catch (const std::exception&) {
            delete obj;
            return NULL;
        }
        return obj;
    }
    else
    if (*vch0 == DB_SIDECHAIN_DEPOSIT_OP) {
        SidechainDeposit *obj = new SidechainDeposit;
        try {
            obj->Unserialize(ds);
        } catch (const std::exception&) {
            delete obj;
            return NULL;
        }
        return obj;
    }

    return NULL;
}

struct CompareMainchainFee
{
    bool operator()(const SidechainWithdrawal& a, const SidechainWithdrawal& b) const
    {
        // C6-B: TOTAL ORDER. mainchainFee is user-chosen, so ties are the common
        // case; an unstable std::sort left tied elements in libstdc++/libc++
        // order, which differs between the Linux and macOS binaries -> the bundle
        // payout order diverged -> the exact-tx replication check
        // (validation.cpp) rejected across platforms = chain split. Tie-break on
        // GetID() (a hash, platform-identical and unique per row) so the order is
        // deterministic regardless of standard library or sort algorithm.
        if (a.mainchainFee != b.mainchainFee)
            return a.mainchainFee > b.mainchainFee;
        return a.GetID() < b.GetID();
    }
};

void SortWithdrawalByFee(std::vector<SidechainWithdrawal>& vWT)
{
    std::sort(vWT.begin(), vWT.end(), CompareMainchainFee());
}

struct CompareWithdrawalBundleHeight
{
    bool operator()(const SidechainWithdrawalBundle& a, const SidechainWithdrawalBundle& b) const
    {
        return a.nHeight > b.nHeight;
    }
};

void SortWithdrawalBundleByHeight(std::vector<SidechainWithdrawalBundle>& vWithdrawalBundle)
{
    std::sort(vWithdrawalBundle.begin(), vWithdrawalBundle.end(), CompareWithdrawalBundleHeight());
}

void SelectUnspentWithdrawal(std::vector<SidechainWithdrawal>& vWT)
{
    vWT.erase(std::remove_if(vWT.begin(), vWT.end(),[](const SidechainWithdrawal& wt)
                {return wt.status != WITHDRAWAL_UNSPENT;}), vWT.end());
}

CScript SidechainObj::GetScript(void) const
{
    CDataStream ds (SER_DISK, CLIENT_VERSION);
    if (sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP)
        ((SidechainWithdrawal *) this)->Serialize(ds);
    else
    if (sidechainop == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP)
        ((SidechainWithdrawalBundle *) this)->Serialize(ds);
    else
    if (sidechainop == DB_SIDECHAIN_DEPOSIT_OP)
        ((SidechainDeposit *) this)->Serialize(ds);

    CScript scriptPubKey;

    std::vector<unsigned char> vch(ds.begin(), ds.end());

    // Add script header
    scriptPubKey.resize(5 + vch.size());
    scriptPubKey[0] = OP_RETURN;
    scriptPubKey[1] = 0xAC;
    scriptPubKey[2] = 0xDC;
    scriptPubKey[3] = 0xF6;
    scriptPubKey[4] = 0x6F;

    // Add vch (serialization)
    memcpy(&scriptPubKey[5], vch.data(), vch.size());

    return scriptPubKey;
}

std::string GenerateDepositAddress(const std::string& strDestIn)
{
    std::string strDepositAddress = "";

    // Append sidechain number
    strDepositAddress += "s";
    strDepositAddress += std::to_string(THIS_SIDECHAIN);
    strDepositAddress += "_";

    // Append destination
    strDepositAddress += strDestIn;
    strDepositAddress += "_";

    // Generate checksum
    std::vector<unsigned char> vch;
    vch.resize(CSHA256::OUTPUT_SIZE);
    CSHA256().Write((unsigned char*)&strDepositAddress[0], strDepositAddress.size()).Finalize(&vch[0]);
    std::string strHash = HexStr(vch.begin(), vch.end());

    // Append checksum (first 6 letters of SHA-256 hash hex)

    strDepositAddress += strHash.substr(0, 6);

    return strDepositAddress;
}

bool ParseDepositAddress(const std::string& strAddressIn, std::string& strAddressOut, unsigned int& nSidechainOut)
{
    if (strAddressIn.empty())
        return false;

    // First character should be 's'
    if (strAddressIn.front() != 's')
        return false;

    unsigned int delim1 = strAddressIn.find_first_of("_") + 1;
    unsigned int delim2 = strAddressIn.find_last_of("_");

    if (delim1 == std::string::npos || delim2 == std::string::npos)
        return false;
    if (delim1 >= strAddressIn.size() || delim2 + 1 >= strAddressIn.size())
        return false;

    std::string strSidechain = strAddressIn.substr(1, delim1);
    if (strSidechain.empty())
        return false;

    // Get sidechain number
    try {
        nSidechainOut = std::stoul(strSidechain);
    } catch (...) {
        return false;
    }

    // Check sidechain number is within range
    if (nSidechainOut > 255)
        return false;

    // Get substring without prefix or suffix
    strAddressOut = strAddressIn.substr(delim1, delim2 - delim1);
    if (strAddressOut.empty())
        return false;

    // Get substring without checksum (for generating our checksum)
    std::string strNoCheck = strAddressIn.substr(0, delim2 + 1);
    if (strNoCheck.empty())
        return false;

    // Generate checksum (first 6 bytes of SHA-256 hash)
    std::vector<unsigned char> vch;
    vch.resize(CSHA256::OUTPUT_SIZE);
    CSHA256().Write((unsigned char*)&strNoCheck[0], strNoCheck.size()).Finalize(&vch[0]);
    std::string strHash = HexStr(vch.begin(), vch.end());

    if (strHash.size() != 64)
        return false;

    // Get checksum from address string
    std::string strCheck = strAddressIn.substr(delim2 + 1, strAddressIn.size());
    if (strCheck.size() != 6)
        return false;

    // Compare address checksum with our checksum
    if (strCheck != strHash.substr(0, 6))
        return false;

    return true;
}

bool GetDepositPayoutOutput(const SidechainDeposit& deposit, CTxOut& out)
{
    // Withdrawal-bundle change return: recorded in the DB, paid to nobody.
    if (deposit.strDest == SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST)
        return false;

    // Nothing left after the deposit fee. Note the comparison is strict: a
    // payout EQUAL to the fee would leave a zero-value output, which is not
    // worth creating and which the old validator demanded anyway - the dust
    // case that halted the deposit queue.
    if (deposit.amtUserPayout <= SIDECHAIN_DEPOSIT_FEE)
        return false;

    // strDest is depositor-chosen data carried up from the L1 transaction, so
    // it is untrusted input and may be anything at all. An undecodable
    // destination is a user error, not a reason to stop the chain: the deposit
    // is recorded and the value simply stays burned on the mainchain.
    const CTxDestination dest = DecodeDestination(deposit.strDest);
    if (!IsValidDestination(dest))
        return false;

    out = CTxOut(deposit.amtUserPayout - SIDECHAIN_DEPOSIT_FEE,
                 GetScriptForDestination(dest));
    return true;
}

bool ClaimDepositPayoutOutput(const CTxOut& required,
                              const std::vector<CTxOut>& vout,
                              std::set<size_t>& setClaimed)
{
    for (size_t i = 0; i < vout.size(); i++) {
        // Skip outputs an earlier deposit in this block already claimed. This
        // single line IS the D-1 fix: without it one output settles every
        // identical debt and the miner keeps the rest.
        if (setClaimed.count(i))
            continue;
        if (vout[i] == required) {
            setClaimed.insert(i);
            return true;
        }
    }
    return false;
}

bool ClaimWithdrawalBurn(const SidechainWithdrawal& withdrawal,
                         const std::vector<CTxOut>& vout,
                         std::set<size_t>& setClaimed)
{
    // The amount/fee validity is a property of the withdrawal, not of any
    // particular output - if it fails, no output can back it.
    if (!(withdrawal.amount > 0 && withdrawal.mainchainFee > 0
            && withdrawal.amount > withdrawal.mainchainFee))
        return false;

    for (size_t i = 0; i < vout.size(); i++) {
        // Skip a burn an earlier withdrawal in this tx already claimed. This is
        // the C6-A fix: without it one OP_RETURN backs every identical-amount
        // withdrawal row and each is paid, minting/draining the rest.
        if (setClaimed.count(i))
            continue;
        const CTxOut& o = vout[i];
        if (o.scriptPubKey.size() && o.scriptPubKey[0] == OP_RETURN
                && o.nValue == withdrawal.amount) {
            setClaimed.insert(i);
            return true;
        }
    }
    return false;
}
