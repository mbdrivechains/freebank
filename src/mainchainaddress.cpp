// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mainchainaddress.h>

#include <base58.h>
#include <bech32.h>
#include <chainparams.h>
#include <hash.h>
#include <script/standard.h>
#include <util.h>
#include <utilstrencodings.h>

#include <algorithm>
#include <string.h>

extern bool g_fMainchainMainFamily; // base58.cpp (A9), set from the L1 at init

MainchainAddrParams GetMainchainAddrParams()
{
    MainchainAddrParams p;
    // Keep in step with the P2PKH branch of DecodeDestination(fMainchain=true)
    // in base58.cpp. EncodeMainchainCarrier re-checks the round trip through that
    // decoder, so a divergence fails closed (no withdrawal) rather than storing
    // a destination that pays somewhere else.
    if (gArgs.GetBoolArg("-regtest", false)) {
        p.p2pkh = Params().Base58Prefix(CChainParams::MAINCHAIN_REGTEST_PUBKEY_ADDRESS);
        p.p2sh = std::vector<unsigned char>(1, 196);
        p.hrp = "bcrt";
    } else if (g_fMainchainMainFamily) {
        p.p2pkh = std::vector<unsigned char>(1, 0);
        p.p2sh = std::vector<unsigned char>(1, 5);
        p.hrp = "bc";
    } else {
        p.p2pkh = Params().Base58Prefix(CChainParams::MAINCHAIN_PUBKEY_ADDRESS);
        p.p2sh = std::vector<unsigned char>(1, 196);
        p.hrp = "tb";
    }
    return p;
}

namespace {

/** base58check decode (base58.h declares DecodeBase58Check inline and defines it
 *  in base58.cpp only, so it is not callable from here). Same rule. */
bool DecodeBase58CheckStr(const std::string& str, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(str, vchRet) || vchRet.size() < 4) {
        vchRet.clear();
        return false;
    }
    const uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet[vchRet.size() - 4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool HasPrefix(const std::vector<unsigned char>& data, const std::vector<unsigned char>& prefix, size_t nPayload)
{
    return data.size() == prefix.size() + nPayload && std::equal(prefix.begin(), prefix.end(), data.begin());
}

/** P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG */
bool IsP2PKH(const CScript& spk)
{
    return spk.size() == 25 && spk[0] == OP_DUP && spk[1] == OP_HASH160 && spk[2] == 0x14 &&
           spk[23] == OP_EQUALVERIFY && spk[24] == OP_CHECKSIG;
}

/** Is s a FreeBank sidechain address (any type) on this node's network? */
bool IsSidechainAddress(const std::string& s)
{
    return IsValidDestination(DecodeDestination(s, false /* fMainchain */));
}

} // namespace

bool ParseMainchainAddress(const std::string& str, CScript& spk, std::string& strError)
{
    spk.clear();
    const MainchainAddrParams params = GetMainchainAddrParams();

    std::vector<unsigned char> data;
    if (DecodeBase58CheckStr(str, data)) {
        if (HasPrefix(data, params.p2pkh, 20)) {
            spk = CScript() << OP_DUP << OP_HASH160
                            << std::vector<unsigned char>(data.begin() + params.p2pkh.size(), data.end())
                            << OP_EQUALVERIFY << OP_CHECKSIG;
            return true;
        }
        if (HasPrefix(data, params.p2sh, 20)) {
            spk = CScript() << OP_HASH160
                            << std::vector<unsigned char>(data.begin() + params.p2sh.size(), data.end())
                            << OP_EQUAL;
            return true;
        }
        strError = IsSidechainAddress(str)
            ? "this is a FreeBank (sidechain) address; give the mainchain address to withdraw to"
            : "base58 address of another network or of an unsupported type";
        return false;
    }

    const bech32::DecodeResult dec = bech32::DecodeEx(str);
    if (dec.encoding == bech32::Encoding::INVALID || dec.data.empty()) {
        strError = "not a valid mainchain address";
        return false;
    }
    if (dec.hrp != params.hrp) {
        strError = IsSidechainAddress(str)
            ? "this is a FreeBank (sidechain) address; give the mainchain address to withdraw to"
            : "bech32 address of another network (expected prefix \"" + params.hrp + "1\")";
        return false;
    }
    const int nVersion = dec.data[0];
    std::vector<unsigned char> program;
    if (!ConvertBits<5, 8, false>(program, dec.data.begin() + 1, dec.data.end())) {
        strError = "invalid witness program padding";
        return false;
    }
    if (nVersion == 0) {
        if (dec.encoding != bech32::Encoding::BECH32) {
            strError = "a version 0 witness address must use the bech32 (BIP173) checksum";
            return false;
        }
        if (program.size() != 20 && program.size() != 32) {
            strError = "a version 0 witness program must be 20 or 32 bytes";
            return false;
        }
        spk = CScript() << OP_0 << program;
        return true;
    }
    if (nVersion == 1) {
        if (dec.encoding != bech32::Encoding::BECH32M) {
            strError = "a version 1 (taproot) address must use the bech32m (BIP350) checksum";
            return false;
        }
        if (program.size() != 32) {
            strError = "a version 1 witness program must be 32 bytes (taproot)";
            return false;
        }
        spk = CScript() << OP_1 << program;
        return true;
    }
    strError = "witness version " + std::to_string(nVersion) + " is not supported for withdrawals";
    return false;
}

std::string EncodeMainchainAddress(const CScript& spk)
{
    const MainchainAddrParams params = GetMainchainAddrParams();
    if (IsP2PKH(spk)) {
        std::vector<unsigned char> data = params.p2pkh;
        data.insert(data.end(), spk.begin() + 3, spk.begin() + 23);
        return EncodeBase58Check(data);
    }
    if (spk.IsPayToScriptHash()) {
        std::vector<unsigned char> data = params.p2sh;
        data.insert(data.end(), spk.begin() + 2, spk.begin() + 22);
        return EncodeBase58Check(data);
    }
    int nVersion;
    std::vector<unsigned char> program;
    if (spk.IsWitnessProgram(nVersion, program)) {
        std::vector<unsigned char> values = {(unsigned char)nVersion};
        ConvertBits<8, 5, true>(values, program.begin(), program.end());
        return nVersion == 0 ? bech32::Encode(params.hrp, values) : bech32::EncodeM(params.hrp, values);
    }
    return "";
}

std::string EncodeMainchainCarrier(const CScript& spk)
{
    std::string strCarrier;
    if (IsP2PKH(spk)) {
        // The consensus decoder reads mainchain P2PKH with the L1 family prefix,
        // so the carrier is the user's L1 string itself.
        std::vector<unsigned char> data = GetMainchainAddrParams().p2pkh;
        data.insert(data.end(), spk.begin() + 3, spk.begin() + 23);
        strCarrier = EncodeBase58Check(data);
    } else if (spk.IsPayToScriptHash()) {
        // Sidechain SCRIPT_ADDRESS prefix (125): what the decoder expects.
        std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), spk.begin() + 2, spk.begin() + 22);
        strCarrier = EncodeBase58Check(data);
    } else {
        int nVersion;
        std::vector<unsigned char> program;
        if (!spk.IsWitnessProgram(nVersion, program))
            return "";
        const bool fV0 = nVersion == 0 && (program.size() == 20 || program.size() == 32);
        const bool fTaproot = nVersion == 1 && program.size() == 32;
        if (!fV0 && !fTaproot)
            return "";
        // Sidechain HRP and the BIP173 checksum, ON PURPOSE even for v1: it is
        // what the frozen consensus decoder (bech32::Decode) accepts.
        std::vector<unsigned char> values = {(unsigned char)nVersion};
        ConvertBits<8, 5, true>(values, program.begin(), program.end());
        strCarrier = bech32::Encode(Params().Bech32HRP(), values);
    }
    // Post-condition: the consensus decoder must map the carrier to exactly spk.
    if (strCarrier.empty() || MainchainPayoutScript(strCarrier) != spk)
        return "";
    return strCarrier;
}

CScript MainchainPayoutScript(const std::string& strStored)
{
    // Exactly the expression CreateWithdrawalBundleTx / VerifyWithdrawalBundles use.
    return GetScriptForDestination(DecodeDestination(strStored, true /* fMainchain */));
}

CScript MainchainPayoutScriptAnyFamily(const std::string& strStored)
{
    std::vector<unsigned char> data;
    if (DecodeBase58CheckStr(strStored, data) && data.size() == 21 && (data[0] == 0 || data[0] == 111)) {
        return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(data.begin() + 1, data.end())
                         << OP_EQUALVERIFY << OP_CHECKSIG;
    }
    const CTxDestination dest = DecodeDestination(strStored, true /* fMainchain */);
    if (!IsValidDestination(dest) || boost::get<CKeyID>(&dest))
        return CScript(); // a P2PKH under some other prefix cannot happen; be strict anyway
    return GetScriptForDestination(dest);
}

std::string MainchainDisplayAddress(const std::string& strStored)
{
    const CTxDestination dest = DecodeDestination(strStored, true /* fMainchain */);
    if (!IsValidDestination(dest))
        return strStored;
    const std::string strL1 = EncodeMainchainAddress(GetScriptForDestination(dest));
    return strL1.empty() ? strStored : strL1;
}
