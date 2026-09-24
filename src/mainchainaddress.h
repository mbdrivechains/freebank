// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAINCHAINADDRESS_H
#define BITCOIN_MAINCHAINADDRESS_H

#include <script/script.h>

#include <string>
#include <vector>

/**
 * Mainchain (L1) withdrawal addresses (v0.2.13 item 5).
 *
 * A withdrawal's L1 destination is stored as a free-form string
 * (SidechainWithdrawal::strDestination). Consensus turns it into the bundle's
 * payout script with GetScriptForDestination(DecodeDestination(str, true))
 * when a bundle is built and verified (validation.cpp CreateWithdrawalBundleTx /
 * VerifyWithdrawalBundles). That decoder follows the L1 only for P2PKH; for P2SH
 * it uses the SIDECHAIN prefix 125, for bech32 the SIDECHAIN HRP (fbk / fbkrt),
 * and it knows only the BIP173 checksum. So v0.2.12 rejected every L1 P2SH,
 * P2WPKH, P2WSH and P2TR address.
 *
 * Fixing the decoder would be a hard fork (a v0.2.12 node would decode the same
 * stored string to nothing and reject the bundle). Instead the wallet/RPC/Qt
 * boundary parses the user's real L1 address and stores a CARRIER string that
 * the unchanged decoder maps to exactly the same L1 script:
 *
 *   L1 P2PKH  1.. / m..  -> the same string (the decoder follows the L1 family)
 *   L1 P2SH   3.. / 2..  -> base58(125 || hash160)        (a914<20>87)
 *   L1 P2WPKH bc1q..     -> bech32 "fbk" v0, 20 bytes      (0014<20>)
 *   L1 P2WSH  bc1q..     -> bech32 "fbk" v0, 32 bytes      (0020<32>)
 *   L1 P2TR   bc1p..     -> bech32 "fbk" v1, 32 bytes, BIP173 checksum (5120<32>)
 *
 * CONSENSUS-FROZEN: stored carriers depend on the exact v0.2.12 decode
 * (DecodeDestination(fMainchain=true), bech32::Decode, SCRIPT_ADDRESS=125,
 * bech32_hrp fbk/fbkrt). Changing any of them splits the chain. The golden
 * pins in mainchainaddress_tests.cpp fail loudly if they change. A future
 * (e.g. Rust) chassis following this chain must reproduce this decode.
 *
 * Carriers are also valid FreeBank sidechain addresses. They are never shown to
 * users: every display goes through MainchainDisplayAddress.
 */

/** Address parameters of the L1 family this node follows. The P2PKH prefix
 *  mirrors DecodeDestination(fMainchain=true) exactly (-regtest -> 111; an L1
 *  that reported chain=main -> 0; otherwise 111). */
struct MainchainAddrParams {
    std::vector<unsigned char> p2pkh;
    std::vector<unsigned char> p2sh;
    std::string hrp;
};
MainchainAddrParams GetMainchainAddrParams();

/** Parse a user-supplied L1 address of this node's L1 family into its
 *  scriptPubKey. Accepts P2PKH, P2SH, P2WPKH, P2WSH (bech32) and P2TR (v1,
 *  32 bytes, bech32m). Rejects everything else with a reason, including
 *  FreeBank sidechain addresses and addresses of another L1 network. */
bool ParseMainchainAddress(const std::string& str, CScript& spk, std::string& strError);

/** The L1 form of a supported payout script (P2PKH, P2SH, v0 witness, v1-v16
 *  witness with bech32m), "" otherwise. */
std::string EncodeMainchainAddress(const CScript& spk);

/** The string to store in SidechainWithdrawal::strDestination for a supported
 *  payout script: one the consensus decoder maps back to exactly spk. "" if the
 *  script type is unsupported or the round trip does not hold (fail closed). */
std::string EncodeMainchainCarrier(const CScript& spk);

/** The L1 payout script a stored destination string yields under consensus
 *  (empty script if it does not decode - a row no bundle can pay). */
CScript MainchainPayoutScript(const std::string& strStored);

/** The payout script a stored destination yields under a decode that does NOT
 *  depend on the L1 family: P2PKH with EITHER mainchain prefix (0 main-family,
 *  111 test/regtest - the script is the same), otherwise exactly
 *  MainchainPayoutScript (the P2SH and bech32 branches of the consensus decoder
 *  never read the family). Used by the withdrawal poison-row guard, which runs
 *  in mempool and block validation where the family (set by the L1 probe) must
 *  not matter. Empty if the string does not decode. */
CScript MainchainPayoutScriptAnyFamily(const std::string& strStored);

/** What to show a user for a stored destination: its L1 address form, or the
 *  stored string itself when it does not decode or has no L1 form. */
std::string MainchainDisplayAddress(const std::string& strStored);

#endif // BITCOIN_MAINCHAINADDRESS_H
