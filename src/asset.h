// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ASSET_H
#define BITCOIN_ASSET_H

// BitAssets (tx v10), v0.2.18 (D-2026-10-03-1; layer-B review
// docs-local/reviews/2026-10-02-layer-b/assets.md). One rule per concern,
// shared by mempool acceptance, ConnectBlock and crash replay:
//  - ComputeAssetTags decides every output's colour from the tx and the coins
//    it spends. CheckTxInputs rejects with it; UpdateCoins and RollforwardBlock
//    compute with it; AddCoins only applies the result.
//  - CheckAssetGenesisShape is the context-free v10 shape + metadata rule
//    (CheckTransaction), so mempool and blocks agree.

#include <amount.h>
#include <uint256.h>

#include <string>
#include <vector>

class CTransaction;
class Coin;

enum : uint8_t {
    ASSET_OUT_PLAIN = 0,
    ASSET_OUT_UNITS = 1,     // carries asset units: 1 unit = 1 sat of the output's value
    ASSET_OUT_CONTROL = 2,   // the asset's control coin: no units
};

/** The colour of a tx's outputs. Empty vOut: the tx moves no asset. */
struct AssetTags {
    uint256 assetID;               // the asset's genesis txid
    std::vector<uint8_t> vOut;     // one ASSET_OUT_* per output when non-empty

    bool IsNull() const { return vOut.empty(); }
    uint8_t Get(size_t n) const { return n < vOut.size() ? vOut[n] : ASSET_OUT_PLAIN; }
};

static const size_t ASSET_TICKER_MAX = 12;
static const size_t ASSET_HEADLINE_MAX = 64;
static const uint8_t ASSET_DECIMALS_MAX = 8;

/** The wallet's value for a control coin (policy, not consensus: above the
 *  dust threshold so it relays; consensus only pins its script). */
static const CAmount ASSET_CONTROL_VALUE = 1000;

/** Ticker: 1-12 characters, A-Z and 0-9 only (no look-alike Unicode). */
bool IsValidAssetTicker(const std::string& str);

/** Headline: at most 64 bytes of strict UTF-8 (shortest form, no surrogates,
 *  <= U+10FFFF) with no control or invisible code points. Byte-range checks
 *  only: a consensus rule must not depend on the node's locale. */
bool IsValidAssetHeadline(const std::string& str);

/** Context-free v10 rule (CheckTransaction): at least 2 outputs; vout[0] (the
 *  control coin) and vout[1] (the whole supply, >= 1 unit) pay spendable
 *  scripts; metadata within limits. False with strReason set otherwise. */
bool CheckAssetGenesisShape(const CTransaction& tx, std::string& strReason);

/** The tx versions that may move asset coins: plain transfers (versions 1-9).
 *  A genesis (v10) may not spend them; every FreeBank op version (11-17) and
 *  any other version refuses them. */
bool IsAssetTransferVersion(int nVersion);

/** Decide the colour of tx's outputs from the coins it spends (vSpent[i] is
 *  the coin vin[i] spends). Returns false with strReason set if the tx breaks
 *  an asset rule:
 *  - every coloured input carries the same, non-null asset ID; at most one
 *    control coin;
 *  - a genesis (v10) spends no coloured coin: vout[0] = control, vout[1] = the
 *    supply, asset ID = txid;
 *  - a transfer (plain version): a control input passes to vout[0] (a spendable
 *    script); the leading outputs after it carry EXACTLY the unit inputs, each
 *    > 0; the rest are plain. A unit output to OP_RETURN burns those units;
 *  - coloured inputs are refused in any other version and in any tx that
 *    writes a sidechain object (withdrawal) or a withdrawal refund request.
 *  A tx that spends no coloured coin and is not v10 gets empty tags. */
bool ComputeAssetTags(const CTransaction& tx, const std::vector<const Coin*>& vSpent,
                      AssetTags& tags, std::string& strReason);

#endif // BITCOIN_ASSET_H
