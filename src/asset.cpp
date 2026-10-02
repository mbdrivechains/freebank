// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <asset.h>

#include <coins.h>
#include <primitives/transaction.h>
#include <script/script.h>

bool IsValidAssetTicker(const std::string& str)
{
    if (str.empty() || str.size() > ASSET_TICKER_MAX)
        return false;
    for (unsigned char c : str) {
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
            return false;
    }
    return true;
}

/** Code points a headline may not contain: controls, separators and the
 *  invisible / formatting / private / non-characters that let two headlines
 *  look alike. */
static bool IsForbiddenHeadlineCodePoint(uint32_t cp)
{
    if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return true;          // C0, DEL, C1
    if (cp == 0x00AD || cp == 0x034F || cp == 0x061C) return true;      // soft hyphen, CGJ, ALM
    if (cp == 0x115F || cp == 0x1160 || cp == 0x17B4 || cp == 0x17B5) return true;
    if (cp >= 0x180B && cp <= 0x180E) return true;                      // Mongolian FVS, MVS
    if (cp >= 0x2000 && cp <= 0x200F) return true;                      // odd-width spaces, ZW*, LRM/RLM
    if (cp >= 0x2028 && cp <= 0x202F) return true;                      // separators, bidi embeds, NNBSP
    if (cp >= 0x205F && cp <= 0x206F) return true;                      // MMSP, WJ, invisible ops, bidi isolates
    if (cp == 0x3000 || cp == 0x3164 || cp == 0xFFA0) return true;      // ideographic space, Hangul fillers
    if (cp >= 0xFE00 && cp <= 0xFE0F) return true;                      // variation selectors
    if (cp == 0xFEFF) return true;                                      // BOM / ZWNBSP
    if (cp >= 0xFFF0 && cp <= 0xFFFB) return true;                      // specials, interlinear annotation
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return true;                      // non-characters
    if ((cp & 0xFFFE) == 0xFFFE) return true;                           // U+xxFFFE / U+xxFFFF
    if (cp >= 0xE000 && cp <= 0xF8FF) return true;                      // private use
    if (cp >= 0x1D173 && cp <= 0x1D17A) return true;                    // musical format controls
    if (cp >= 0xE0000 && cp <= 0xE0FFF) return true;                    // tags, VS supplement
    if (cp >= 0xF0000) return true;                                     // supplementary private use
    return false;
}

bool IsValidAssetHeadline(const std::string& str)
{
    if (str.size() > ASSET_HEADLINE_MAX)
        return false;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(str.data());
    const size_t n = str.size();
    size_t i = 0;
    while (i < n) {
        const unsigned char c = p[i];
        uint32_t cp;
        size_t len;
        if (c < 0x80) { cp = c; len = 1; }
        else if (c >= 0xC2 && c <= 0xDF) { cp = c & 0x1F; len = 2; }
        else if (c >= 0xE0 && c <= 0xEF) { cp = c & 0x0F; len = 3; }
        else if (c >= 0xF0 && c <= 0xF4) { cp = c & 0x07; len = 4; }
        else return false;                                  // continuation byte, C0/C1 lead, > F4
        if (i + len > n) return false;
        for (size_t k = 1; k < len; k++) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if (len == 3 && cp < 0x800) return false;           // overlong
        if (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;     // surrogates
        if (IsForbiddenHeadlineCodePoint(cp)) return false;
        i += len;
    }
    return true;
}

bool CheckAssetGenesisShape(const CTransaction& tx, std::string& strReason)
{
    if (tx.vout.size() < 2) { strReason = "bad-asset-genesis-vout-count"; return false; }
    if (tx.vout[0].scriptPubKey.IsUnspendable()) { strReason = "bad-asset-genesis-control-dest"; return false; }
    if (tx.vout[1].scriptPubKey.IsUnspendable()) { strReason = "bad-asset-genesis-supply-dest"; return false; }
    if (tx.vout[1].nValue < 1) { strReason = "bad-asset-genesis-supply"; return false; }
    if (!IsValidAssetTicker(tx.ticker)) { strReason = "bad-asset-genesis-ticker"; return false; }
    if (!IsValidAssetHeadline(tx.headline)) { strReason = "bad-asset-genesis-headline"; return false; }
    if (tx.nDecimals > ASSET_DECIMALS_MAX) { strReason = "bad-asset-genesis-decimals"; return false; }
    // payload: a fixed 32 bytes on the wire; all-zero means "none".
    return true;
}

bool IsAssetTransferVersion(int nVersion)
{
    // The plain versions: 1-9 (the wallet writes 3, CTransaction::CURRENT_VERSION).
    // 10-17 are the genesis and the FreeBank ops; anything else is refused too,
    // so a future op version cannot inherit asset coins by accident.
    return nVersion >= 1 && nVersion < TRANSACTION_BITASSET_CREATE_VERSION;
}

bool ComputeAssetTags(const CTransaction& tx, const std::vector<const Coin*>& vSpent,
                      AssetTags& tags, std::string& strReason)
{
    tags = AssetTags();
    if (tx.IsCoinBase())
        return true;
    if (vSpent.size() != tx.vin.size()) { strReason = "bad-asset-internal-inputs"; return false; }

    uint256 id;
    CAmount nUnitsIn = 0;
    int nControl = 0;
    for (const Coin* coin : vSpent) {
        if (!coin || !coin->IsAssetColoured())
            continue;
        if (coin->assetID.IsNull() || (coin->fBitAsset && coin->fBitAssetControl)) {
            strReason = "bad-asset-input-tag"; return false;
        }
        // Remember the FIRST id and hold every coloured input to it: a plain
        // input in between must not reset it (layer-B review A1).
        if (id.IsNull())
            id = coin->assetID;
        else if (coin->assetID != id) {
            strReason = "bad-asset-inputs-mixed"; return false;
        }
        if (coin->fBitAsset) {
            nUnitsIn += coin->out.nValue;
            if (!MoneyRange(coin->out.nValue) || !MoneyRange(nUnitsIn)) { strReason = "bad-asset-units-range"; return false; }
        }
        if (coin->fBitAssetControl && ++nControl > 1) {
            strReason = "bad-asset-control-multiple"; return false;
        }
    }
    const bool fColouredIn = !id.IsNull();

    if (tx.nVersion == TRANSACTION_BITASSET_CREATE_VERSION) {
        if (fColouredIn) { strReason = "bad-asset-genesis-coloured-input"; return false; }
        // CheckTransaction has already pinned the shape (>= 2 outputs).
        if (tx.vout.size() < 2) { strReason = "bad-asset-genesis-vout-count"; return false; }
        tags.assetID = tx.GetHash();
        tags.vOut.assign(tx.vout.size(), ASSET_OUT_PLAIN);
        tags.vOut[0] = ASSET_OUT_CONTROL;
        tags.vOut[1] = ASSET_OUT_UNITS;
        return true;
    }

    if (!fColouredIn)
        return true;

    if (!IsAssetTransferVersion(tx.nVersion)) { strReason = "bad-asset-input-op"; return false; }
    for (const CTxOut& out : tx.vout) {
        std::vector<unsigned char> vch;
        uint256 wtid;
        std::vector<unsigned char> vchSig;
        if (out.scriptPubKey.IsSidechainObj(vch) || out.scriptPubKey.IsWithdrawalRefundRequest(wtid, vchSig)) {
            strReason = "bad-asset-input-withdrawal"; return false;
        }
    }

    tags.assetID = id;
    tags.vOut.assign(tx.vout.size(), ASSET_OUT_PLAIN);
    size_t n = 0;
    if (nControl == 1) {
        if (tx.vout.empty() || tx.vout[0].scriptPubKey.IsUnspendable()) {
            strReason = "bad-asset-control-dest"; return false;
        }
        tags.vOut[0] = ASSET_OUT_CONTROL;
        n = 1;
    }
    // Exactly the unit inputs, in the leading outputs after the control slot.
    CAmount nUnitsOut = 0;
    while (nUnitsOut < nUnitsIn) {
        if (n >= tx.vout.size()) { strReason = "bad-asset-units-not-conserved"; return false; }
        if (tx.vout[n].nValue <= 0) { strReason = "bad-asset-units-zero-output"; return false; }
        nUnitsOut += tx.vout[n].nValue;
        tags.vOut[n] = ASSET_OUT_UNITS;
        n++;
    }
    if (nUnitsOut != nUnitsIn) { strReason = "bad-asset-units-not-conserved"; return false; }
    return true;
}
