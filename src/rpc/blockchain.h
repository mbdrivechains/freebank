// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_BLOCKCHAIN_H
#define BITCOIN_RPC_BLOCKCHAIN_H

#include <amount.h>

#include <stdint.h>
#include <utility>
#include <vector>

class CBlock;
class CBlockIndex;
class CTransaction;
class CTxUndo;
class UniValue;

static constexpr int NUM_GETBLOCKSTATS_PERCENTILES = 5;

/** Callback for when block tip changed. */
void RPCNotifyBlockChange(bool ibd, const CBlockIndex *);

/** Block description to JSON */
UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false);

/** Mempool information to JSON */
UniValue mempoolInfoToJSON();

/** Mempool to JSON */
UniValue mempoolToJSON(bool fVerbose = false);

/** Block header to JSON */
UniValue blockheaderToJSON(const CBlockIndex* blockindex);

/** Used by getblockstats to get feerates at different percentiles by weight */
void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight);

/** Fee of a non-coinbase tx from its undo record (sum of spent prevouts minus
 *  sum of outputs). False, never an assert, on a vin/undo size mismatch or an
 *  out-of-MoneyRange sum. */
bool TxFeeFromUndo(const CTransaction& tx, const CTxUndo& txundo, CAmount& fee);

#endif

