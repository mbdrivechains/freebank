// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CREDITBIND_H
#define BITCOIN_CREDITBIND_H

// What a credit transaction's input signatures commit to beyond the classic digest (v1.0.2, NEXT 40,
// docs-local/CREDIT_SIGHASH_SPEC.md). Versions 11-17 carry an op and a payload that the txid covers but the two
// input digests did not, so a relay or a block producer could rewrite what an unconfirmed credit transaction does
// (a DISCOUNT into an ENDORSE, a RECOURSE's payer, a TOPUP's partner) and every input signature stayed valid.
//
// From the binding height on (SCRIPT_VERIFY_CREDIT_BINDING), both digests append CreditBindingHash after the lock
// time. It covers the op and the payload's BINDING FORM: the payload decoded, its signature fields emptied (each
// signature, and which approver made it), the BillDiscount link's height set to 0, and re-encoded. Those fields
// stay out because several ceremonies sign some inputs before another party adds its payload signature (discount,
// settle, netting, note lock); every one of them is checked against its own digest or the chain. Everything else is
// bound, so a field added to a payload later is bound by default. A payload that doesn't decode is bound as its raw
// bytes (such a transaction is invalid anyway).
//
// Built into the consensus library (interpreter.cpp calls it), so it uses only the payload structs' inline
// serializers, never the families' decode functions.

#include <uint256.h>

#include <stdint.h>

class CTransaction;

/** True for the credit versions whose op and payload the input digests bind (11-18; the gram-notes release added
 *  the issued-token version 18 and binds every annex). */
bool IsCreditBindingVersion(int32_t nVersion);

/** SHA256d of the op and the payload's binding form; meaningful only when IsCreditBindingVersion(tx.nVersion). */
uint256 CreditBindingHash(const CTransaction& tx);

#endif // BITCOIN_CREDITBIND_H
