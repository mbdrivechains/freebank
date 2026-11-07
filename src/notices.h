// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FREEBANK_NOTICES_H
#define FREEBANK_NOTICES_H

/** The user warnings legal chose (gateway/docs/legal/USER_WARNINGS_2026-11.md section 2; Michael's OK 2026-11-05).
 *  Keep the wording exactly as legal wrote it: S (short line), N (standard notice), L6 (the warnings field) and the
 *  role lines R1-R5 for the RPC help. NOTICE.md (the full notice, F) ships in every release tarball. */

#define FREEBANK_NOTICE_URL "https://github.com/mbdrivechains/freebank/blob/master/NOTICE.md"

/** S: in -version and -help (one paragraph: FormatParagraph wraps it). */
#define FREEBANK_NOTICE_SHORT \
    "FreeBank is experimental software: you can lose what you put in. It is not a bank; houses are run by " \
    "independent operators and can fail. Not advice. Full notice: NOTICE.md (in the release tarball, or " \
    FREEBANK_NOTICE_URL ").\n"

/** N: printed once, at a data directory's first start, to the terminal and debug.log (and kept as NOTICE.txt). */
#define FREEBANK_NOTICE_STANDARD \
    "Notice. FreeBank is experimental, open-source software. It has not been audited, and you can lose what\n" \
    "you put into it. FreeBank is not a bank. Nothing on it is insured or guaranteed by any government or by\n" \
    "its developers.\n" \
    "\n" \
    "Houses are run by independent operators, not by FreeBank's developers. A house can suspend payment or\n" \
    "fail, and its notes may not be paid in full. Notes are denominated in grams of gold and paid in sECX (ECX\n" \
    "held on FreeBank) at a rate each house sets itself, or in gold tokens on Ethereum if the house delivers\n" \
    "them. FreeBank checks only a house's sECX, never its gold tokens, and shows whether the house pays.\n" \
    "Moving sECX back to eCash is slow and needs eCash miners' approval, and sECX can trade below ECX.\n" \
    "\n" \
    "Running a house, issuing tokens or lending to consumers may need a licence where you do it. Nothing here\n" \
    "is an offer of a financial product, or financial, legal or tax advice. FreeBank is not offered where\n" \
    "using it would be unlawful. You are responsible for the laws and taxes that apply to you.\n" \
    "\n" \
    "The full notice: NOTICE.md (in the release tarball, or " FREEBANK_NOTICE_URL ").\n"

/** L6: the RPC `warnings` field of a pre-release build (CLIENT_VERSION_IS_RELEASE false). */
#define FREEBANK_NOTICE_PRERELEASE \
    "This is a pre-release build of experimental software: use only funds you can afford to lose. See NOTICE.md."

/** R1-R5: in the help of the RPCs where someone takes on a role that may need a licence. Assigned by which side
 *  calls each RPC (legal's table 3.1, place 7). */
#define HELP_ROLE_HOUSE \
    "\nRunning a house for others (issuing notes, lending them out, taking deposits or discounting bills) may be\n" \
    "banking, deposit-taking or a financial service where you do it, and need a licence. Gram notes may count as\n" \
    "financial products, such as derivatives, and paying out sECX or gold tokens for notes may count as a\n" \
    "crypto-asset service. That is your responsibility, not FreeBank's developers'.\n"
#define HELP_ROLE_TOKEN_ISSUER \
    "\nIssuing tokens against dollar tokens you hold for others is custody and token issuance, which needs a\n" \
    "licence in most countries.\n"
#define HELP_ROLE_POOL \
    "\nPool shares can lose value against what you put in. A token is only as good as its issuer.\n"
#define HELP_ROLE_BILL \
    "\nBills are for trade between businesses. Credit to consumers, buy-now-pay-later-style credit included,\n" \
    "needs a licence in many countries.\n"

#endif // FREEBANK_NOTICES_H
