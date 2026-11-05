# Notice

**What FreeBank is.** FreeBank is open-source software (MIT licence, see COPYING), provided as is, with no
warranty. Its developers write and publish the code. They don't run houses, money changers or custody, don't issue
tokens or report prices, and don't check anyone who does.

**You can lose what you put in.** The software is experimental and has not been audited; it may have bugs. Your
keys are yours alone: nobody, including the developers, can recover your funds or reverse a payment.

**Blocks can stop.** FreeBank has new blocks only while someone bids for them on eCash. Until 31 Oct 2027 its developer
bids a fixed amount so that blocks keep coming ([doc/PRODUCER_POLICY.md](doc/PRODUCER_POLICY.md)); anyone may bid, and
the highest bid wins. After that date, if nobody bids, FreeBank stops: coins on it can't move or be withdrawn until
someone does.

**Not a bank, no guarantee.** FreeBank is not a bank. Nothing on it is insured or guaranteed by any government or
by its developers.

**Houses and notes.** A note is a claim on the house that issued it, not on FreeBank, its developers or any gold.
Houses are run by independent operators. A house can suspend payment (it then owes interest on queued demands for
up to 12 months) or fail. If it fails, holders are paid from what the chain can seize, and that may not cover them
in full. Every note shows what its house holds and how it can fail.

**Grams and sECX.** Notes are denominated in grams of gold and paid in sECX at an on-chain gold price. If no price
is available, a house may pay in gold tokens. sECX is ECX held on FreeBank. Moving it back to eCash is slow, needs
eCash miners' approval and isn't guaranteed, and sECX can trade below ECX. ECX's price can fall.

**Gold tokens and pools.** A gold token is only as good as its issuer, who holds the backing elsewhere, and some
issuers can freeze their tokens. Passing the chain's checks is not a guarantee. Pool shares can lose value against
what you put in.

**Roles that may need a licence.** In many countries:
- issuing notes payable on demand and lending them out may be banking or deposit-taking;
- gram notes may be financial products, such as derivatives;
- lending to consumers needs a licence, buy-now-pay-later-style credit included;
- holding tokens for others, or issuing your own against them, is custody and token issuance;
- paying out sECX for notes may count as a crypto-asset service;
- customer-check, sanctions and reporting laws apply to anyone serving the public;
- knowingly false prices are an offence.

If you take on any of these roles, the law where you do it is your responsibility, not the developers'.

**Not an offer, not advice.** Nothing in FreeBank, its documents, its app or its assistant is an offer of a
financial product, or financial, legal or tax advice. FreeBank is not offered where using it would be unlawful. You
are responsible for the laws and taxes that apply to you.

**Test networks.** easynet is a public test network. Its coins, notes and tokens have no value, and it may be
restarted.
