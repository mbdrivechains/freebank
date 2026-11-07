# Notice

**What FreeBank is.** FreeBank is open-source software (MIT licence, see COPYING), provided as is, with no
warranty. Its developers write and publish the code. They don't run houses, money changers or custody, don't issue
tokens or set rates, and don't check anyone who does.

**You can lose what you put in.** The software is experimental and has not been audited; it may have bugs. Your
keys are yours alone: nobody, including the developers, can recover your funds or reverse a payment.

**Blocks can stop.** FreeBank has new blocks only while someone bids for them on eCash. Until 31 Oct 2027 its developer
bids a fixed amount so that blocks keep coming ([doc/PRODUCER_POLICY.md](doc/PRODUCER_POLICY.md)); anyone may bid, and
the highest bid wins. After that date, if nobody bids, FreeBank stops: coins on it can't move or be withdrawn until
someone does.

**Not a bank, no guarantee.** FreeBank is not a bank. Nothing on it is insured or guaranteed by any government or
by its developers.

**Houses and notes.** A note is a claim on the house that issued it, not on FreeBank, its developers or any gold.
Houses are run by independent operators. To issue new notes, a house must hold sECX in escrow on FreeBank worth at
least 10% of its notes and deposits, and show that it controls further sECX worth at least 2% of its notes (checked
at a recent block; it can spend it afterwards), both counted at the highest rate it asked in the last 30 days. It
can fall below either. If a demand goes unpaid past its deadline, the house has 7 days to pay it or to suspend
payment; otherwise it fails. A suspended house owes interest on queued demands, and fails if it hasn't resumed
within 12 months or stops proving its sECX to the chain on schedule. The 7 days are given once in any 180 days: a
new unpaid demand within 180 days of the last one, or of the end of a suspension, fails the house at once. FreeBank
can't see a house's gold tokens or whether its loans are good, so it never closes one for either. If a house fails, holders are paid from what the chain can
seize, mainly its sECX escrow, and that may not cover them in full. The chain can't seize gold tokens a house keeps
elsewhere: holders depend on its owners to pay those out.

**Grams and sECX.** Notes are denominated in grams of gold. A house pays them in sECX at a rate it sets itself and
can lower at any time; you see the rate before you demand. FreeBank sets no gold price. When you redeem, you sign for
what you are paid. A formal demand is paid in sECX at no less than the house's rate when you make it; a later cut
doesn't reduce it. Instead, for 10 g or more, you can ask for gold tokens: one the house's charter names (check which
before you demand), sent on Ethereum to an address you control. FreeBank can't make a house deliver gold tokens. If
they aren't delivered and claimed in time, the house owes you sECX instead, at the lower of its rate when you
demanded and its highest rate in the day before the swap's deadline (about 72 hours after the demand, longer if
FreeBank's blocks stall). If it doesn't pay within a further day, the debt can be protested like any unpaid demand.
If it pays you less than its rate when you demanded and fails within 90 days of paying you, the difference becomes a
claim on it, which may not be paid in full. To receive gold tokens you need an Ethereum address and ETH to move
them, and the token's issuer can freeze an address. sECX is ECX held on FreeBank. Moving it back to eCash is slow,
needs eCash miners' approval and isn't guaranteed, and sECX can trade below ECX. ECX's price can fall.

**Gold tokens and pools.** FreeBank doesn't hold, count or check gold tokens. Each house names in its charter the
gold tokens it pays in kind; FreeBank keeps no list of them and doesn't check the entries. A house may hold fewer
gold tokens than its notes, or none. A gold token is only as good as its issuer, who holds the gold and can freeze
the tokens. Pool shares can lose value against what you put in.

**Roles that may need a licence.** In many countries:
- issuing notes payable on demand and lending them out may be banking or deposit-taking;
- gram notes may be financial products, such as derivatives;
- lending to consumers needs a licence, buy-now-pay-later-style credit included;
- holding tokens for others, or issuing your own against them, is custody and token issuance;
- paying out sECX or gold tokens for notes may count as a crypto-asset service;
- customer-check, sanctions and reporting laws apply to anyone serving the public.

If you take on any of these roles, the law where you do it is your responsibility, not the developers'.

**Not an offer, not advice.** Nothing in FreeBank, its documents, its app or its assistant is an offer of a
financial product, or financial, legal or tax advice. FreeBank is not offered where using it would be unlawful. You
are responsible for the laws and taxes that apply to you.

**Test networks.** easynet is a public test network. Its coins, notes and tokens have no value, and it may be
restarted.
