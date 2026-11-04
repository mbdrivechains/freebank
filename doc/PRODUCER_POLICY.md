# Who produces FreeBank blocks, and what they include

## Block production until 31 October 2027 (v1.1.0)

Until 31 October 2027 Michael Blowes bids to produce FreeBank blocks on eCash, so that blocks keep coming while few
others bid. Anyone may bid, and the highest bid wins. For that period:

- His bid is a fixed **2,000 sats (0.00002 ECX) per eCash block**, paid as the fee of the bid transaction, published
  here, and is never raised to beat another bidder. The bidding stops on 31 October 2027.
- His block producer includes every valid transaction it receives - price and backing reports and pool swaps
  included - and publishes an inclusion log (`getinclusionlog`, and `inclusion.log` in the node's data folder). Where a
  reporter sends two reports for one block, the producer keeps the latest valid one it received, by a fixed rule, and
  the log records the replacement.
- He, any entity he controls, and anyone acting for him hold no gram notes, gold or dollar tokens, pool shares or stake
  in any house; post no issuer bond and put no liquidity in any pool; don't lend to, fund, guarantee or arrange for any
  issuer or house; buy nothing to support a price and rescue no house.

The no-forfeit rule for price reporters ends at a height that a later release sets once a second, unconnected bidder
is producing blocks (see the parameter schedule, `vGramSchedule` in `src/consensus/params.h`).

The producer is a block producer only. It runs no house, no money changer and no custody. FreeBank has no protocol
fee: no part of any transaction is set aside for a developer or a foundation. A block's coinbase pays whoever produced it the
block's transaction fees plus 1,000 sats per deposit, and the fee for creating a token or a pool is burned.

## What every block includes

The producer includes every valid transaction it receives. From v0.2.19 it fills each block in this order (until
then, by fee rate alone):

1. **Transactions that run a house's solvency clock, oldest first**: redemptions and discharges, demands, protests,
   insolvency claims, term-deposit withdrawals and claims, and house attestations. They may use up to half of each
   block, so a demand or a protest never waits behind cheaper traffic.
2. **Everything else, by fee rate**, as in Bitcoin Core.

It filters nothing by who sent a transaction, which house it concerns or what it says. A transaction is left out only if
it is invalid, pays less than the minimum relay fee, or doesn't fit; one that doesn't fit goes into a later block.

You can check this: every block is public, the explorer at https://explorer.ecxfreebank.com shows each block's producer
(the coinbase tag `ecxfreebank.com`), and the code above is in this repository.

## Run your own node, seed or producer

- **Node:** download a release, check it (VERIFY.md) and follow FREEBANK_GUIDE.md. A node needs a synced eCash node and
  the drivechain enforcer.
- **Seed:** a node that accepts connections (`-listen=1`, port 8455 open) helps new nodes find the network. Tell us its
  address and we will list it.
- **Producer:** any node with an eCash wallet can bid (`refreshbmm`, or an engine such as BitWindow). The highest bid
  for an eCash block wins it. Set `coinbasetag=<name>` so the explorer shows your blocks.
