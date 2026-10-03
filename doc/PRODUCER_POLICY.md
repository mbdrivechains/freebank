# Who produces FreeBank blocks, and what they include

## The current producer

FreeBank blocks are blind-merged-mined: anyone running a FreeBank node with an eCash wallet can bid for the right to
produce the next block. At launch, one producer runs the seed node `seed.ecxfreebank.com` and bids for every block. It
does so for twelve months from the mainnet launch, until **31 October 2027**. After that date it stops bidding, and blocks come from whoever bids.

The producer is a block producer only. It runs no house, no money changer and no custody, and it takes no protocol fee:
FreeBank has none.

## What every block includes

The seed node includes every valid transaction it receives. From v0.2.19 it fills each block in this order (until then,
by fee rate alone):

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
