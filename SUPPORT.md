# Support

## Questions about this documentation

Open an issue on `bitcoinuniverseio/src-101`. Include the page and the section heading you are asking about.

## Questions about the SRC-101 protocol itself

SRC-101 originated in the Bitcoin Stamps community, not in Bitcoin Universe. Protocol questions are best answered by the people who maintain the indexers:

- Bitcoin Stamps indexer: <https://github.com/stampchain-io/btc_stamps>
- Stampchain explorer and API: <https://stampchain.io/>

## Questions about Bitcoin Universe products

The central documentation portal is <https://docs.bitcoinuniverse.io>. For a specific product, use the issue tracker of that product's repository.

Note that no Bitcoin Universe product implements a trade path for SRC-101, and Bitcoin Universe does not operate a namespace. If you are asking who to contact about a specific namespace, the answer is whoever deployed it, and this project has no way to find that out for you.

## Suspected vulnerability

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## What we cannot help with

We cannot recover funds, reverse a broadcast Bitcoin transaction, un-mint a name, restore an expired registration, or change how an independent indexer interprets your transaction.

Two situations come up often and both have the same answer, which is that nothing can be done:

- **Your name expired.** There is no grace period and no redemption window in the protocol. Once the block timestamp passes the expiry, the name is claimable by anyone, and if somebody else claimed it, it is theirs.
- **Your transaction confirmed but nothing happened.** Almost always this means the payload was excluded: a key set that did not match exactly, a `prim` written as a JSON boolean, or a numeric field written with a decimal point. An excluded payload leaves no record anywhere, which is why there is nothing to look up. Paste the payload into the [validator](https://bitcoinuniverseio.github.io/src-101/validator.html) with the block height set, and it will name the cause.
