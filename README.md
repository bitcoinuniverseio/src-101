# SRC-101

**Documentation site: <https://bitcoinuniverseio.github.io/src-101/>**

SRC-101 is a **name registry** on Bitcoin. Its `deploy`, `mint`, `transfer`, `setrecord` and `renew` operations are UTF-8 JSON documents carried in **transaction output scripts** through the Bitcoin Stamps data carrier, the same carrier SRC-20 uses. A name is not owned outright: it is leased for a paid term, and when the term ends the name returns to the pool.

This repository holds the documentation. It does not hold the protocol: SRC-101 originated in the Bitcoin Stamps community, and the rules documented here are the ones the Bitcoin Stamps indexer actually enforces.

## Pages

| Page | What is in it |
| --- | --- |
| [Overview](https://bitcoinuniverseio.github.io/src-101/) | Plain-language explanation, the name lifecycle, what SRC-101 shares with SRC-20 and where they diverge |
| [Specification](https://bitcoinuniverseio.github.io/src-101/specification.html) | 83 numbered normative rules: carrier, activation heights, key sets, field rules, the five operations, validity, the Counterparty relationship |
| [Guide](https://bitcoinuniverseio.github.io/src-101/guide.html) | Worked payloads with computed byte framing, term pricing arithmetic, reading a result, product support |
| [Reference](https://bitcoinuniverseio.github.io/src-101/reference.html) | Status codes, storage tables, indexer semantics, reorg behaviour, limitations, security, implementation checklist |
| [Test vectors](https://bitcoinuniverseio.github.io/src-101/vectors.html) | Valid, invalid and excluded vectors, plus a stateful name lifecycle from claim to lapse to re-claim |
| [Validator](https://bitcoinuniverseio.github.io/src-101/validator.html) | Client-side payload validator with a block-height control, so you can watch the 872200 rule change take effect |
| [Changelog](https://bitcoinuniverseio.github.io/src-101/changelog.html) | Protocol changes by block height, and document versions |

## The protocol in one table

| | |
| --- | --- |
| Chain and network | Bitcoin mainnet only |
| Model | One entry per name per namespace: owner, previous owner, expiry, records, primary flag |
| Operations | `deploy`, `mint`, `transfer`, `setrecord`, `renew` |
| Protocol string | `src-101`, compared case-insensitively, hyphen required |
| Names | Base64, standard alphabet, at most 128 characters encoded, compared after decoding and lower-casing |
| Numerics | Coerced to **integer**, must be at least 0. No ceiling, no decimals |
| Term | `dua` years of exactly 31536000 seconds, rounded up to a multiple of the namespace's `idua` |
| Payment | `mint` and `renew` must pay a computed amount to output 0, to an address in the namespace's `rec` |
| Carriers | Bare multisig with ARC4, and P2WSH. Both require `keyburn == 1` |
| Live since | Block 870652. **No end block** |
| Lifecycle | Experimental |
| Document version | 2026.09.01 |

## Five things implementers get wrong

1. **Extra fields are fatal, not ignored.** `deploy`, `transfer`, `setrecord` and `renew` compare the payload's key set to the operation's with a symmetric difference that must be empty. One extra key and the payload is **excluded**: no row, no status code, no trace. `mint` is the sole exception, and only from block 872200.
2. **`prim` must be the string, not the boolean.** The validator compares against `"true"` and `"false"` as text. A JSON `true` fails, and because field failure is fatal in SRC-101, the whole operation is discarded.
3. **A multi-name mint partially succeeds.** Names already held with a live expiry are quietly dropped and the rest are minted. The payment is computed over the full submitted list, so you pay for what you asked for and receive what was free. Only if every name is taken does it fail, with `DM`.
4. **A transfer wipes the records.** The owners row written by a transfer clears the resolved Bitcoin address, the resolved Ethereum address and the text record, and sets the primary flag false. The expiry is carried over unchanged.
5. **`lim` is not a mint limit.** It is never enforced as a cap on anything. Its only role is as a presence sentinel: a namespace whose `lim` is zero is treated as not deployed, so every later operation gets `ND`. Deploying with `lim` zero creates a namespace nobody can use.

A sixth, for readers rather than implementers: **expiry is absolute**. No grace period, no redemption window, no automatic renewal. Renew before the block timestamp reaches your expiry, or the name is open to anyone.

## Same carrier as SRC-20, almost nothing else in common

Both protocols use the `stamp:` prefix, bare multisig or P2WSH, and require `keyburn == 1`. An indexer reads them out of a transaction with the same code. Above that line:

| | SRC-20 | SRC-101 |
| --- | --- | --- |
| Genesis | 788041 | **870652** |
| Counterparty carriage | Ignored from block 796000 | **Never ends** |
| Extra JSON fields | Tolerated | **Rejected** for four of five operations |
| Bad field | Invalid, with a status code | **Excluded**, with no record |
| Numerics | `Decimal`, ceiling 2^64 minus 1 | `int`, no ceiling |
| Protocol fee | None | **Required** for mint and renew |
| Ledger hash | Contributes, cross-checked externally | **Contributes nothing**, no cross-check |
| Marketplace | StampDEX, external execution | **None** |

The SRC-20 documentation is the sibling of this site: <https://bitcoinuniverseio.github.io/src-20/>.

## The three activation heights, and the one that is misdescribed

| Height | Effect |
| --- | --- |
| 870652 | SRC-101 genesis. Nothing below counts, and no end block exists |
| 872200 | `img` leaves the `mint` key set, and `mint` matching relaxes from exact to superset |
| 940000 | Output 0's value becomes readable **on the P2WSH branch** |

Block 940000 is frequently described as when P2WSH carriage begins for SRC-101. It is not. P2WSH carriage works from block 865000, a gate shared with SRC-20 that predates SRC-101 entirely. What 940000 changes is whether the decoder reads output 0's value on that branch, which is exactly what mint and renew payments are measured against. Below it, a P2WSH-carried mint or renew fails with `IRV` no matter what was actually paid.

## Bitcoin Universe support

From the ecosystem capability registry, and nothing beyond it:

- **Core**: view, discover, view-collection, view-activity, view-transaction
- **Wallet**: view, send, receive
- **Inscribe**: mint, transfer

**There is no marketplace entry for SRC-101 in the registry at all.** No Bitcoin Universe product implements list, buy, offer, settle or any other trade path. This is not a narrowed marketplace with unsupported actions recorded against it, as SRC-20 has; the protocol has no marketplace record. The registry also records no source of truth, no indexer, and no freshness, confirmation or reorg policy for SRC-101.

Note also that Inscribe's two recorded actions are mint and transfer. There is no `deploy`, no `renew` and no `setrecord`: opening a namespace, renewing a term and writing records are operations you would need to construct yourself.

## Grounding

Every normative statement is traceable to code:

- [`stampchain-io/btc_stamps`](https://github.com/stampchain-io/btc_stamps), the Bitcoin Stamps indexer, version 1.9.3. Rules quoted from `indexer/src/index_core/src101.py`, `indexer/src/config.py`, `indexer/src/index_core/models.py`, `indexer/src/index_core/transaction_utils.py`, `indexer/src/index_core/database.py`, `indexer/src/index_core/blocks.py` and `indexer/src/index_core/util.py`.
- [Stampchain](https://stampchain.io/), the public explorer and API.
- The Bitcoin Universe ecosystem capability registry, for product support claims.

Where the code does something that reads as a defect rather than a design, the specification marks the rule as an **Observation** and says so, rather than describing an intention the code does not have. Three claims that circulate about SRC-101 were checked against the source and corrected; the [changelog](https://bitcoinuniverseio.github.io/src-101/changelog.html) lists them.

## Building and contributing

Static hand-authored HTML, CSS and vanilla JavaScript. No build step, no dependencies, no CDN, no web fonts, no trackers. Serve the directory with any static file server:

```
python -m http.server 8000
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the constraints that are deliberate, [SECURITY.md](SECURITY.md) for private vulnerability reporting, and [SUPPORT.md](SUPPORT.md) for where to ask questions.

## Elsewhere

- Central documentation portal: <https://docs.bitcoinuniverse.io>
- Report a vulnerability privately: <https://github.com/bitcoinuniverseio/src-101/security/advisories/new>

Brand asset attribution is in [`assets/ATTRIBUTION.md`](assets/ATTRIBUTION.md). Licensed under [MIT](LICENSE).
