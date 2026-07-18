# SRC-101 documentation

Bitcoin Universe documentation for SRC-101 on Bitcoin.

## Combined documentation home

This SRC-101 repository is kept as a nested local checkout inside the [Stamps, SRC-20 and SRC-101 documentation set](https://bitcoinuniverse.github.io/src-20/) and publishes independently at [bitcoinuniverse.github.io/src-101](https://bitcoinuniverse.github.io/src-101/). SRC-101 remains a distinct protocol reference. Its field, operation, and lifecycle rules should not be inferred from the parent SRC-20 materials.

## What this covers

SRC-101 is a name and record system in the Bitcoin Stamps ecosystem. Its active reference indexer validates a closed set of JSON fields for deploy, mint, transfer, renew, and setrecord operations.

## State model

A deployed namespace is referenced by its deploy transaction hash. Token IDs are base64-encoded labels, and owner state has a renewal and record lifecycle. Exact field sets are operation-specific.

## Documentation site

- Overview: [bitcoinuniverse.github.io/src-101](https://bitcoinuniverse.github.io/src-101/)
- Field reference: [reference.html](https://bitcoinuniverse.github.io/src-101/reference.html)
- Build and verification playbook: [guide.html](https://bitcoinuniverse.github.io/src-101/guide.html)

## Core rules

- The reference parser requires p = src-101 and exact operation-specific field sets.
- p and op are normalized to uppercase by the active processor after parsing.
- tick is normalized to lowercase and a SHA3-256 ticker hash is calculated.
- tokenid is base64-encoded, normalized, and rejected when it contains forbidden special characters.
- deploy hash is required for mint, transfer, renew, and setrecord.
- Mint requires a duration in years, called dua, and has recipient, coefficient, and signature constraints.

## Source material

- [Stampchain BTC Stamps reference indexer](https://github.com/stampchain-io/btc_stamps/blob/main/indexer/src/index_core/src101.py)
- [Stampchain FAQ](https://stampchain.io/faq)
- [Stamps official press-kit assets](https://github.com/stampchain-io/stampchain.io/tree/dev/static/img/presskit)

## Scope

SRC-101 has strict, revision-sensitive field validation. Generate payloads from the active parser contract and regression-test them before using real names.
