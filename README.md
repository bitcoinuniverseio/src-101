# SRC-101 documentation

Bitcoin Universe documentation for SRC-101 on Bitcoin.

## What this covers

SRC-101 is a name and record system in the Bitcoin Stamps ecosystem. Its active reference indexer validates a closed set of JSON fields for deploy, mint, transfer, renew, and setrecord operations.

## State model

A deployed namespace is referenced by its deploy transaction hash. Token IDs are base64-encoded labels, and owner state has a renewal and record lifecycle. Exact field sets are operation-specific.

## Documentation site

- Overview: [index.html](index.html)
- Field reference: [reference.html](reference.html)
- Build and verification playbook: [guide.html](guide.html)

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

## Scope

SRC-101 has strict, revision-sensitive field validation. Generate payloads from the active parser contract and regression-test them before using real names.
