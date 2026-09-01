# Contributing

Thanks for helping keep the SRC-101 documentation accurate.

## The one rule that matters

Every normative statement on this site must be traceable to code that actually enforces it, or to an operator decision recorded in a repository. If you cannot point at the enforcing implementation, do not state the rule as protocol behaviour. Write what is verifiable and mark the rest as unverified, or omit it.

Grounding sources used to build this site:

- `stampchain-io/btc_stamps`, the Bitcoin Stamps indexer, for parsing, validity and storage.
- `stampchain-io/stampchain.io`, the public explorer and v2 API, for published field shapes.
- The Bitcoin Universe ecosystem capability registry, for what Bitcoin Universe products actually support.

Where the reference implementation does something that reads as a defect, say so and mark the rule as an **Observation**. Do not describe an intention the code does not have, and do not quietly document the behaviour you think was meant.

## Working on the site

There is no build step and no package manager. Clone the repository and open the HTML files directly, or serve the directory with any static file server.

```
python -m http.server 8000
```

Constraints that are deliberate, please keep them:

- Static hand-authored HTML, CSS and vanilla JavaScript. No framework, no bundler, no CDN, no web fonts, no trackers.
- All ordinary content must be readable with JavaScript disabled. JavaScript only enhances search, the theme toggle, and the validator.
- Light and dark themes must both meet WCAG 2.2 AA contrast.
- The layout must work down to 320px wide with no horizontal page overflow. Wide tables and code blocks scroll inside their own container.
- Diagrams are inline SVG with a `<title>` and `<desc>`, using CSS custom properties so they stay legible in both themes.
- The single accent colour is reserved for an active registration. The muted tone is for anything expired, lapsed or renewable. Do not introduce a third status colour.
- **No em dash characters anywhere**, in prose, titles, meta descriptions or Open Graph tags. Where a source string contains one, transcribe it as a backslash-u escape for code point 2014 rather than as the literal character; `assets/validator.js` does exactly this for the indexer's special-character class. Grep the tree for code point 2014 before you push.
- Example addresses and keys must be checksum-valid and derived from fixed text, never copied from a transaction on chain. A broken example teaches the wrong lesson, and a real one implies a claim about somebody's coins.

## When you change page content

Update `search-index.json` so the new heading is findable, and add the page to `sitemap.xml` and `llms.txt` if it is new. If you change a normative rule, add a line to `changelog.html`. Rule numbers are assigned once and never reused: retire a number rather than renumbering.

## When you change the validator

`assets/validator.js` reimplements the indexer's pre-chain checks. Every check it makes must correspond to a rule in the specification, and every rule it cannot check must appear in the "what this tool cannot know" list. If you add a check, add its vector to `vectors.html` too.

## Pull requests

Branch from `main`, keep the change focused, and describe in the pull request which source you verified the change against. Documentation changes that assert protocol behaviour without a source will be asked for one.
