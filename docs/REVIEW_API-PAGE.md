# Review — the API page: version badge, endpoint cards, Try-it-out under each (`feat/api-page-try-it-out`)

Adversarial second-opinion pass, 2026-09-15, on the 8-claim brief for `ae0664a`. Codex (gpt-5.6-sol, xhigh) had a shell
and measured with probes and `go test`; Cursor (Grok 4.6 high fast, ask mode, shell blocked) traced from source. Each
worked on its own `git archive` export; every verdict was re-checked here. The fixes are commit `4bc3bec`.

## Verdicts

| Claim | Codex | Cursor | Decision |
|---|---|---|---|
| C1 every old form control present once | CONFIRMED (DOM probe: 10 controls, 3 options, 5 handlers, 13 functions) | CONFIRMED | — |
| C2 `displayVersion` for the workflows' shapes | REFUTED: a `vnext` tag renders `next` | CONFIRMED | **Rejected** — a `vnext` tag is not a release version; changing the release workflow for it is out of scope |
| C3 the substitutions cannot inject markup | REFUTED: `validHost` permits `<>"'`, the replacer does not escape | REFUTED, the same | **Accepted** — escape at the sink |
| C4 the download id is one safe segment | REFUTED: a flow's `uuid` of `..` → `download_url …/download/..` | CONFIRMED (the `..` case not tried) | **Accepted** — `validDownloadID` server-side, the panel's regex |
| C5 the example never overwrites typed text | REFUTED: whitespace-only text is overwritten | CONFIRMED | **Accepted** — `value === ''` |
| C6 the CSS | CONFIRMED | CONFIRMED (text, not pixels) | — |
| C7 the tests fail on `develop` | CONFIRMED (reverse-applied: build failures) | CONFIRMED (static) | — |
| C8 nothing else changed | CONFIRMED (`--numstat`: 3 files, no handler hunks) | CONFIRMED | — |

## C3 — reflected XSS through `X-Forwarded-Host`

**Finding (both).** `baseURL(r)` (from `Host` / `X-Forwarded-Host`) is substituted into the page's HTML; `validHost` only
rejects `/\?#@` and whitespace, so `<svg>` passes and lands in the page as markup. The line was added by this branch.

**Re-check.** `X-Forwarded-Host: <svg>` on the pre-fix binary is served raw. Cursor also proposed tightening `validHost`
and dropping the `r.Host` fallback — that changes `download_url`, a JSON value, for every caller.

**Decision.** Accepted at the sink: `html.EscapeString` on both substitutions (imported as `stdhtml`; the page's local
variable is `html`). Measured after: `X-Forwarded-Host: <svg>` → `curl -X POST https://&lt;svg&gt;/generate`. Cursor's
`validHost` change rejected (behaviour preservation; wrong layer).

## C4 — the download id

**Finding (Codex).** For a single flow the cache key is the flow's `uuid` (handleGenerate), caller-supplied: `..` makes
`download_url` end in `/download/..`, `a/b` decodes to a two-segment path. The panel encodes the id, which does not help.

**Re-check.** Reproduced against the running binary with the fixture's uuid replaced by `..`.

**Decision.** Accepted: `validDownloadID` (letters, digits, `-`, `_`) in `respond` — an id outside that alphabet is
replaced by a generated one before caching — and the panel refuses such an id before sending. Measured after: the same
request returns `/download/6576f3a5cad7aa14cb625e4edadeacee`.

## C5 — typed whitespace

**Finding (Codex).** `.trim()` treated whitespace-only text as empty; open → close → open replaced it with the example.
**Decision.** Accepted: `input.value === ''`.

## Not asked, and what happened to it

- **Codex:** the `/download/{id}` card said "the server keeps a policy for an hour"; `cleanupCache` evicts after 10
  minutes. **Applied** — the text I wrote had not read the code.
- **Cursor:** none beyond C3's wider fix (above).

## Outcome

Eight claims: three refuted and fixed (C3 by both, C4 and C5 by Codex's measurements where Cursor had confirmed), one
refutation rejected on scope (C2), one "not asked" applied. Cursor implemented the four fixes from a brief; the diff was
read, the suite run (`go test ./... -count=1` green), and both security fixes measured against the rebuilt binary.

## Second pass — on the fixed head `1cbfabd` (PR #3)

The same two models on a 9-claim brief: (A) does each fix close its hole and open no other; (B) what the first pass never
named — two generates in a row, the page behind the lab's Gateway, a token-protected server, the tests with the fixes
reverted, curl users. Codex measured with `go test` and a Node VM driving the page's script; Cursor traced from source.

| Claim | Codex | Cursor | Decision |
|---|---|---|---|
| C1 the escaping covers everything `validHost` admits | CONFIRMED (`h<>&"'=x` → all five escaped, three occurrences) | CONFIRMED | — |
| C2 the download id is one safe segment end to end | REFUTED: `/download/a/b` still reaches `cache["a/b"]` in `handleDownload` | CONFIRMED | **Accepted** — defence in depth: `validDownloadID` in `handleDownload`, 404 |
| C3 typed text is never lost | REFUTED: Clear → fold → unfold loads the example | CONFIRMED: intended — empty is the trigger | **Accepted as a text fix** — the card said "the first time"; it now says "whenever this unfolds with an empty box (so after Clear, too)" |
| C4 "10 minutes" against a 5-minute ticker | CONFIRMED ((10, 15] minutes; 10 is the floor) | CONFIRMED | — |
| C5 two generates in a row | REFUTED: the id and the YAML were current, `#downloadStatus`/`#downloadResult` still showed the previous download | CONFIRMED (missed the stale response) | **Accepted** — both cleared when a new id arrives |
| C6 behind the Gateway, with and without `externalUrl` | CONFIRMED (three header traces) | CONFIRMED | — |
| C7 a token-protected server | REFUTED: "open in a new tab" is a navigation, no bearer header → 401 | CONFIRMED, then volunteered the same | **Accepted** — the link is hidden when a token is in the field |
| C8 the four tests fail with the fixes reverted | CONFIRMED (all four exit 1) | CONFIRMED (static) | — |
| C9 curl users unchanged | CONFIRMED (YAML + Content-Disposition, bare OK, the JSON keys) | CONFIRMED | — |

Cursor (agent mode) implemented the four from a brief; the diff read; `go test ./... -count=1` green; measured on the
rebuilt binary: `GET /download/a/b` → 404; after a second generate the id changed and status/result cleared and the link
hidden; with a token in the field, Send answers `HTTP 200 OK` through fetch and the link stays hidden. Fixes: `a733044`.
