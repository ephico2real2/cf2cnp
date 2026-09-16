# Review — structured logging and the download's three answers (`feat/structured-logging`)

The change: `log/slog` on the HTTP server (`--log-format`, `--log-level`), one `request` line per call with a request
id, every refusal a `refused` line with a reason, `/health` at debug; `/download/{id}` answering 404 (never generated),
410 (expired, with the time) or 200; chart values `logging.format` / `logging.level`. Written by Cursor from a brief,
verified on the built binary (wrong token, empty body, bad JSON, unknown id, a proxy's `X-Request-Id`, a bad `--log-level`
refused at start; the token and the wrong value absent from the log), then reviewed.

## First pass — on `0985642`

Nine claims, each reviewer in its own `git archive` copy: Codex (`gpt-5.6-sol`, xhigh, a shell — it built, ran and
wrote focused reproductions) and Cursor (`agent --mode ask`, read-only). Every verdict re-read against the cited
lines before acceptance.

| Claim | Codex | Cursor | Accepted |
|---|---|---|---|
| C1 no secret ever logged | REFUTED | REFUTED | yes — `query` was `r.URL.RawQuery` verbatim; a parse error's message can carry body bytes (Codex: a 5,000-digit `destination_port` echoed whole) |
| C2 one line per request, always | REFUTED | REFUTED | yes — the `request` line ran after `next.ServeHTTP`, not deferred; a panic (Codex: `request_lines=0 panic_escaped_middleware=boom`) is recovered by `net/http` outside the middleware |
| C3 request id | CONFIRMED | CONFIRMED | — (Cursor: the tests would not notice the header set *after* the handler, since the recorder accepts late `Header().Set`) |
| C4 statusWriter | CONFIRMED | CONFIRMED | Cursor's side note accepted: `http.MaxBytesReader` type-asserts `requestTooLarge()` on the writer without `Unwrap`, so a 413 no longer marked the connection to close |
| C5 download's three answers | semantics CONFIRMED; "bounded" REFUTED | CONFIRMED with the same caveat | yes — every JSON generate becomes a tombstone for 24 h (Codex: `cached_responses=1000 … tombstones=1000`); a client that can generate grows the map for a day |
| C6 levels, startup line, bad flags | CONFIRMED | CONFIRMED | — |
| C7 chart and flags | CONFIRMED | CONFIRMED | — (flag beats env, measured) |
| C8 tests assert their names | REFUTED | REFUTED | yes — six tests, not five; several pass with the feature broken (header order, both 404s under one reason, no panic case) |
| C9 no regressions | CONFIRMED | CONFIRMED | — |

## The fixes (second commit)

`params` = the sorted query parameter *names*, never values; every `error` attr through `cutRunes(…, 200)`; a deferred
recover in `logRequests` — `panic` at ERROR with the value and a 4,000-rune stack, a 500 when nothing was written, the
`request` line still emitted; `tombstoneTTL` 1 h; `statusWriter.requestTooLarge()` forwarding the marker; five tests:
the header is present at handler time, a panic yields the 500 and both lines under one id, `?name=s3cret-name` leaves
only `["l7","name"]` in the log, `bad!id` is `download_id_invalid` and an unknown id `download_unknown`, a 5,000-digit
body token leaves a 200-rune `error`.

Measured on the rebuilt binary: `GET /download/x?token=SUPERSECRET&name=shop` → the log carries `params:["name","token"]`
and the string `SUPERSECRET` zero times; the 5,000-digit body → `error` attr of exactly 200 runes; `tombstoneTTL = 1 * time.Hour`.

## Not changed, on purpose

- "Always one line" still means "at the line's level": `/health` is silent at info, a 200 on `/` is silent at warn.
  That is what levels are for; the README says so.
- The YOLO handler logs the namespace the request named (pre-existing behaviour, a value that becomes a policy's
  namespace — not a secret).
