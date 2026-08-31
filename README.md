# ErgebnisFPE

Stateless visitor tokens with a rotating key ring (sliding window).

ErgebnisFPE turns a timestamp into an opaque, reversible token. The core is a
format-preserving encryption (an 8-round Feistel network over Z_24) combined
with the Julian Day Number and the Maya Long Count. On top sits generation
tracking: every window (`WINDOW_MINUTES`, default 15) gets its own key, so a
token ages from MAIN to SECONDARY to TERTIARY and then expires.

Validation is fully stateless. There is no blacklist flag and no database. An
old token (SECONDARY/TERTIARY) is automatically up-leveled to a fresh MAIN-key
token when it is validated.

## Build

    cargo build --release

## Usage

    # generate SERVER_SECRET and WINDOW_MINUTES into .env
    ./target/release/ergebnis-fpe init

    # create a token (default: now)
    ./target/release/ergebnis-fpe make

    # create a token for an explicit ISO timestamp
    ./target/release/ergebnis-fpe make "2026-08-31T14:07:23.456"

    # validate a token
    ./target/release/ergebnis-fpe validate "<TOKEN>"

## Token format

    <generation>.<fingerprint>

- `generation` is the plaintext window index (15-minute slots since year 0).
- `fingerprint` is the lossless timestamp (year down to millisecond),
  FPE-encrypted and encoded in base62.

## Validation tiers

| Delta | Tier | Result |
|-------|------|--------|
| 0 | MAIN | valid, fresh |
| 1 | SECONDARY | valid, deprecated, a new MAIN token is issued |
| 2 | TERTIARY | valid, strongly deprecated, a new MAIN token is issued |
| 3+ | - | expired / invalid |

## Configuration (.env)

    SERVER_SECRET=<64-bit integer, keep secret>
    WINDOW_MINUTES=15

## Benchmarks

Measured locally with `cargo build --release`, `/usr/bin/time -v` (CLI) and
`ergebnis-fpe bench` (core, in-process).

### FPE core (in-process)

`ergebnis-fpe bench` measures the pure crypto without process startup:

| Operation | ns/op | ops/s |
|-----------|-------|-------|
| `make_fingerprint` (encrypt) | ~950  | ~1.05 M |
| `recover_values` (decrypt)   | ~1065 | ~0.94 M |

### Full CLI call (one process per token)

Measured over 200 runs; memory via `/usr/bin/time -v`.

| Metric | Value |
|--------|-------|
| Binary size | 447,168 bytes (~437 KiB, stripped) |
| Peak RAM (one call) | 2,176 KB (~2.13 MiB) |
| Wall time (one call) | ~1.33 ms |
| Throughput (one process per call) | ~755 tokens/s |
| CPU | single-threaded, ~100% of one core per call |

### Notes

- The FPE core is alloc-free (fixed arrays, no Vec/String in the hot path) and
  costs ~1 µs per token. That is <0.1% of the 1.33 ms call; the rest is process
  startup (fork/exec + dotenv + chrono).
- Called in-process (a long-lived service) instead of spawning one process per
  token, throughput rises from ~755/s to ~1 M/s, roughly 1500x.
- Timestamps are captured in UTC; only differences between timestamps matter,
  so the local timezone is irrelevant to the token logic.
- Memory is per-invocation and released on exit. There is no long-lived process
  and no database, so steady-state memory is zero.

## Server / in-process

For a request path (a web server validating a visitor token per request), do
**not** spawn the binary per token — that pays fork/exec + dotenv + chrono on
every call. Instead embed the core as a library and call it in-process. The
FPE core runs in ~1 µs, so a single thread handles roughly 1 M validations/s,
which is enough even for DDoS-level traffic.

Add the crate as a dependency and call the same primitives the CLI uses:

```rust
use ergebnis_fpe::{make_token, validate_token, Timestamp, DEFAULT_WINDOW_MINUTES};

// Shared once per process (no per-request state, no DB, no locks).
let secret: u64 = std::env::var("SERVER_SECRET")?.parse()?;
let window: i64 = DEFAULT_WINDOW_MINUTES;

// Issue (login / first visit):
let token = make_token(&Timestamp::now(), secret, window);

// Validate (every request), e.g. in an axum/actix handler:
match validate_token(&token, secret, window) {
    Ok(v) => {
        // v.tier: MAIN | SECONDARY | TERTIARY
        // v.issued_at, v.age_minutes
        // v.fresh_token: Some(new MAIN token) when the old one was deprecated
    }
    Err(e) => {
        // expired, forged, or malformed -> reject
    }
}
```

Because validation is stateless, any number of workers can share the same
secret with no coordination. The only per-request cost is the FPE core.

## Formalization

See [FORMALIZATION.md](FORMALIZATION.md) for the full mathematical definition
of the pipeline.

## Disclaimer

This is a self-built construction and has not been cryptographically audited.
Do not use it to protect high-value secrets.
