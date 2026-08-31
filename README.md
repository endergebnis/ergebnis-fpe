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
| `make_fingerprint` (encrypt) | ~832  | ~1.20 M |
| `recover_values` (decrypt)   | ~1060 | ~0.94 M |

Built with `-C target-cpu=native` and `lto = "fat"` (see `.cargo/config.toml`).
Decrypt is slower because it ends in `decode`/`from_base62` with 128-bit
arithmetic (base-24 value > 2^64); AVX2 helps the encrypt side, not the u128
division on the decrypt side.

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
  token, latency drops from ~1.33 ms to ~1 µs and throughput rises from ~755/s
  to ~0.94–1.05 M/s — a ~1250× (decrypt) to ~1400× (encrypt) speedup.
- Timestamps are captured in UTC; only differences between timestamps matter,
  so the local timezone is irrelevant to the token logic.
- Memory is per-invocation and released on exit. There is no long-lived process
  and no database, so steady-state memory is zero.

## Server / in-process

For a request path (a web server validating a visitor token per request), do
**not** spawn the binary per token — that pays fork/exec + dynamic linking +
dotenv + chrono on every call. Embed the core as a library and call it
in-process instead.

| Mode | Latency per token | Throughput (1 core) |
|------|-------------------|---------------------|
| CLI, one process per token | ~1.33 ms | ~755 tokens/s |
| In-process (library) | ~1.0 µs | ~0.94–1.05 M tokens/s |

The 1.33 ms of a CLI call is ~99.9% process startup, not crypto: the FPE core
runs in ~1 µs. In-process that startup cost is paid once at boot, and every
validation afterwards costs only the ~1 µs of the core.

What ~1 M validations/s actually means for a service: one core saturates at
roughly 1 M token-validations per second. Validation is a ~1 µs CPU operation,
so it disappears next to network I/O and TLS:

| Requests/s | Share of one core |
|-----------|-------------------|
| 10,000 | ~1% |
| 100,000 | ~10% |
| 1,000,000 | ~100% (full core) |

Because validation is stateless, it also scales with worker threads. Measured
on this box (8 physical cores / 16 threads, Xeon E5-2667 v3):

| Threads | Throughput | Speedup |
|---------|------------|---------|
| 1 | ~0.86 M req/s | 1× |
| 8 | ~5.6 M req/s | 6.5× |
| 16 | ~7.6 M req/s | 8.7× |

Scaling is sub-linear: ~6.5× at 8 threads and only ~8.7× at 16, because the
16 logical CPUs are 8 physical cores + hyperthreads (SMT adds little for this
integer-bound workload) and memory bandwidth becomes the limiter. Plan on
~0.85 M req/s per *physical* core, not per thread. The token layer is never
the bottleneck at realistic traffic — the network stack is.

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
