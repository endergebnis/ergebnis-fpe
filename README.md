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

## Formalization

See [FORMALIZATION.md](FORMALIZATION.md) for the full mathematical definition
of the pipeline.

## Disclaimer

This is a self-built construction and has not been cryptographically audited.
Do not use it to protect high-value secrets.
