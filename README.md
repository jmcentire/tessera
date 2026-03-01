# Tessera

**Self-Validating Executable Document Format**

The document proves itself. The engine validates the chain. Nothing outside the artifact is consulted.

> The *tessera hospitalis* was a Roman token of mutual recognition — a clay tablet broken between host and guest. The fit proved the relationship without any third party. Tessera the format carries the same property: **the document proves itself.**

## What It Does

A Tessera document carries its data, schema, mutation history, and cryptographic signatures in a single portable artifact. Any conforming engine can:

1. **Replay the full history** from genesis to current state
2. **Verify every mutation** — correct hash chain, valid signatures, authorized actors
3. **Enforce rules** — schema-declared guards and embedded validators prevent invalid transitions
4. **Detect tampering** — any modification to state, chain, or schema breaks verification

**Core principle: cheaters can cheat but they can't hide it.** The engine doesn't prevent invalid mutations — it makes them detectable. Any party who receives a Tessera document can replay the chain and verify every step.

## Features

- **Dual-format serialization** — JSON and CBOR, content-sniffed on load
- **Ed25519 signatures** — every mutation signed by actor, entire document signed by authority
- **SHA-256 hash chain** — content-addressable versioning (hash of state = version)
- **Schema enforcement** — typed fields, transition guards, structural validation
- **Embedded scripting** — Rhai-based validators for complex domain logic (chess rules, contract negotiation, etc.)
- **Execution policy** — control whether embedded code runs: `Disabled`, `TrustKeys`, `TrustAll`
- **Multi-actor support** — different parties sign their own mutations, all verifiable
- **No external dependencies** — fully offline, no server, no database, no blockchain

## Quick Start

```bash
# Build everything
cargo build --workspace

# Run all tests (130+ across the workspace)
cargo test --workspace

# Run the chess example (Scholar's Mate with embedded validator)
cargo run --bin chess

# Run the contract negotiation example
cargo run --bin contract
```

## Architecture

Three-layer separation:

| Layer | What | Where |
|-------|------|-------|
| **Model + Controller** | Schema, state, logic, chain | In the document |
| **Engine** | Crypto validation, schema enforcement, runtime | Tessera library |
| **Presentation** | UI, display, user interaction | Your application |

### Crate Structure

```
crates/
├── tessera-core/       # Types, traits, errors, crypto primitives
├── tessera-format/     # JSON + CBOR serialization
├── tessera-chain/      # Hash chain: build, validate, replay
├── tessera-engine/     # Structural validation + scripting runtime + API
├── tessera-wasm/       # WASM bindings (planned)
└── tessera/            # CLI binary
examples/
├── chess/              # Full chess game with embedded Rhai validator
└── contract/           # Contract negotiation between two parties
```

### Dependency Flow

```
tessera-core (types only)
  ├── tessera-format (serialization)
  ├── tessera-chain (hash chain)
  │     └── tessera-engine (validation + runtime)
  │           ├── tessera-wasm (WASM bindings)
  │           └── tessera (CLI)
```

## Examples

### Chess

A complete chess game with all rules enforced by an embedded Rhai validator (~650 lines of chess logic running inside the document's sandbox). Demonstrates:

- Full move validation (legal moves, check, checkmate, stalemate, castling, en passant, promotion)
- Multi-actor turns (white and black sign their own moves)
- Post-game guards (no moves after checkmate)
- Tamper detection
- JSON/CBOR round-trip serialization

```bash
cargo run --bin chess
```

### Contract Negotiation

Two-party contract negotiation where every edit, proposal, counter-offer, and acceptance is cryptographically recorded. Demonstrates:

- Turn-based workflow (propose/counter/accept/withdraw)
- Business rules enforced by embedded validator (can't accept own proposal, can't edit after acceptance)
- Multi-party signatures (vendor and client sign independently)
- Complete audit trail in the chain
- Tamper-evident final agreement

```bash
cargo run --bin contract
```

## Document Format

A Tessera document is a JSON or CBOR envelope:

```json
{
  "tessera": "0.1",
  "schema": { "fields": {}, "mutations": {}, "code": "..." },
  "api": { "read": [], "write": [] },
  "state": {},
  "chain": [],
  "chain_mode": "embedded",
  "pubkey": "<Ed25519 public key>",
  "signature": "<Ed25519 signature>"
}
```

Each mutation in the chain:

```json
{
  "prev_hash": "<SHA-256 of previous state>",
  "op": { "type": "move", "args": {"from": "e2", "to": "e4"} },
  "next_hash": "<SHA-256 of resulting state>",
  "actor": "<actor's Ed25519 public key>",
  "sig": "<actor's signature>",
  "timestamp": 1703880000
}
```

The version of a document is the SHA-256 hash of its current state. Content-addressable by definition.

See [SPEC.md](SPEC.md) for the full format specification.

## Embedded Validators

Tessera supports embedding domain logic as [Rhai](https://rhai.rs/) scripts inside the document schema. The validator receives the current state and mutation arguments, and returns the new state. The engine:

1. Checks execution authorization (policy + code signature)
2. Compiles the embedded code in a sandboxed Rhai runtime
3. Calls the validator function declared for this mutation type
4. Validates the returned state against the schema
5. Extends the hash chain and signs

Resource limits (max operations, call stack depth, expression complexity) are enforced to prevent abuse.

## Crypto Stack

| Library | Purpose |
|---------|---------|
| `ed25519-dalek` 2.x | Ed25519 signing and verification |
| `sha2` 0.10 | SHA-256 hashing |
| `rhai` 1.x | Sandboxed scripting runtime |
| `serde` + `serde_json` | JSON serialization |
| `ciborium` | CBOR serialization |

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
