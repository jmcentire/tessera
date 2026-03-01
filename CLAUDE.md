# Tessera

Self-Validating Executable Document Format. The document proves itself. The engine validates the chain. Nothing outside the artifact is consulted.

The tessera hospitalis was a Roman token of mutual recognition — a clay tablet broken between host and guest. The fit proved the relationship without any third party. Tessera the format carries the same property: the document proves itself.

## Core Principle

**Cheaters can cheat but they can't hide it.** The engine doesn't prevent invalid mutations — it makes them detectable. Any party who receives a Tessera document can replay the chain and verify every step.

## What Tessera Is

A data/integrity layer. An API gateway, not an application server.

1. **Serialize/deserialize** — JSON + CBOR, dual-format
2. **Cryptographic integrity** — Ed25519 signatures, SHA-256 hash chain, content-addressable versioning
3. **Structural validation** — schema-declared field types and rules enforced
4. **Thin logic layer** — transition guards, field access, comparisons. Enough to validate a chess move, not enough to build a servlet
5. **Transport-friendly** — easy to move, easy to verify, no external authority

## What Tessera Is NOT

- An application runtime (that's the application's job)
- A cheating prevention system (it makes cheating detectable)
- A blockchain (no consensus, no mining, no tokens)
- A general-purpose programming language
- DRM

## Architecture

Three-layer separation (MVC pattern):

- **Model + Controller** = the struct (schema + state + logic + chain). Lives in the document.
- **Engine** = the runtime/validator. Validates crypto, enforces schema rules, exposes API. Our code.
- **Presentation** = untrusted, arbitrary UI. Not our code.

## Crate Structure

```
crates/
├── tessera-core/       # Types, traits, errors, crypto primitives
├── tessera-format/     # JSON + CBOR serialization
├── tessera-chain/      # Hash chain: build, validate, replay
├── tessera-engine/     # Structural validation + thin logic + API
├── tessera-wasm/       # WASM bindings (Phase 2)
└── tessera/            # CLI binary
```

### Dependency Flow

```
tessera-core (types only, no logic)
  ├── tessera-format (serialization)
  ├── tessera-chain (hash chain ops)
  │     └── tessera-engine (validation + logic + API)
  │           ├── tessera-wasm (WASM bindings)
  │           └── tessera (CLI)
```

## Quick Reference

```bash
cargo build --workspace          # build all
cargo test --workspace           # test all
make check                       # fmt + clippy + test

# CLI (once built)
tessera create <schema.json>     # new document from schema
tessera validate <doc.tsr>       # verify chain integrity
tessera inspect <doc.tsr>        # show metadata + state
tessera apply <doc.tsr> <mut>    # apply mutation
tessera sign <doc.tsr> --key k   # sign document
```

## Crypto Stack

| Library | Purpose |
|---------|---------|
| ed25519-dalek 2.x | Ed25519 signing/verification |
| sha2 0.10 | SHA-256 hashing |
| zeroize | Secure memory clearing |
| rand | CSPRNG |

## Key Invariants

1. **Chain integrity** — every mutation's prev_hash matches the hash of the prior state
2. **Signature validity** — every mutation is signed by the declared actor
3. **Document signature** — the envelope signature covers the complete chain
4. **Determinism** — same document, same validation result, every platform
5. **No floating point** — integer and rational arithmetic only in the logic layer
6. **Schema enforcement** — mutations must conform to declared types and rules

## Privacy Stack Integration

| Component | Role |
|-----------|------|
| Signet | Identity + authorization. Documents can require Signet-issued capability tokens. |
| Agent-Safe (SPL) | Policy-in-token. SPL tokens evaluated by the engine before state transitions. |
| HermesP2P | Transport. Tessera payloads are messages on the mesh. |
| BlindDB | Storage. Document state persisted in blind database. |
| Delegator | Multi-party. Tessera documents as cryptogram payloads. |

## Format Spec

See [SPEC.md](./SPEC.md) for the complete format specification.

## Kindex

Tessera captures discoveries, decisions, and architectural rationale in [Kindex](~/Code/kindex). Search before adding. Link related concepts.
