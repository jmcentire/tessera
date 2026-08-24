# Review Standard — Tessera

Tailored pointer for automated/agent code review on this repo. Governing standards live at
`~/Code/tools/CODE-REVIEW-STANDARD.md` (evidence-producing review, seven adversarial lenses,
verdict ladder) and `~/Code/tools/DIFF-INTENT-GATE.md` (material-change escalation for declared
intent). Apply both; this file adds only what's specific to Tessera.

## What this project is

Self-validating executable document format: JSON/CBOR envelope + Ed25519 signatures + SHA-256
hash chain + a thin Rhai-scripted logic layer. The document proves itself — the engine validates,
nothing external is consulted. See `CLAUDE.md` for the full invariant list; the ones below are
what a reviewer must actively check, not just recall.

## Always check

- **Chain integrity is untouchable by convenience.** Any change to `tessera-chain` must preserve:
  every mutation's `prev_hash` matches the hash of the prior state, and validation replays the
  full chain — never trusts a cached/short-circuited result.
- **Determinism.** Same document, same platform-independent result, every time. No floating point
  in the logic/validation layer (`tessera-engine`) — integer/rational only. A PR introducing `f32`/
  `f64` into schema types, guards, or the eval layer is a defect, not a style nit.
- **Crypto stays in the audited libraries.** Signing/verification goes through `ed25519-dalek`,
  hashing through `sha2`. No hand-rolled crypto, no reimplemented constant-time comparison, no
  crypto primitive added without an explicit reason to leave the existing stack.
- **Signature/hash changes are HIGH risk by the review standard's own classification** (integrity
  claims here are the entire product). Never emit `CLEAN_QUALIFIED` for a change touching
  `tessera-core::crypto`, `tessera-chain`, or the envelope signature path — route to
  `HUMAN_REVIEW_REQUIRED` even with all tests green.
- **Schema/type changes are a compatibility surface.** `tessera-core::types` and the wire format
  (`tessera-format`) are consumed by every downstream document; a field-type or serialization
  change is a material change to declared intent per `DIFF-INTENT-GATE.md` — trace provenance,
  don't just diff clean.
- **`SPEC.md` is the source of truth for the format.** A behavior change without a matching
  `SPEC.md` update is incomplete, not just under-documented.
- **Execution policy defaults stay fail-closed.** `Disabled` / `TrustKeys` / `TrustAll` gating in
  `tessera-engine::runtime` must never silently widen (e.g. a refactor that makes `TrustAll`
  reachable from a `Disabled` default is a material change).
- **Test sensitivity (lens 6).** For chain/crypto/validation changes, confirm the test actually
  fails on the broken behavior (tamper-detection tests must tamper something the code path
  actually checks — see the "guard the action, not the artifact" rule in
  `CODE-REVIEW-STANDARD.md`).

## Style

- `cargo fmt --check` and `cargo clippy --workspace -- -D warnings` are both required gates
  (`make check` runs fmt + clippy + test) — treat any new clippy allow as something to justify,
  not silence.
- Crate boundaries are load-bearing: `tessera-core` has no logic, only types/traits/crypto
  primitives; don't let higher crates leak back down (check `Cargo.toml` dependency direction
  matches the documented flow in `CLAUDE.md`).
- Small, reviewable modules; docstrings state the *why* and the invariant being upheld, matching
  existing style in `crates/*/src`.

## Skip

- `Cargo.lock` — generated, don't review line-by-line; check only that it's present/updated
  alongside a `Cargo.toml` dependency change.
- `target/` — build output, never committed, never reviewed.
- `docs/*.html` (GitHub Pages demos) — cosmetic/presentation, not the integrity layer; standard
  web-review care applies but they carry none of the HIGH-risk classification above.
- `.kin/local/`, `.kin/cache/`, `.kin/tmp/`, `.kin/private/` — gitignored local Kindex state,
  never committed, never reviewed.
