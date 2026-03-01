# Tessera Format Specification

Version: 0.1.0-draft

## Document Structure

A Tessera document is a JSON or CBOR envelope containing:

```json
{
  "tessera": "0.1",
  "schema": { ... },
  "api": { ... },
  "state": { ... },
  "chain": [ ... ],
  "chain_mode": "embedded",
  "pubkey": "<hex-encoded Ed25519 public key>",
  "signature": "<hex-encoded Ed25519 signature>"
}
```

### Fields

- `tessera` — format version string
- `schema` — declares document type, fields, valid transitions, guards
- `api` — interface the engine exposes to presentation layers
- `state` — current application state (typed per schema)
- `chain` — ordered array of mutations (if chain_mode is embedded)
- `chain_mode` — one of: `stateless`, `referenced`, `embedded`
- `pubkey` — Ed25519 public key of the document authority
- `signature` — Ed25519 signature over `SHA-256(canonical(schema + api + state + chain))`

### Chain Modes

- **stateless** — self-contained, no history, no predecessor reference
- **referenced** — contains `prev_hash` only; history lives elsewhere
- **embedded** — full history included in the document

## Mutation Structure

Each mutation in the chain:

```json
{
  "prev_hash": "<hex SHA-256 of previous state>",
  "op": { "type": "increment", "args": {} },
  "next_hash": "<hex SHA-256 of resulting state>",
  "actor": "<hex Ed25519 public key of actor>",
  "sig": "<hex Ed25519 signature over (prev_hash + op + next_hash + schema_hash)>",
  "timestamp": 1703880000
}
```

- `prev_hash` — SHA-256 of the state before this mutation
- `op` — the operation performed (declared in schema)
- `next_hash` — SHA-256 of the state after this mutation
- `actor` — public key of the party who performed the mutation
- `sig` — Ed25519 signature by actor over `SHA-256(prev_hash || canonical(op) || next_hash || schema_hash)` where `schema_hash = SHA-256(canonical(schema))`
- `timestamp` — Unix epoch seconds, must be non-decreasing within the chain

## Version

The version of a document IS the SHA-256 hash of its current state. Content-addressable by definition. No separate version field.

## Schema Structure

```json
{
  "fields": {
    "count": { "type": "u64", "default": 0 }
  },
  "mutations": {
    "increment": {
      "guards": ["count < 1000"],
      "effects": { "count": "count + 1" }
    },
    "decrement": {
      "guards": ["count > 0"],
      "effects": { "count": "count - 1" }
    }
  }
}
```

### Field Types

- `bool`, `u64`, `i64`, `string`, `bytes`
- `array<T>`, `map<K, V>`
- Nested objects via inline schema

### Guards

Simple expressions evaluated by the engine's thin logic layer:
- Field access: `field_name`
- Comparisons: `==`, `!=`, `<`, `>`, `<=`, `>=`
- Boolean: `&&`, `||`, `!`
- Arithmetic: `+`, `-`, `*`, `/`, `%`
- Literals: integers, strings, booleans

Guards must be deterministic. No I/O, no randomness, no floating point.

### Effects

Describe how state changes when a mutation is applied. Same expression language as guards.

## API Structure

```json
{
  "read": ["count"],
  "write": ["increment", "decrement"]
}
```

The API declares what operations the engine exposes to presentation layers. Read operations return field values. Write operations map to mutations declared in the schema.

## Validation Algorithm

On load, the engine:

1. Deserialize document (JSON or CBOR)
2. Verify document signature against embedded pubkey
3. Validate current state against schema field definitions
4. If chain_mode is `embedded`:
   a. Compute genesis state from schema defaults; verify `chain[0].prev_hash` matches its hash
   b. Compute `schema_hash = SHA-256(canonical(schema))`
   c. For each mutation:
      - Verify actor signature over `SHA-256(prev_hash || canonical(op) || next_hash || schema_hash)`
      - Verify `prev_hash` matches the previous mutation's `next_hash` (chain linkage)
      - Verify `timestamp` is non-decreasing (monotonicity)
   d. Verify current state hash matches the last mutation's `next_hash`
5. If chain_mode is `referenced`: verify the last mutation's `next_hash` matches the current state
6. If chain_mode is `stateless`: verify document signature only

If any step fails, the document is rejected. No partial trust state.

## Canonical Serialization

For hashing and signing, JSON is canonicalized:
- Keys sorted lexicographically
- No whitespace
- Numbers as integers (no floating point)
- UTF-8 encoding

CBOR uses deterministic encoding (RFC 8949 Section 4.2).

## Embedded Code Execution

Documents may embed validator code in `schema.code`. Mutations reference validator functions by name. The engine enforces an execution policy before running embedded code:

- **Disabled** — never execute embedded code; mutations with validators are rejected
- **TrustKeys(keys)** — execute code from documents signed by any listed public key
- **TrustAuthorizations(auths)** — execute code matching a signed consent receipt:
  - The receipt contains: `code_hash`, `authority_pubkey`, `authorizer_pubkey`, `authorizer_sig`
  - `authorizer_sig` covers `SHA-256(code_hash || authority_pubkey)`
  - The engine verifies the receipt signature before execution
- **TrustAll** — execute any embedded code (testing/development only)

The runtime sandbox enforces resource limits:
- Maximum operations per execution
- Maximum call stack depth
- Maximum expression nesting depth
- Maximum string, array, and map sizes

## Checksums

- Hash function: SHA-256 (FIPS 180-4)
- Signature algorithm: Ed25519 (RFC 8032)
- Key encoding: hex (lowercase)
