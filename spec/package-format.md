# Split-Key Delivery Package Format (`TRONSPK1`)

Version 1 — Draft

The seller returns the offset `d` inside a **signed package**. The package
proves origin and integrity; it is NOT encrypted because `d` is worthless
without the buyer's secret `b` (see `split-key.md`).

## 1. Binary layout

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 8 | magic | `"TRONSPK1"` |
| 8 | 2 | version | `0x0001` little-endian |
| 10 | 4 | signer_key_id | little-endian; identifies the Ed25519 public key embedded in the verifier |
| 14 | 2 | pattern_len | little-endian, bytes |
| 16 | N | pattern | UTF-8 pattern string; grammar per `split-key.md` §3.1 |
| 16+N | 33 | B | buyer's compressed secp256k1 public key |
| 49+N | 32 | d | offset scalar, big-endian |
| 81+N | 8 | timestamp | Unix seconds, little-endian — see §1.1 |
| 89+N | 64 | signature | Ed25519 over bytes `[0 .. 89+N)` |

Total size: `153 + pattern_len` bytes.

### 1.1 Field semantics

- `pattern`: the order-agreed match pattern. v1 supports `repeat:<n>`
  only (see `split-key.md` §3.1); unknown types MUST be rejected.
- `timestamp`: **informational issue time only**. It is NOT used in
  signature semantics, replay protection, or buyer-side verification;
  it exists for order correlation and dispute evidence.
- `B`, `d`: semantics per `split-key.md` §3–§5.

### 1.2 Parser rules (normative)

- `pattern_len` bound: parsers MUST NOT allocate before validating that
  `16 + pattern_len + 137` equals the total input length (i.e. the
  signature lands exactly at EOF). A sane upper bound for v1 is
  `pattern_len ≤ 64`; larger values MUST be rejected.
- **Exact length**: any bytes after the signature field → MUST reject.
  A package is accepted only at exactly `153 + pattern_len` bytes.
- `version` values other than `0x0001` → MUST reject.

## 2. Signature

- Algorithm: **Ed25519** (ed25519-dalek or equivalent)
- Signed message: all bytes before the signature field
- Verification key: the seller's Ed25519 public key, embedded in `tron-tool`
  and indexed by `signer_key_id` (supports key rotation)
- Any modification of any byte → signature verification fails → the tool
  MUST reject the package before any further processing
- **Semantics**: the signature proves *origin and integrity only* — "this
  package was issued by key_id N and is unmodified." It is NOT the
  acceptance gate: the package's `pattern` field is seller-signed data,
  and final acceptance is the buyer-side check chain in `split-key.md`
  §4 (binding → order → pattern). This containment is deliberate: a
  forged package is useless to a forger who does not know `b`, because
  acceptance still requires the delivered `d` to satisfy the order.

## 3. Verification procedure

```
parse → check magic + version → lookup pubkey by signer_key_id
      → Ed25519 verify(signature, bytes[0..sig_offset])
      → on success: return (pattern, B, d, timestamp)
      → on failure: abort, report "invalid or tampered package"
```

## 4. Rationale

- **No encryption**: confidentiality would be security theater — `d` alone
  reveals nothing. Integrity + origin is what matters.
- **Signature binds** `(pattern, B, d)` together: a swapped-in package, a
  modified `d`, or a mismatched `B` all fail verification.
- **key_id** allows rotating signing keys without breaking old packages;
  the tool ships a map `key_id → pubkey` and rejects unknown ids.

## 5. Seller key management (normative for issuer)

- The Ed25519 signing private key is kept OFFLINE and never committed to
  any repository.
- **Issuer self-check**: before signing, the issuer MUST verify that
  `1 ≤ d < n` and that `addr(B + d·G)` satisfies the order's `pattern`
  — a signed package MUST be valid on its own terms.
- Compromise procedure: issue new key_id, publish new public key via a new
  `tron-tool` release, and announce revocation of the old key_id.
  Revocation is advisory: already-distributed binaries keep accepting the
  old key_id, but per §2 the signature is only an origin proof — a forged
  package still cannot pass the buyer-side acceptance chain without
  actually satisfying the buyer's order.
