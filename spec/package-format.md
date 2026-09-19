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
| 10 | 4 | signer_key_id | identifies the Ed25519 public key embedded in the verifier |
| 14 | 2 | pattern_len | little-endian, bytes |
| 16 | N | pattern | UTF-8 pattern string (order spec) |
| 16+N | 33 | B | buyer's compressed secp256k1 public key |
| 49+N | 32 | d | offset scalar, big-endian |
| 81+N | 8 | timestamp | Unix seconds, little-endian |
| 89+N | 64 | signature | Ed25519 over bytes `[0 .. 89+N)` |

Total size: `153 + pattern_len` bytes.

## 2. Signature

- Algorithm: **Ed25519** (ed25519-dalek or equivalent)
- Signed message: all bytes before the signature field
- Verification key: the seller's Ed25519 public key, embedded in `tron-tool`
  and indexed by `signer_key_id` (supports key rotation)
- Any modification of any byte → signature verification fails → the tool
  MUST reject the package before any further processing

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
- Compromise procedure: issue new key_id, publish new public key via a new
  `tron-tool` release, and announce revocation of the old key_id.
