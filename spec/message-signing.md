# TIP-191 Message Signing (TRON)

Version 1 — Draft

Specifies how `tron-tool` produces and verifies TIP-191 signed messages.
Used by merchants to publish a self-authenticating receive-address
statement ("this is my official address").

## 1. Signing

```
digest = keccak256( "\x19TRON Signed Message:\n" ‖ decimal(len_bytes(msg)) ‖ msg )
sig    = secp256k1_sign(digest, privkey)   // 65 bytes: r ‖ s ‖ v
```

`len_bytes(msg)` is the **UTF-8 byte length** of the message, NOT the
character count — a Chinese statement has byte length ≈ 3× its character
count; using character count produces a different digest and breaks
cross-tool verification.

`v` is the ECDSA recovery id. TronWeb convention emits `27/28`;
implementations SHOULD accept `0/1` and normalize by adding 27.

Output: `0x`-prefixed hex, 132 characters.

The `\x19` prefix prevents a signed message from ever being reinterpreted
as a valid transaction (replay protection).

## 2. Verification

```
addr' = TRON_addr( ecrecover(digest, sig) )
return addr' == claimed_address
```

`tron-tool verify` prints the recovered address so the caller can compare
visually as well as programmatically.

## 3. Recommended statement contents

A merchant statement SHOULD include: the full address, merchant name,
and an issue/expiry date — bounding the signature's useful lifetime.

```
"Official receive address: TWsbXR...55555555 — Merchant: X — Issued: 2026-09-18"
```

## 4. Scope and limitations

- Proves: "the statement was signed by whoever holds this address's key."
- Does NOT prove: the merchant is honest. It binds a statement to an
  address, not to a reputation.
- A lookalike attacker can sign statements for THEIR OWN address — the
  check remains valid only if the verifier also confirms the address
  itself (e.g. the vanity pattern). Signature + eyeball, never signature
  alone.
- Off-chain only: no fee, no broadcast, works on any secp256k1 library.

## 5. Cross-check

Compatible with `tronWeb.trx.signMessageV2` / `verifyMessageV2` and
TronScan's "Sign & Verify" tool. An independent verification path SHOULD
always be available to end users.
