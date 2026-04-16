# Identities and identity matching

This document describes how signer identities are represented and how a policy's expected identity is matched against the identities surfaced by verification.

All types live in the `api/v1` package (`proto/carabiner/signer/v1/identity.proto`).

## Overview

After a signature is verified, the result carries one or more *signer identities* — records describing who produced the signature. A policy declares one or more *expected identities*. Matching answers: did any verified signer satisfy the policy's expectation?

```go
sv.MatchesIdentity(expected *Identity) bool
```

An `Identity` is a oneof — exactly one of these variants is set:

| Variant    | Go type             | Used when                                     |
| ---------- | ------------------- | --------------------------------------------- |
| `Sigstore` | `*IdentitySigstore` | Signer is a Fulcio-issued cert (OIDC-backed). |
| `Key`      | `*IdentityKey`      | Signer is a raw public key (RSA/ECDSA/Ed25519/GPG). |
| `Ref`      | `*IdentityRef`      | A placeholder pointing to an identity defined elsewhere (e.g., at a policy-set level). |

`MatchesIdentity` dispatches on which variant is set:

- `Sigstore` → `MatchesSigstoreIdentity`
- `Key` → `MatchesKeyIdentity`
- `Ref` → not matched directly; refs must be resolved to a concrete identity before matching (see [References](#references)).

## Slug format

Identities can be parsed from a compact string via `NewIdentityFromSlug`:

| Slug                                                 | Parses to                                                  |
| ---------------------------------------------------- | ---------------------------------------------------------- |
| `sigstore::<issuer>::<identity>`                     | Sigstore, exact mode.                                      |
| `sigstore(regexp)::<issuer-regex>::<identity-regex>` | Sigstore, regexp mode.                                     |
| `key::<type>::<id>`                                  | Key identity with `Type` and `Id`.                         |
| `ref:<id>`                                           | Reference identity.                                        |

`Identity.Slug()` is the inverse.

## Sigstore identities

`IdentitySigstore` has three fields:

| Field      | Meaning                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `Issuer`   | OIDC issuer from the Fulcio cert (e.g., `https://accounts.google.com`). |
| `Identity` | Subject claim (email or workload identity).                             |
| `Mode`     | `exact` (default) or `regexp`.                                          |

### Matching rules

Both `Issuer` and `Identity` must be set in the policy, otherwise the match is rejected outright.

**Exact mode** (default, or when `Mode == "exact"`):

- `policy.Issuer == signer.Issuer` (byte-exact)
- `policy.Identity == signer.Identity` (byte-exact)

**Regexp mode** (`Mode == "regexp"`):

- `policy.Issuer` compiles as a Go regular expression that must match `signer.Issuer`.
- `policy.Identity` compiles as a regexp that must match `signer.Identity`.
- If either regexp fails to compile, the match is rejected.

A match requires *both* fields to match under the same mode — mixing exact-issuer + regexp-identity (or vice versa) is not supported at this layer; use regexp mode with a literal pattern if you need that.

### Example

```go
policy := &Identity{
    Sigstore: &IdentitySigstore{
        Issuer:   "https://accounts.google.com",
        Identity: "releases@example.com",
    },
}
sv.MatchesIdentity(policy)
```

With regexp:

```go
mode := SigstoreModeRegexp
policy := &Identity{
    Sigstore: &IdentitySigstore{
        Mode:     &mode,
        Issuer:   `^https://token\.actions\.githubusercontent\.com$`,
        Identity: `^https://github\.com/carabiner-dev/.+/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`,
    },
}
```

## Key identities

`IdentityKey` has four fields:

| Field                | Meaning                                                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `Id`                 | Key identifier. For non-GPG keys this is a hash-derived 8-byte hex id; for GPG it's the primary key's full fingerprint.                     |
| `Type`               | Scheme string (e.g., `rsa`, `ecdsa-sha2-nistp256`, `ed25519`). Optional; narrows matches when both sides set it.                            |
| `Data`               | PEM-encoded public key (or ASCII-armored OpenPGP block). Used for normalization, not matched directly.                                      |
| `SigningFingerprint` | For GPG, fingerprint of the specific subkey that produced the signature. Populated on signer identities after verification; optional on policy identities as a pin. |

### Normalization

If a policy identity has `Data` but no `Id`, `MatchesKeyIdentity` clones it and calls `Normalize()`, which parses the key material and fills in `Id` and `Type`. The original policy object is not mutated.

An identity with neither `Id` nor `Data` can't match anything.

### Matching rules

All string comparisons are **case-insensitive** (hex fingerprints appear in both cases in the wild) and surrounding whitespace is trimmed.

For each signer identity in the verification result:

1. **Id match** (required): `policy.Id` must equal *either* `signer.Id` **or** `signer.SigningFingerprint`. This lets a policy name a GPG identity by its primary fingerprint or directly by a signing subkey.
2. **Type match** (optional): when both `policy.Type` and `signer.Type` are non-empty, they must be equal. If either is empty, this step is skipped.
3. **Signing-fingerprint pin** (optional): when `policy.SigningFingerprint` is non-empty, it must equal `signer.SigningFingerprint` exactly. When empty, the pin is not enforced.

The first signer satisfying all three rules is a match.

### GPG: the three policy shapes

For GPG keys a verified signer has both a primary fingerprint (`Id`) and — when the signature was made by a subkey — a subkey fingerprint (`SigningFingerprint`). Three useful policy shapes:

| Intent                                             | `policy.Id`        | `policy.SigningFingerprint` | Matches                                                                    |
| -------------------------------------------------- | ------------------ | --------------------------- | -------------------------------------------------------------------------- |
| Trust this key, any subkey                         | primary FP         | *empty*                     | Any signature by this key (primary-direct or via any of its subkeys).      |
| Trust only this subkey                             | subkey FP          | *empty*                     | Only signatures made by that specific subkey.                              |
| Trust this key, but only when signed by a subkey  X | primary FP         | subkey FP                   | Signatures where the primary matches *and* the exact subkey was used. Primary-direct signatures and other subkeys are rejected. |

Notes:

- When the signature was made by the primary directly, the signer's `SigningFingerprint` is empty, so the "any subkey" shape (row 1) still matches and the "pin a subkey" shape (row 3) rejects it — as you'd expect.
- For non-GPG keys (`rsa`, `ecdsa`, `ed25519`), `SigningFingerprint` is unused on both sides and all three shapes collapse to "Id match + optional Type match".

### Building signer identities

After DSSE verification, `*key.VerificationResult.Keys[]` contains one `*key.Public` per verified signature. `SigningKeyFingerprint` on each entry holds the actual signing (sub)key. To bridge to proto:

```go
for _, pub := range res.Keys {
    sv.Identities = append(sv.Identities, &Identity{
        Key: IdentityKeyFromPublic(pub),
    })
}
```

`IdentityKeyFromPublic` populates `Id`, `Type`, and `SigningFingerprint` from the verified key.

### Example

Pin a GPG primary and allow any subkey:

```go
policy := &Identity{
    Key: &IdentityKey{
        Id: "5270DFC517AD50957EDA0CFDBE1B8E71C9A0F3B2",
    },
}
```

Pin a specific signing subkey:

```go
policy := &Identity{
    Key: &IdentityKey{
        Id: "04B44C056663906446B77A6D89F11DC191AA7042",
    },
}
```

Strict primary + subkey:

```go
policy := &Identity{
    Key: &IdentityKey{
        Id:                 "5270DFC517AD50957EDA0CFDBE1B8E71C9A0F3B2",
        SigningFingerprint: "04B44C056663906446B77A6D89F11DC191AA7042",
    },
}
```

## References

`IdentityRef` holds a single `Id` string pointing at an identity defined outside the policy (typically in a shared policy-set definition). It has no matching logic in this package — the calling layer must resolve the reference to a concrete `Sigstore` or `Key` identity before calling `MatchesIdentity`. An unresolved `Ref` passed to `MatchesIdentity` falls through to the default branch and returns `false`.

Slug form: `ref:<id>`.

## Quick reference

| You want to match…                          | Set on `*Identity`                                                    |
| ------------------------------------------- | --------------------------------------------------------------------- |
| Any signer from an OIDC issuer + subject    | `Sigstore{Issuer, Identity}` (exact)                                  |
| Sigstore with wildcard on the subject       | `Sigstore{Mode: regexp, Issuer, Identity: "<regex>"}`                 |
| A raw key by its id                         | `Key{Id}`                                                             |
| A key only if the scheme matches            | `Key{Id, Type}`                                                       |
| A GPG primary, any subkey                   | `Key{Id: <primary FP>}`                                               |
| A specific GPG subkey                       | `Key{Id: <subkey FP>}`                                                |
| A GPG primary *and* a specific subkey       | `Key{Id: <primary FP>, SigningFingerprint: <subkey FP>}`              |
| A reference defined elsewhere               | `Ref{Id}` (caller must resolve)                                       |
