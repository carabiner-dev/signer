# SPIFFE timestamping

SPIFFE-signed bundles carry an X.509-SVID as the signer identity.
SPIRE issues SVIDs with short lifetimes by design — the test fixture
in `hack/spire/` uses 10 minutes; production deployments are typically
1 hour. Without further trust-root assistance, a bundle can only be
verified while its SVID is still valid: once the SVID expires, the
chain validation step fails with `x509: certificate has expired or
is not yet valid` and the bundle is effectively unverifiable.

This package solves that by attaching an RFC 3161 timestamp from a
trusted Timestamp Authority (TSA) to every SPIFFE-signed bundle, then
using the verified timestamp's time during SVID chain validation.

## Why RFC 3161

RFC 3161 timestamps are signer-agnostic: a TSA stamps the signature
bytes with a TimeStampToken anchored to its own cert chain. The TSA
does not care what kind of cert produced the signature. So sigstore's
public TSA (the same one used to timestamp Fulcio-signed bundles)
works equally well for SVID-signed bundles, and the TSA's trust root
sits beside the SPIRE upstream root in the verifier — neither stands
in for the other.

## What the bundle carries

For a SPIFFE-signed bundle with timestamping on, the bundle contains:

- The SVID leaf cert (and any intermediates from the SPIRE upstream
  authority) in `VerificationMaterial.x509_certificate_chain`.
- The DSSE envelope signed by the SVID's private key.
- An RFC 3161 `TimeStampToken` from sigstore's TSA in
  `VerificationMaterial.timestamp_verification_data.rfc3161_timestamps`.

Nothing else from sigstore configuration leaks into the bundle —
no Fulcio reference, no OIDC issuer, no Rekor entry. The TSA token
itself, naturally, references sigstore's TSA cert chain (that's how
RFC 3161 works), but that's the only sigstore-derived data in the
artifact.

## Configuration

Timestamping is on by default for SPIFFE. The flag plumbing:

| Flag | Where | Effect |
| --- | --- | --- |
| `--signing-timestamp` | bundled `SignerSet` (e.g. `bnd statement`) | shared toggle that applies to whichever backend was selected |
| `--spiffe-timestamp` | standalone `SpiffeSignSet` | per-backend toggle when the SPIFFE set is wired without `SignerSet` |

`SignerSet` suppresses `--spiffe-timestamp` (and `--sigstore-timestamp`)
when bundled — `--signing-timestamp` is the single user-facing knob.

Users opting *out*:

```sh
bnd statement file.json --signing-timestamp=false
```

The resulting bundle has no `timestamp_verification_data`. It will
verify only while the SVID is still valid.

## Sign-side flow

The sign-time path:

1. `SpiffeSignSet.BuildSigner` produces an `*options.Signer` with
   `Backend=BackendSpiffe` and `Timestamp` propagated from the flag.
   It does **not** populate `SigningConfig` — keeping the OptionsSet
   layer free of sigstore-derived state.
2. `bundle.DefaultSigner.BuildBundleOptions` (in `bundle/signer.go`)
   sees `opts.Timestamp=true` and `opts.SigningConfig==nil`, then
   synthesizes a TSA-only `SigningConfig` from the embedded
   sigstore-roots. Fulcio / OIDC / Rekor URL slices are explicitly
   left empty.
3. The synthesized config feeds `bundleOptions.TimestampAuthorities`
   via `sign.NewTimestampAuthority(tsaOpts)`.
4. `bundle.DefaultSigner.SignBundle` calls sigstore-go's `sign.Bundle`,
   which iterates the configured TSAs, POSTs each one the signature
   bytes, and embeds the returned RFC 3161 tokens in the bundle's
   `VerificationMaterial.timestamp_verification_data`.

Code references:

- `options/spiffe_set.go` — `SpiffeSign.Timestamp`, `BuildSigner`.
- `bundle/signer.go` — `BuildBundleOptions` (the `if opts.Timestamp`
  branch and the TSA-only fallback) plus `tsaOnlySigningConfig` helper.
- `backend.go` — `spiffeBackend.prepare` calls `BuildBundleOptions`,
  then `SignBundle`.

## Verify-side flow

`signer.NewVerifier` wires a lazy `TSAMaterialLoader` closure into the
SPIFFE verifier. The closure resolves the trusted root via TUF
(`tuf.GetRoot`, cached locally by sigstore-go after the first call)
and parses it through `root.NewTrustedRootFromJSON`. It runs at most
once per Verifier and only when a bundle that actually carries
timestamps is presented — verifiers that never see TSA-stamped
bundles never pay the TUF fetch cost. The same TUF + cache pattern
is what the sigstore verify path uses, so behavior is consistent.

At verify time, `spiffe/verifier.Verifier.Verify`:

1. Calls `chainValidationTime(bndl)` to compute what time to use
   for SVID chain validation:
   - Bundle has no timestamps → returns the zero time. `x509.Verify`
     falls back to `time.Now()` (legacy behavior). The loader is not
     invoked.
   - Bundle has timestamps but no loader is configured → returns
     the zero time (best-effort fallback). The verifier was
     constructed without a TSA trust source.
   - Bundle has timestamps and a loader is configured → resolves the
     `TrustedMaterial` (lazily, cached on the Verifier) and calls
     sigstore-go's `verify.VerifySignedTimestamp(bndl, tm)`. Each
     timestamp is validated against each TSA in the trust material.
     - **Loader fails** → error (e.g. TUF unreachable). Verification
       fails closed; we don't know if the bundle is genuine without
       validating its timestamp.
     - Validation succeeds → returns the **earliest** verified time
       (most conservative for chain validation) plus the list of
       verified timestamps.
     - **Validation fails for all timestamps** → returns an error.
       Same fail-closed reasoning.
2. Validates the SVID chain with `x509.VerifyOptions.CurrentTime`
   set to the resolved time (zero → `time.Now()`).
3. After signature/identity checks pass, surfaces the verified
   timestamps in `result.VerifiedTimestamps` with
   `Type="TimestampAuthority"` (matching sigstore-go's own conventions
   for Fulcio-signed bundles).

Code references:

- `spiffe/verifier/verifier.go` — `Verify`, `chainValidationTime`,
  `SetTSATrustedMaterial`.
- `verifier.go` (top-level signer package) — `NewVerifier` calls
  `tsaTrustedMaterial(rootsData)` to build the trust material and
  injects it into the SPIFFE verifier.

## Decision matrix

| Bundle has timestamps | TSA loader | Loader / validation result | Outcome |
| --- | --- | --- | --- |
| no  | n/a       | (loader not invoked)              | `time.Now()` chain validation (legacy behavior) |
| yes | nil       | (loader not invoked)              | `time.Now()` chain validation (verifier wasn't given a TSA source) |
| yes | set       | loader fails (e.g. TUF unreachable) | **error** — fails closed |
| yes | set       | all timestamps verify             | earliest verified time used for chain validation |
| yes | set       | some verify, others fail          | earliest of the verifying ones used; failures recorded |
| yes | set       | none verify                       | **error** — fails closed |

## Limitations / future work

- **Single TSA source.** Both the sign-time TSA URL and the verify-time
  TSA trust root come from the embedded sigstore-roots. There's
  currently no way to point either at a private TSA. Tracked as a
  follow-up in the SPIFFE deferred-work list.
- **No threshold / quorum.** Any single verifying timestamp is enough.
  sigstore-go has `VerifySignedTimestampWithThreshold` but we don't
  expose a knob for it; SPIFFE bundles typically carry one timestamp
  anyway.
- **No replay protection vs. clock skew.** The earliest verified time
  is taken at face value. If a TSA is later compromised, bundles it
  stamped become as untrustworthy as the TSA. Trust-pinning specific
  TSA cert chains (vs. the embedded sigstore roots wholesale) is a
  potential refinement.

## End-to-end test

`spiffe/e2e_test.go:TestE2ESPIFFESignAndVerifyWithTimestamp` exercises
the full sign → TSA round-trip → verify path against the local SPIRE
fixture. Run with:

```sh
make spire-up
export SPIFFE_ENDPOINT_SOCKET="unix://$(pwd)/hack/spire/socket/api.sock"
export SPIFFE_TRUST_BUNDLE="$(pwd)/hack/spire/bundle.pem"
go test -tags=e2e ./spiffe/... -run TestE2ESPIFFESignAndVerifyWithTimestamp -v
```

The test signs an in-toto statement with the issued SVID, asserts the
bundle carries an RFC 3161 token, then verifies and asserts
`result.VerifiedTimestamps` is non-empty. Network access to
`timestamp.sigstore.dev` is required at sign time; the test skips
(rather than failing) if the TSA isn't reachable.
