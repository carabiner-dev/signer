# Keyless DSSE fixtures

`generator.intoto.jsonl` and `no-cert.intoto.jsonl` are real provenance
envelopes from the original slsa-verifier's test data (Apache-2.0,
https://github.com/slsa-framework/slsa-verifier): DSSE envelopes signed
keyless by the slsa-github-generator, the first carrying its Fulcio
certificate in the non-standard `cert` signature field, the second
without one. `rekor-response.json` is the Rekor SearchLogQuery response
for the first, frozen from rekor.sigstore.dev so the tests verify the
real log entry offline.
