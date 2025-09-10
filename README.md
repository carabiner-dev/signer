# Carabiner Signer Library

Easy digital signing library with support for [sigstore](https://www.sigstore.dev/)
bundles, [DSSE](https://github.com/secure-systems-lab/dsse) envelopes and (upcoming)
support for simpler signing with key pairs.

## Signing Sigstore Bundles

Signing data with sigstore and bundling it is super easy. The library takes
care of producing the signing key pair and fulcio certificate for you. Once
the signing operation is done, the Carabiner signer registers it in the
Rekor transparency log.

### Example

```golang
package main

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/signer"
)

func main() {
    // Create a signer:
    s := signer.NewSigner()

	// Sign a string as a sigstore bundle.
    //
    // This call triggers the sigstore flow if ambient
    // credentials are not available.
	bundle, err := s.SignMessage([]byte("My signed data"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Output the bundle to STDOUT
	if err := s.WriteBundle(bundle, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
```

## Dead Simple Signing Envelope (DSSE)

Initial support for DSSE has been implemented since v0.2.0. The library can verify
envelopes signed with arbitrary keys.

### Example

```golang
package main

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/signer"
)

func main() {
	v := signer.NewVerifier()
	res, err := v.VerifyDSSE("attestation.dsse.json", []key.PublicKeyProvider{
		// Add your keys here
	})
	if err != nil {
		fmt.Printf("Error verifying: %v\n", err)
	}

	if res.Verified {
		fmt.Println("DSSE envelope verified!")
	} else {
		fmt.Println("DSSE envelope failed verification.")
	}
}
```

## Key Pair Handling

The `key` package will handle all aspects with keys. For now only public key
parsing is implemented.

Most verifying operations take a `key.PublicKeyProvider`. This interface is
masks any object that can provide a public key object for use in cryptographic
operations. The `key.Public` obkect is the most basic `PublicKeyProvider` but
we may implement more complex providers such as cache interfaces and key
maagement systems clients.

## Status

The library has simple signing function to sign and verify attestations and
arbitrary data into sigstore bundles. The current functionality is considered
stable but the library is still under active feature development.

Full [DSSE](https://github.com/secure-systems-lab/dsse) signature verification
is now implemented in the signer module. The main verifier exposes functions to
verify the signatures of DSSE envelopes and their payloads.

The library also includes a `key` package that handles public key parsing and
signature verification.

### Upcoming Features

Some of the features we are working on that will soon show up in this module
include:

- Support for signing with supplied plain key pairs.
- DSSE (non bundle) output
- Keypair providers
- Certificate/identity cache ([gitsign](https://github.com/sigstore/gitsign)
credential cache style).

## Code Examples

We have two simple examples that demonstrate
[how to sign and verify an in-toto attestation](_examples/attestation) and
[how to sign and verify a random data message](_examples/message).

## Copyright

This library is made with <3 and Copyright by Carabiner Systems, Inc and released
under the Apache-2.0 license. Feel free to send patches and open issues or just
tell us if you are using it. We love feedback on all our projects.
