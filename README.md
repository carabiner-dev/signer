# Carabiner Signer Library

Easy digital signing library with support for [sigstore](https://www.sigstore.dev/)
and (upcoming) support for simpler signing with key pairs.

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

## Status

The library has simple signing function to sign and verify attestations and
arbitrary data into sigstore bundles. The current functionality is considered
stable but the library is still under active feature development.

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
