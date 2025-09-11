// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"encoding/base64"
	"testing"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/key"
)

func TestSign(t *testing.T) {
	t.Parallel()
	signer := DefaultSigner{}
	verifier := DefaultVerifier{}
	kv := key.NewVerifier()
	gen := key.NewGenerator()

	dsig, err := base64.StdEncoding.DecodeString("MEQCIEeMmq2z7+0yMyt8tL85S9pydxFCaxsGEArbPXXsgYFrAiBob+778d4PwHXQJ/WOVaCp4e/1i/P2i66hSxqPXT0Ykw==")
	require.NoError(t, err)

	for _, tt := range []struct {
		name    string
		numKeys int
		sut     *sdsse.Envelope
	}{
		{"normal", 1, &sdsse.Envelope{
			Payload:     []byte("string"),
			PayloadType: "testType",
			Signatures:  []*sdsse.Signature{},
		}},
		{"two-keys", 2, &sdsse.Envelope{
			Payload:     []byte("string"),
			PayloadType: "testType",
			Signatures:  []*sdsse.Signature{},
		}},
		{"two-keys-existing", 2, &sdsse.Envelope{
			Payload:     []byte("string"),
			PayloadType: "testType",
			Signatures: []*sdsse.Signature{
				{Sig: dsig},
			},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mustVerify := len(tt.sut.GetSignatures()) == 0
			keys := []key.PrivateKeyProvider{}
			for i := 0; i <= tt.numKeys; i++ {
				k, err := gen.GenerateKeyPair()
				require.NoError(t, err)
				keys = append(keys, k)
			}

			expectedNumKeys := len(tt.sut.GetSignatures()) + len(keys)

			err := signer.Sign(tt.sut, keys)
			require.NoError(t, err)

			// Ensure we have the right number of  signatures
			require.Len(t, tt.sut.GetSignatures(), expectedNumKeys)

			for _, sig := range tt.sut.GetSignatures() {
				require.NotEmpty(t, sig.GetSig())
			}

			if !mustVerify {
				return
			}

			// Verify with each key:
			for _, k := range keys {
				//nolint:errcheck,forcetypeassert
				res, err := verifier.RunVerification(nil, kv, tt.sut, []key.PublicKeyProvider{k.(*key.Private)})
				require.NoError(t, err)
				require.NotNil(t, res)
				require.True(t, res.Verified)
			}
		})
	}
}
