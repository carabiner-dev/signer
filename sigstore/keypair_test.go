// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/require"
)

func TestNewSignerKeypairNilSigner(t *testing.T) {
	t.Parallel()
	kp, err := NewSignerKeypair(nil, nil)
	require.Error(t, err)
	require.Nil(t, kp)
}

func TestSignerKeypairDefaults(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kp, err := NewSignerKeypair(priv, nil)
	require.NoError(t, err)

	// The wrapped key must be the exact key the caller provided.
	pub, ok := kp.GetPublicKey().(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, pub.Equal(&priv.PublicKey))

	require.Equal(t, "ECDSA", kp.GetKeyAlgorithm())
	require.Equal(t, protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, kp.GetSigningAlgorithm())
	require.Equal(t, protocommon.HashAlgorithm_SHA2_256, kp.GetHashAlgorithm())
	require.NotEmpty(t, kp.GetHint())

	pem, err := kp.GetPublicKeyPem()
	require.NoError(t, err)
	parsed, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pem))
	require.NoError(t, err)
	parsedECDSA, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, parsedECDSA.Equal(&priv.PublicKey))
}

func TestSignerKeypairSignData(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kp, err := NewSignerKeypair(priv, nil)
	require.NoError(t, err)

	data := []byte("proof-of-possession subject")
	sig, digest, err := kp.SignData(t.Context(), data)
	require.NoError(t, err)

	// Digest is the SHA-256 of the data, and the signature verifies against the
	// caller-owned key over that digest.
	want := sha256.Sum256(data)
	require.Equal(t, want[:], digest)
	require.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest, sig))
}

func TestSignerKeypairCustomHint(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hint := []byte("my-hint")
	kp, err := NewSignerKeypair(priv, &SignerKeypairOptions{Hint: hint})
	require.NoError(t, err)
	require.Equal(t, hint, kp.GetHint())
}
