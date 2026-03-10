// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		funcs        []FnGenOpt
		mustErr      bool
		expectedType Type
	}{
		{"default", []FnGenOpt{}, false, ECDSA},
		{"rsa", []FnGenOpt{WithKeyType(RSA)}, false, RSA},
		{"rsa-small-key", []FnGenOpt{WithKeyType(RSA), WithKeyLength(5)}, true, RSA},
		{"ecdsa", []FnGenOpt{WithKeyType(ECDSA)}, false, ECDSA},
		{"ed25519", []FnGenOpt{WithKeyType(ED25519)}, false, ED25519},
		{"gpg-via-generate", []FnGenOpt{WithKeyType(GPG)}, true, GPG},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gen := Generator{}
			res, err := gen.GenerateKeyPair(tt.funcs...)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, tt.expectedType, res.Type)
			require.NotEmpty(t, res.Data)
			require.True(t, strings.HasPrefix(res.Data, "-----BEGIN "))
			require.True(t, strings.HasSuffix(res.Data, "PRIVATE KEY-----\n"))
			t.Log("\n" + res.Data)
			public, err := res.PublicKey()
			require.NoError(t, err)
			require.NotNil(t, public)
		})
	}
}

func TestGenerateGPGKeyPair(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		funcs   []FnGPGGenOpt
		mustErr bool
	}{
		{"default-ed25519", []FnGPGGenOpt{
			WithGPGName("Test User"), WithGPGEmail("test@example.com"),
		}, false},
		{"rsa", []FnGPGGenOpt{
			WithGPGName("RSA User"), WithGPGEmail("rsa@example.com"),
			WithGPGAlgorithm(packet.PubKeyAlgoRSA), WithGPGRSABits(2048),
		}, false},
		{"ecdsa-p256", []FnGPGGenOpt{
			WithGPGName("ECDSA User"), WithGPGEmail("ecdsa@example.com"),
			WithGPGAlgorithm(packet.PubKeyAlgoECDSA), WithGPGCurve(packet.CurveNistP256),
		}, false},
		{"with-comment", []FnGPGGenOpt{
			WithGPGName("Comment User"), WithGPGEmail("comment@example.com"),
			WithGPGComment("test comment"),
		}, false},
		{"with-expiration", []FnGPGGenOpt{
			WithGPGName("Expire User"), WithGPGEmail("expire@example.com"),
			WithGPGKeyLifetime(3600),
		}, false},
		{"rsa-too-small", []FnGPGGenOpt{
			WithGPGAlgorithm(packet.PubKeyAlgoRSA), WithGPGRSABits(512),
		}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gen := NewGenerator()
			gpgPriv, err := gen.GenerateGPGKeyPair(tt.funcs...)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, gpgPriv)
			require.Equal(t, GPG, gpgPriv.GetType())
			require.NotEmpty(t, gpgPriv.Fingerprint())
			require.NotNil(t, gpgPriv.Entity())

			// Should be able to extract a standard private key
			priv, err := gpgPriv.PrivateKey()
			require.NoError(t, err)
			require.NotNil(t, priv.Key)

			// Should be able to extract a standard public key
			pub, err := gpgPriv.PublicKey()
			require.NoError(t, err)
			require.NotNil(t, pub.Key)

			// Sign and verify round-trip
			msg := []byte("test message for " + tt.name)
			signer := NewSigner()
			sig, err := signer.SignMessage(gpgPriv, msg)
			require.NoError(t, err)

			verifier := NewVerifier()
			ok, err := verifier.VerifyMessage(gpgPriv.GPGPublicKey(), msg, sig)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}
