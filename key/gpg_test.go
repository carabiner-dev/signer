// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
)

// generateTestEntity creates a test GPG entity with the given config.
func generateTestEntity(t *testing.T, name, email string, config *packet.Config) *openpgp.Entity {
	t.Helper()
	entity, err := openpgp.NewEntity(name, "", email, config)
	require.NoError(t, err)
	return entity
}

// serializeArmored serializes an entity to ASCII-armored public key bytes.
func serializeArmoredPublic(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()
	pub := &GPGPublic{entity: entity}
	var buf bytes.Buffer
	require.NoError(t, pub.Serialize(&buf))
	return buf.Bytes()
}

// serializeArmoredPrivate serializes an entity to ASCII-armored private key bytes.
func serializeArmoredPrivate(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()
	priv := &GPGPrivate{entity: entity}
	var buf bytes.Buffer
	require.NoError(t, priv.Serialize(&buf))
	return buf.Bytes()
}

// serializeBinaryPublic serializes an entity to binary public key bytes.
func serializeBinaryPublic(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()
	pub := &GPGPublic{entity: entity}
	var buf bytes.Buffer
	require.NoError(t, pub.SerializeBinary(&buf))
	return buf.Bytes()
}

func TestParseGPGPublicKey_RSA_Armored(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Test User", "test@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	data := serializeArmoredPublic(t, entity)
	keys, err := ParseGPGPublicKey(data)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	gpgKey := keys[0]
	require.Equal(t, GPG, gpgKey.GetType())
	require.NotEmpty(t, gpgKey.Fingerprint())
	require.NotEmpty(t, gpgKey.KeyID())
	require.Contains(t, gpgKey.UserIDs(), "Test User <test@example.com>")
	require.NotNil(t, gpgKey.GetKey())
	require.NotNil(t, gpgKey.GetNotBefore())
}

func TestParseGPGPublicKey_ECDSA_Armored(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "ECDSA User", "ecdsa@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve:     packet.CurveNistP256,
	})

	data := serializeArmoredPublic(t, entity)
	keys, err := ParseGPGPublicKey(data)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	gpgKey := keys[0]
	require.Equal(t, GPG, gpgKey.GetType())
	require.Contains(t, gpgKey.UserIDs(), "ECDSA User <ecdsa@example.com>")
}

func TestParseGPGPublicKey_Ed25519_Armored(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Ed25519 User", "ed25519@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	})

	data := serializeArmoredPublic(t, entity)
	keys, err := ParseGPGPublicKey(data)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	gpgKey := keys[0]
	require.Equal(t, GPG, gpgKey.GetType())
	require.Contains(t, gpgKey.UserIDs(), "Ed25519 User <ed25519@example.com>")
}

func TestParseGPGPublicKey_Binary(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Binary User", "binary@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	data := serializeBinaryPublic(t, entity)
	keys, err := ParseGPGPublicKey(data)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	gpgKey := keys[0]
	require.Equal(t, GPG, gpgKey.GetType())
	require.Contains(t, gpgKey.UserIDs(), "Binary User <binary@example.com>")
}

func TestParseGPGPrivateKey_RSA(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Private RSA", "rsa-priv@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	data := serializeArmoredPrivate(t, entity)
	keys, err := ParseGPGPrivateKey(data, nil)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	privKey, err := keys[0].PrivateKey()
	require.NoError(t, err)
	require.Equal(t, RSA, privKey.Type)
	require.IsType(t, &rsa.PrivateKey{}, privKey.Key)
}

func TestParseGPGPrivateKey_ECDSA(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Private ECDSA", "ecdsa-priv@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve:     packet.CurveNistP256,
	})

	data := serializeArmoredPrivate(t, entity)
	keys, err := ParseGPGPrivateKey(data, nil)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	privKey, err := keys[0].PrivateKey()
	require.NoError(t, err)
	require.Equal(t, ECDSA, privKey.Type)
	require.IsType(t, &ecdsa.PrivateKey{}, privKey.Key)
}

func TestParseGPGPrivateKey_Ed25519(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Private Ed25519", "ed-priv@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	})

	data := serializeArmoredPrivate(t, entity)
	keys, err := ParseGPGPrivateKey(data, nil)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	privKey, err := keys[0].PrivateKey()
	require.NoError(t, err)
	require.Equal(t, ED25519, privKey.Type)
	require.IsType(t, ed25519.PrivateKey{}, privKey.Key)
}

func TestParseGPGPrivateKey_Passphrase(t *testing.T) {
	t.Parallel()
	passphrase := []byte("test-passphrase-123")

	entity := generateTestEntity(t, "Encrypted User", "enc@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	// Encrypt the private key with passphrase
	require.NoError(t, entity.PrivateKey.Encrypt(passphrase))
	for _, sk := range entity.Subkeys {
		if sk.PrivateKey != nil {
			require.NoError(t, sk.PrivateKey.Encrypt(passphrase))
		}
	}

	// Use SerializePrivateWithoutSigning since the key is encrypted
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, entity.SerializePrivateWithoutSigning(aw, nil))
	require.NoError(t, aw.Close())
	data := buf.Bytes()

	// Parsing without passphrase should fail
	_, err = ParseGPGPrivateKey(data, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "encrypted")

	// Parsing with wrong passphrase should fail
	_, err = ParseGPGPrivateKey(data, []byte("wrong-passphrase"))
	require.Error(t, err)

	// Parsing with correct passphrase should succeed
	keys, err := ParseGPGPrivateKey(data, passphrase)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	privKey, err := keys[0].PrivateKey()
	require.NoError(t, err)
	require.NotNil(t, privKey.Key)
}

func TestGPGPublicKey_RoundTrip_Armored(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Roundtrip User", "roundtrip@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	// Serialize → parse → serialize → parse
	data1 := serializeArmoredPublic(t, entity)
	keys1, err := ParseGPGPublicKey(data1)
	require.NoError(t, err)
	require.Len(t, keys1, 1)

	var buf2 bytes.Buffer
	require.NoError(t, keys1[0].Serialize(&buf2))
	data2 := buf2.Bytes()

	keys2, err := ParseGPGPublicKey(data2)
	require.NoError(t, err)
	require.Len(t, keys2, 1)

	// Fingerprints should match
	require.Equal(t, keys1[0].Fingerprint(), keys2[0].Fingerprint())
	require.Equal(t, keys1[0].KeyID(), keys2[0].KeyID())
	require.Equal(t, keys1[0].UserIDs(), keys2[0].UserIDs())
}

func TestGPGPublicKey_RoundTrip_Binary(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Binary RT", "binary-rt@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve:     packet.CurveNistP256,
	})

	// Serialize binary → parse → serialize binary → parse
	data1 := serializeBinaryPublic(t, entity)
	keys1, err := ParseGPGPublicKey(data1)
	require.NoError(t, err)
	require.Len(t, keys1, 1)

	var buf2 bytes.Buffer
	require.NoError(t, keys1[0].SerializeBinary(&buf2))
	data2 := buf2.Bytes()

	keys2, err := ParseGPGPublicKey(data2)
	require.NoError(t, err)
	require.Len(t, keys2, 1)

	require.Equal(t, keys1[0].Fingerprint(), keys2[0].Fingerprint())
}

func TestGPGPublic_InterfaceCompliance(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Interface User", "iface@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPub := newGPGPublic(entity)

	// Key interface
	var _ Key = gpgPub
	require.Equal(t, GPG, gpgPub.GetType())
	require.NotEmpty(t, gpgPub.GetScheme())
	require.NotZero(t, gpgPub.GetHashType())
	require.NotEmpty(t, gpgPub.GetData())
	require.NotNil(t, gpgPub.GetKey())
	require.NotNil(t, gpgPub.GetNotBefore())

	// PublicKeyProvider interface
	var _ PublicKeyProvider = gpgPub
	pub, err := gpgPub.PublicKey()
	require.NoError(t, err)
	require.Equal(t, RSA, pub.Type)
	require.NotNil(t, pub.Key)
}

func TestGPGPrivate_InterfaceCompliance(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "PrivIface User", "priv-iface@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPriv, err := newGPGPrivate(entity)
	require.NoError(t, err)

	// Key interface
	var _ Key = gpgPriv
	require.Equal(t, GPG, gpgPriv.GetType())

	// PrivateKeyProvider interface
	var _ PrivateKeyProvider = gpgPriv
	priv, err := gpgPriv.PrivateKey()
	require.NoError(t, err)
	require.NotNil(t, priv.Key)

	// PublicKeyProvider interface
	var _ PublicKeyProvider = gpgPriv
	pub, err := gpgPriv.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, pub.Key)
}

func TestGPGPrivate_GPGPublicKey(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "PubFromPriv", "pub-from-priv@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPriv, err := newGPGPrivate(entity)
	require.NoError(t, err)

	gpgPub := gpgPriv.GPGPublicKey()
	require.Equal(t, gpgPriv.Fingerprint(), gpgPub.Fingerprint())
	require.Equal(t, gpgPriv.KeyID(), gpgPub.KeyID())
	require.Equal(t, gpgPriv.UserIDs(), gpgPub.UserIDs())
}

func TestGPGPublicKey_RSA_PublicKeyExtraction(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "RSA Extract", "rsa-extract@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPub := newGPGPublic(entity)
	pub, err := gpgPub.PublicKey()
	require.NoError(t, err)
	require.Equal(t, RSA, pub.Type)
	require.Equal(t, RsaSsaPssSha256, pub.Scheme)
	require.Equal(t, crypto.SHA256, pub.HashType)
	require.IsType(t, &rsa.PublicKey{}, pub.Key)
}

func TestGPGPublicKey_ECDSA_PublicKeyExtraction(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "ECDSA Extract", "ecdsa-extract@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve:     packet.CurveNistP256,
	})

	gpgPub := newGPGPublic(entity)
	pub, err := gpgPub.PublicKey()
	require.NoError(t, err)
	require.Equal(t, ECDSA, pub.Type)
	require.Equal(t, EcdsaSha2nistP256, pub.Scheme)
	require.Equal(t, crypto.SHA256, pub.HashType)
	require.IsType(t, &ecdsa.PublicKey{}, pub.Key)
}

func TestGPGPublicKey_Ed25519_PublicKeyExtraction(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Ed25519 Extract", "ed-extract@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	})

	gpgPub := newGPGPublic(entity)
	pub, err := gpgPub.PublicKey()
	require.NoError(t, err)
	require.Equal(t, ED25519, pub.Type)
	require.Equal(t, Ed25519, pub.Scheme)
}

func TestGPGPublicKey_WithExpiration(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Expiring User", "expire@example.com", &packet.Config{
		Algorithm:       packet.PubKeyAlgoRSA,
		RSABits:         2048,
		KeyLifetimeSecs: 3600, // 1 hour
	})

	gpgPub := newGPGPublic(entity)
	require.NotNil(t, gpgPub.GetNotBefore())
	require.NotNil(t, gpgPub.GetNotAfter())

	// NotAfter should be approximately 1 hour after creation
	expected := gpgPub.CreationTime().Add(time.Hour)
	require.WithinDuration(t, expected, *gpgPub.GetNotAfter(), time.Second)
}

func TestGPGPublicKey_NoExpiration(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "NoExpire User", "noexpire@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPub := newGPGPublic(entity)
	require.NotNil(t, gpgPub.GetNotBefore())
	require.Nil(t, gpgPub.GetNotAfter())
}

func TestGPG_SignVerify_RSA(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "SignVerify RSA", "signverify@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPriv, err := newGPGPrivate(entity)
	require.NoError(t, err)

	// Sign with the GPG private key
	message := []byte("hello world from GPG RSA key")
	signer := NewSigner()
	sig, err := signer.SignMessage(gpgPriv, message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Verify with the extracted public key
	gpgPub := gpgPriv.GPGPublicKey()
	verifier := NewVerifier()
	verified, err := verifier.VerifyMessage(gpgPub, message, sig)
	require.NoError(t, err)
	require.True(t, verified)

	// Verify with tampered message
	verified, err = verifier.VerifyMessage(gpgPub, []byte("tampered"), sig)
	require.NoError(t, err)
	require.False(t, verified)
}

func TestGPG_SignVerify_ECDSA(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "SignVerify ECDSA", "sv-ecdsa@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoECDSA,
		Curve:     packet.CurveNistP256,
	})

	gpgPriv, err := newGPGPrivate(entity)
	require.NoError(t, err)

	message := []byte("hello world from GPG ECDSA key")
	signer := NewSigner()
	sig, err := signer.SignMessage(gpgPriv, message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	gpgPub := gpgPriv.GPGPublicKey()
	verifier := NewVerifier()
	verified, err := verifier.VerifyMessage(gpgPub, message, sig)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestGPG_SignVerify_Ed25519(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "SignVerify Ed25519", "sv-ed@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	})

	gpgPriv, err := newGPGPrivate(entity)
	require.NoError(t, err)

	message := []byte("hello world from GPG Ed25519 key")
	signer := NewSigner()
	sig, err := signer.SignMessage(gpgPriv, message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	gpgPub := gpgPriv.GPGPublicKey()
	verifier := NewVerifier()
	verified, err := verifier.VerifyMessage(gpgPub, message, sig)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestGPG_KeySet_ActiveKeys(t *testing.T) {
	t.Parallel()

	// Key with no expiration (always active)
	activeEntity := generateTestEntity(t, "Active", "active@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})
	activeKey := newGPGPublic(activeEntity)

	// Key that expires in 1 hour (should be active)
	soonEntity := generateTestEntity(t, "Soon", "soon@example.com", &packet.Config{
		Algorithm:       packet.PubKeyAlgoRSA,
		RSABits:         2048,
		KeyLifetimeSecs: 3600,
	})
	soonKey := newGPGPublic(soonEntity)

	ks := KeySet{activeKey, soonKey}
	active := ks.ActiveKeys()
	require.Len(t, active, 2)
}

func TestIsOpenPGPArmored(t *testing.T) {
	t.Parallel()
	require.True(t, isOpenPGPArmored([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")))
	require.True(t, isOpenPGPArmored([]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\n")))
	require.True(t, isOpenPGPArmored([]byte("  \n-----BEGIN PGP PUBLIC KEY BLOCK-----\n")))
	require.False(t, isOpenPGPArmored([]byte("-----BEGIN RSA PRIVATE KEY-----\n")))
	require.False(t, isOpenPGPArmored([]byte{0x99, 0x01, 0x0d}))
}

func TestParseGPGPublicKey_InvalidData(t *testing.T) {
	t.Parallel()
	_, err := ParseGPGPublicKey([]byte("not a gpg key"))
	require.Error(t, err)
}

func TestParseGPGPrivateKey_PublicKeyOnly(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "PubOnly", "pubonly@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	// Serialize as public key only
	data := serializeArmoredPublic(t, entity)

	// Trying to parse as private should fail
	_, err := ParseGPGPrivateKey(data, nil)
	require.Error(t, err)
}

func TestNewGPGPrivate_NoPrivateKey(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "NoPriv", "nopriv@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	// Remove private key material
	entity.PrivateKey = nil
	_, err := newGPGPrivate(entity)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no private key material")
}

func TestGPGPublic_Entity(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Entity Test", "entity@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPub := newGPGPublic(entity)
	require.Equal(t, entity, gpgPub.Entity())
}

func TestGPGPrivate_Entity(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Entity Test", "entity@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPriv, err := newGPGPrivate(entity)
	require.NoError(t, err)
	require.Equal(t, entity, gpgPriv.Entity())
}

func TestGPGPrivate_CreationTime(t *testing.T) {
	t.Parallel()
	entity := generateTestEntity(t, "Time Test", "time@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   2048,
	})

	gpgPriv, err := newGPGPrivate(entity)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), gpgPriv.CreationTime(), 5*time.Second)
}

func TestCryptoKeyToTypeSchemeHash(t *testing.T) {
	t.Parallel()

	t.Run("unsupported type", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := cryptoKeyToTypeSchemeHash("not a key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key type")
	})
}
