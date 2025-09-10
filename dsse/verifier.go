// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"time"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
)

type Verifier interface {
	RunVerification(*options.Verifier, *key.Verifier, *sdsse.Envelope, []key.PublicKeyProvider) (*key.VerificationResult, error)
	BuildKeyVerifier(*options.Verifier) (*key.Verifier, error)
	OpenEnvelope(string) (*sdsse.Envelope, error)
}

type DefaultVerifier struct{}

// RunVerification verifies the DSSE envelope
func (dv *DefaultVerifier) RunVerification(
	opts *options.Verifier, kv *key.Verifier, env *sdsse.Envelope, keys []key.PublicKeyProvider,
) (*key.VerificationResult, error) {
	if env == nil {
		return nil, fmt.Errorf("")
	}

	if kv == nil {
		return nil, errors.New("did not get a key verifier to check signatures")
	}

	digests := map[crypto.Hash][]byte{}
	digestStrs := map[string]string{}
	for _, kp := range keys {
		k := kp.PublicKey()
		if _, ok := digests[k.HashType]; ok {
			continue
		}
		// Hash in this hasher
		digest, err := hashPayload(env, k.HashType)
		if err != nil {
			return nil, fmt.Errorf("error hashing with %T: %w", k.HashType, err)
		}
		digests[k.HashType] = digest
		digestStrs[k.HashType.String()] = fmt.Sprintf("%x", digest)
	}

	// Got all required hashes, verify
	for _, sig := range env.GetSignatures() {
		for _, kp := range keys {
			k := kp.PublicKey()
			pass, err := kv.VerifyDigest(k, digests[k.HashType], sig.GetSig())
			if err == nil {
				if pass {
					return &key.VerificationResult{
						Key:      k,
						Time:     time.Now(),
						Digest:   digestStrs,
						Verified: true,
					}, nil
				}
			}
		}
	}
	return &key.VerificationResult{
		Key:      nil,
		Time:     time.Now(),
		Digest:   digestStrs,
		Verified: false,
	}, nil
}

// BuildKeyVerifier builds a key verifier used to check the DSSE signatures
func (dv *DefaultVerifier) BuildKeyVerifier(opts *options.Verifier) (*key.Verifier, error) {
	v := key.NewVerifier()
	return v, nil
}

// OpenEnvelope parses a DSSE envelope
func (dv *DefaultVerifier) OpenEnvelope(path string) (*sdsse.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening DSSE envelope file: %w", err)
	}

	env := &sdsse.Envelope{}
	if err := protojson.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("unmarshaling DSSE envelope: %w", err)
	}
	return env, nil
}

// hashPayload generates the payload hash using the supplied hasher. Note that
// this function is not a normal hasher, it implements the DSSE PAE encoding
// and the returned digest is from the PAE message constructed according to the
// DSSE specification.
func hashPayload(env *sdsse.Envelope, hasher crypto.Hash) ([]byte, error) {
	if env == nil {
		return nil, errors.New("no envelope supplied")
	}

	if env.Payload == nil {
		return nil, errors.New("DSEE envelope has no payload")
	}

	if env.GetPayloadType() == "" {
		return nil, errors.New("unset payload type in DSSE envelope")
	}

	paeEncoded := paeEncode(env)

	h := hasher.New()
	if _, err := h.Write(paeEncoded); err != nil {
		return nil, fmt.Errorf("writing to hasher: %w", err)
	}
	return h.Sum(nil), nil
}

// paeEncode implements the DSSE signing protocol:
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#signature-definition
// This function was stolen from the Secure System Labs dsse packager.
func paeEncode(env *sdsse.Envelope) []byte {
	// payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s",
		len(env.GetPayloadType()), env.GetPayloadType(),
		len(env.GetPayload()), env.GetPayload())
}
