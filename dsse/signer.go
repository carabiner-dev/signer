// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package dsse

import (
	"errors"
	"fmt"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"

	"github.com/carabiner-dev/signer/key"
)

func NewSigner() Signer {
	return &DefaultSigner{}
}

// SignerOptions captures the options to sign
type SignerOptions struct {
	Keys []key.PrivateKeyProvider
}

// Signer signs content and wrapps them in DSSE
//
//counterfeiter:generate . Signer
type Signer interface {
	WrapPayload(string, []byte) (*sdsse.Envelope, error)
	// PaeEncode(*sdsse.Envelope) ([]byte, error)
	Sign(*sdsse.Envelope, []key.PrivateKeyProvider) error
}

type DefaultSigner struct{}

// WrapPayload wraps the contents in a DSSE envelope and sets the type
func (ds *DefaultSigner) WrapPayload(payloadType string, payload []byte) (*sdsse.Envelope, error) {
	if payloadType == "" {
		return nil, errors.New("payload type not set")
	}

	return &sdsse.Envelope{
		Payload:     payload,
		PayloadType: payloadType,
		Signatures:  []*sdsse.Signature{},
	}, nil
}

// PaeEncode implements the signing sequence according to the DSSE protocol
func (ds *DefaultSigner) PaeEncode(env *sdsse.Envelope) ([]byte, error) {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s",
		len(env.GetPayloadType()), env.GetPayloadType(),
		len(env.GetPayload()), env.GetPayload()), nil
}

// Sign encodes the payload of a DSSE envelope and signs it. If the envelope
// already has signatures in it, the new signatures are appended to the exisiting
// ones.
func (ds *DefaultSigner) Sign(env *sdsse.Envelope, keys []key.PrivateKeyProvider) error {
	// Encode the envelope data
	encoded, err := ds.PaeEncode(env)
	if err != nil {
		return fmt.Errorf("failed PAE encoding the envelope: %w", err)
	}

	// Create a new key signer
	signer := key.NewSigner()

	signatures := []*sdsse.Signature{}
	for i, kp := range keys {
		sig, err := signer.SignMessage(kp, encoded)
		if err != nil {
			return fmt.Errorf("error signing envelope with key #%d: %w", i, err)
		}
		signatures = append(signatures, &sdsse.Signature{
			Sig: sig,
			// Keyid: "", // not implemented yet
		})
	}

	env.Signatures = append(env.Signatures, signatures...)
	return nil
}
