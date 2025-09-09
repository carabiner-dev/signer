// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"fmt"

	"github.com/carabiner-dev/signer/options"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

type Verifier interface {
	RunVerification(*options.Verifier, *sdsse.Envelope) (*verify.VerificationResult, error)
	OpenEnvelope(string) (*sdsse.Envelope, error)
}

type DefaultVerifier struct{}

// RunVerification verifies the DSSE envelope
func (dv *DefaultVerifier) RunVerification(
	opts *options.Verifier, env *sdsse.Envelope,
) (*verify.VerificationResult, error) {

	return nil, nil
}

// OpenEnvelope parses a DSSE envelope
func (dv *DefaultVerifier) OpenEnvelope(data string) (*sdsse.Envelope, error) {
	env := &sdsse.Envelope{}
	if err := protojson.Unmarshal([]byte(data), env); err != nil {
		return nil, fmt.Errorf("unmarshaling DSSE envelope: %w", err)
	}
	return env, nil
}
