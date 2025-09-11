package options

import "github.com/carabiner-dev/signer/key"

// Sign options (not to be confused with signer options) are options
// that control each signing operation behavior.
type Sign struct {
	// PayloadType is the payload type to be declared in DSSE envelopes
	PayloadType string

	// PrivateKeys for DSSE envelope signing. These will be honored later
	// to reuse in bundle signing
	Keys []key.PrivateKeyProvider
}

var DefaultSign = Sign{
	PayloadType: "application/octet-stream",
}

type SignOptFn = func(*Sign) error

// WithPayloadType sets the DSSE payload type
func WithPayloadType(t string) SignOptFn {
	return func(opts *Sign) error {
		opts.PayloadType = t
		return nil
	}
}

// WithKey adds one or more key providers that will be used to sign
func WithKey(keys ...key.PrivateKeyProvider) SignOptFn {
	return func(opts *Sign) error {
		opts.Keys = append(opts.Keys, keys...)
		return nil
	}
}
