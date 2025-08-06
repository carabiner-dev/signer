package options

// Sign options (not to be confused with signer options) are options
// that control each signing operation behavior.
type Sign struct {
	// PayloadType is the payload type to be declared in DSSE envelopes
	PayloadType string
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
