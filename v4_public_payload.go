package paseto

import (
	"github.com/pkg/errors"
)

// V4PublicPayload v4 local payload
type V4PublicPayload struct {
	message   []byte
	signature [64]byte
}

func (p V4PublicPayload) Bytes() []byte {
	return append(p.message, p.signature[:]...)
}

func NewV4PublicPayload(bytes []byte) (V4PublicPayload, error) {
	signatureOffset := len(bytes) - 64

	if signatureOffset < 0 {
		var p V4PublicPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	message := make([]byte, len(bytes)-64)
	var signature [64]byte

	copy(message, bytes[:signatureOffset])
	copy(signature[:], bytes[signatureOffset:])

	return V4PublicPayload{message, signature}, nil
}
