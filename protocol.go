package paseto

import (
	"errors"
	"fmt"
)

var (
	// V4Local represents a v4 protocol in local mode
	V4Local = Protocol{Version4, Local}
	// V4Public represents a v4 protocol in public mode
	V4Public = Protocol{Version4, Public}
)

// Protocol represents a set of cryptographic operations for paseto
type Protocol struct {
	version Version
	purpose Purpose
}

// NewProtocol creates a new protocol with a given version and purpose (both
// must be valid)
func NewProtocol(version Version, purpose Purpose) (*Protocol, error) {
	v4Local, v4Public := V4Local, V4Public

	switch version {
	default:
		return nil, errors.New("Unsupported PASETO version")
	case Version4:
		switch purpose {
		default:
			return nil, errors.New("Unsupported PASETO purpose")
		case Local:
			return &v4Local, nil
		case Public:
			return &v4Public, nil
		}
	}
}

// Header computes the header for the protocol
func (p Protocol) Header() string {
	return fmt.Sprintf("%s.%s.", p.version, p.purpose)
}

// Version returns the version for a protocol
func (p Protocol) Version() Version {
	return p.version
}

// Purpose returns the purpose for a protocol
func (p Protocol) Purpose() Purpose {
	return p.purpose
}

func (p Protocol) newPayload(bytes []byte) (payload, error) {
	switch p.version {
	default:
		var p payload
		return p, errors.New("Unsupported PASETO version")
	case Version4:
		switch p.purpose {
		default:
			var p payload
			return p, errors.New("Unsupported PASETO purpose")
		case Local:
			return newV4LocalPayload(bytes)
		case Public:
			return newV4PublicPayload(bytes)
		}
	}
}
