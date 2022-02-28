package paseto

import (
	"errors"
	"fmt"
)

var (
	// V2Local represents a v2 protocol in local mode
	V2Local = Protocol{Version2, Local}
	// V2Public represents a v2 protocol in public mode
	V2Public = Protocol{Version2, Public}
	// V3Local represents a v3 protocol in local mode
	V3Local = Protocol{Version3, Local}
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
func NewProtocol(version Version, purpose Purpose) (Protocol, error) {
	switch version {
	default:
		return Protocol{}, errors.New("Unsupported PASETO version")
	case Version2:
		switch purpose {
		default:
			return Protocol{}, errors.New("Unsupported PASETO purpose")
		case Local:
			return V2Local, nil
		case Public:
			return V2Public, nil
		}
	case Version3:
		switch purpose {
		default:
			return Protocol{}, errors.New("Unsupported PASETO purpose")
		case Local:
			return V3Local, nil
		}
	case Version4:
		switch purpose {
		default:
			return Protocol{}, errors.New("Unsupported PASETO purpose")
		case Local:
			return V4Local, nil
		case Public:
			return V4Public, nil
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
		return nil, errors.New("Unsupported PASETO version")
	case Version2:
		switch p.purpose {
		default:
			return nil, errors.New("Unsupported PASETO purpose")
		case Local:
			return newV2LocalPayload(bytes)
		case Public:
			return newV2PublicPayload(bytes)
		}
	case Version3:
		switch p.purpose {
		default:
			return nil, errors.New("Unsupported PASETO purpose")
		case Local:
			return newV3LocalPayload(bytes)
		}
	case Version4:
		switch p.purpose {
		default:
			return nil, errors.New("Unsupported PASETO purpose")
		case Local:
			return newV4LocalPayload(bytes)
		case Public:
			return newV4PublicPayload(bytes)
		}
	}
}
