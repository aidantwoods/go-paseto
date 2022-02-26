package paseto

import (
	"errors"
	"fmt"
)

var (
	V4Local  = Protocol{Version4, Local}
	V4Public = Protocol{Version4, Public}
)

type Protocol struct {
	version Version
	purpose Purpose
}

func NewProtocol(version Version, purpose Purpose) (Protocol, error) {
	switch version {
	default:
		var p Protocol
		return p, errors.New("Unsupported PASETO version")
	case Version4:
		switch purpose {
		default:
			var p Protocol
			return p, errors.New("Unsupported PASETO purpose")
		case Local:
			return V4Local, nil
		case Public:
			return V4Public, nil
		}
	}
}

func (p Protocol) Header() string {
	return fmt.Sprintf("%s.%s.", p.version, p.purpose)
}

func (p Protocol) Version() Version {
	return p.version
}

func (p Protocol) Purpose() Purpose {
	return p.purpose
}

func (p Protocol) NewPayload(bytes []byte) (Payload, error) {
	switch p.version {
	default:
		var p Payload
		return p, errors.New("Unsupported PASETO version")
	case Version4:
		switch p.purpose {
		default:
			var p Payload
			return p, errors.New("Unsupported PASETO purpose")
		case Local:
			return NewV4LocalPayload(bytes)
		case Public:
			return NewV4PublicPayload(bytes)
		}
	}
}
