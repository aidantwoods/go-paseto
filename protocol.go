package paseto

import (
	"errors"
	"fmt"
)

var (
	V4Local = Protocol{Version4, Local}
)

type Protocol struct {
	version Version
	purpose Purpose
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
		}
	}
}
