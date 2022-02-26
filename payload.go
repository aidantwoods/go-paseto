package paseto

import "errors"

type Payload interface {
	Bytes() []byte
}

func ProtocolForPayload(payload Payload) (Protocol, error) {
	switch payload.(type) {
	default:
		var p Protocol
		return p, errors.New("Unsupported Payload")
	case V4LocalPayload:
		return V4Local, nil
	case V4PublicPayload:
		return V4Public, nil
	}
}
