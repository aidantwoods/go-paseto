package paseto

import "errors"

type payload interface {
	bytes() []byte
}

func protocolForPayload(payload payload) (*Protocol, error) {
	switch payload.(type) {
	default:
		return nil, errors.New("Unsupported Payload")
	case v4LocalPayload:
		return &V4Local, nil
	case v4PublicPayload:
		return &V4Public, nil
	}
}
