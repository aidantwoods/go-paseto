package paseto

import "errors"

type payload interface {
	bytes() []byte
}

func protocolForPayload(payload payload) (Protocol, error) {
	switch payload.(type) {
	default:
		return Protocol{}, errors.New("Unsupported Payload")
	case v2LocalPayload:
		return V2Local, nil
	case v2PublicPayload:
		return V2Public, nil
	case v3LocalPayload:
		return V3Local, nil
	case v4LocalPayload:
		return V4Local, nil
	case v4PublicPayload:
		return V4Public, nil
	}
}
