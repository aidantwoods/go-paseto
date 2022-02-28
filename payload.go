package paseto

import "errors"

type payload interface {
	bytes() []byte
}

func protocolForPayload(payload payload) (*Protocol, error) {
	v2Local, v2Public := V2Local, V2Public
	v3Local := V3Local
	v4Local, v4Public := V4Local, V4Public

	switch payload.(type) {
	default:
		return nil, errors.New("Unsupported Payload")
	case v2LocalPayload:
		return &v2Local, nil
	case v2PublicPayload:
		return &v2Public, nil
	case v3LocalPayload:
		return &v3Local, nil
	case v4LocalPayload:
		return &v4Local, nil
	case v4PublicPayload:
		return &v4Public, nil
	}
}
