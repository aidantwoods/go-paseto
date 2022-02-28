package paseto

import "errors"

type payload interface {
	bytes() []byte
}

func protocolForPayload(payload payload) (*Protocol, error) {
	v3Local := V3Local
	v4Local, v4Public := V4Local, V4Public

	switch payload.(type) {
	default:
		return nil, errors.New("Unsupported Payload")
	case v3LocalPayload:
		return &v3Local, nil
	case v4LocalPayload:
		return &v4Local, nil
	case v4PublicPayload:
		return &v4Public, nil
	}
}
