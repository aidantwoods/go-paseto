package paseto

import (
	"strings"

	"github.com/aidantwoods/go-paseto/internal/encoding"
	"github.com/pkg/errors"
)

type Message struct {
	protocol Protocol
	payload  Payload
	footer   []byte
}

func (m Message) Header() string {
	return m.protocol.Header()
}

func (m Message) Payload() Payload {
	return m.payload
}

func (m Message) UnsafeFooter() []byte {
	return m.footer
}

func (m Message) Encoded() string {
	main := m.Header() + encoding.Encode(m.payload.Bytes())

	if len(m.footer) == 0 {
		return main
	}

	return main + "." + encoding.Encode(m.footer)
}

func NewMessageFromPayload(payload Payload, footer []byte) (Message, error) {
	var protocol Protocol
	var err error

	if protocol, err = ProtocolForPayload(payload); err != nil {
		var m Message
		return m, err
	}

	return Message{protocol, payload, footer}, nil
}

func newMessageFromPayload(payload Payload, footer []byte) Message {
	var message Message
	var err error

	// Assume internal callers won't construct bad payloads
	if message, err = NewMessageFromPayload(payload, footer); err != nil {
		panic("Sanity check for payload failed")
	}

	return message
}

func deconstructToken(token string) (header string, encodedPayload string, encodedFooter string, err error) {
	parts := strings.Split(token, ".")

	partsLen := len(parts)

	if partsLen != 3 && partsLen != 4 {
		err = errors.New("Invalid number of message parts in token")
		return
	}

	header = strings.Join([]string{parts[0], parts[1]}, ".") + "."
	encodedPayload = parts[2]

	if partsLen == 4 {
		encodedFooter = parts[3]
	} else {
		encodedFooter = ""
	}

	return header, encodedPayload, encodedFooter, nil
}

func NewMessage(protocol Protocol, token string) (Message, error) {
	header, encodedPayload, encodedFooter, err := deconstructToken(token)

	if err != nil {
		var m Message
		return m, err
	}

	if header != protocol.Header() {
		var m Message
		return m, errors.Errorf("Message header is not valid with the given purpose, expected %s got %s", protocol.Header(), header)
	}

	var payloadBytes []byte

	if payloadBytes, err = encoding.Decode(encodedPayload); err != nil {
		var m Message
		return m, err
	}

	var footer []byte

	if footer, err = encoding.Decode(encodedFooter); err != nil {
		var m Message
		return m, err
	}

	var payload Payload
	if payload, err = protocol.NewPayload(payloadBytes); err != nil {
		var m Message
		return m, err
	}

	return newMessageFromPayload(payload, footer), nil
}

func (m Message) V4Verify(key V4AsymmetricPublicKey, implicit []byte) (*Token, error) {
	if packet, err := V4PublicVerify(m, key, implicit); err == nil {
		return packet.token()
	} else {
		return nil, err
	}
}

func (m Message) V4Decrypt(key V4SymmetricKey, implicit []byte) (*Token, error) {
	if packet, err := V4LocalDecrypt(m, key, implicit); err == nil {
		return packet.token()
	} else {
		return nil, err
	}
}
