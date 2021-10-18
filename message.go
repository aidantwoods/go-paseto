package paseto

import (
	"strings"

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

func (m Message) Footer() []byte {
	return m.footer
}

func (m Message) encoded() string {
	main := m.Header() + b64urlEncode(m.payload.Bytes())

	if len(m.footer) == 0 {
		return main
	}

	return main + "." + b64urlEncode(m.footer)
}

func NewMessage(payload Payload, footer []byte) (Message, error) {
	var protocol Protocol
	var err error

	if protocol, err = ProtocolForPayload(payload); err != nil {
		var m Message
		return m, err
	}

	return Message{protocol, payload, footer}, nil
}

func newMessage(payload Payload, footer []byte) Message {
	// Assume internal callers won't construct bad payloads
	protocol, _ := ProtocolForPayload(payload)

	return Message{protocol, payload, footer}
}

func deconstructToken(token string) (header string, encodedPayload string, encodedFooter string, err error) {
	parts := strings.Split(token, ".")

	partsLen := len(parts)

	if partsLen != 3 && partsLen != 4 {
		err = errors.New("Invalid number of message parts in token")
		return
	}

	header = strings.Join([]string{parts[0], parts[1]}, ".")
	encodedPayload = parts[2]

	if partsLen == 4 {
		encodedFooter = parts[3]
	} else {
		encodedFooter = ""
	}

	return header, encodedPayload, encodedFooter, nil
}

func NewMessageFromToken(protocol Protocol, token string) (Message, error) {
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

	if payloadBytes, err = b64urlDecode(encodedPayload); err != nil {
		var m Message
		return m, err
	}

	var footer []byte

	if footer, err = b64urlDecode(encodedFooter); err != nil {
		var m Message
		return m, err
	}

	var payload Payload
	if payload, err = protocol.NewPayload(payloadBytes); err != nil {
		var m Message
		return m, err
	}

	return newMessage(payload, footer), nil
}
