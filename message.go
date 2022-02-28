package paseto

import (
	"strings"

	"github.com/aidantwoods/go-paseto/internal/encoding"
	"github.com/pkg/errors"
)

// Message is a building block type, only use if you need to use Paseto
// cryptography without Paseto's token or validator semantics.
type Message struct {
	protocol Protocol
	p        payload
	footer   []byte
}

// NewMessage creates a new message from the given token, with an expected
// protocol. If the given token does not match the given token, or if the
// token cannot be parsed, will return an error instead.
func NewMessage(protocol Protocol, token string) (Message, error) {
	header, encodedPayload, encodedFooter, err := deconstructToken(token)
	if err != nil {
		return Message{}, err
	}

	if header != protocol.Header() {
		return Message{}, errors.Errorf("Message header is not valid with the given purpose, expected %s got %s", protocol.Header(), header)
	}

	payloadBytes, err := encoding.Decode(encodedPayload)
	if err != nil {
		return Message{}, err
	}

	footer, err := encoding.Decode(encodedFooter)
	if err != nil {
		return Message{}, err
	}

	payload, err := protocol.newPayload(payloadBytes)
	if err != nil {
		return Message{}, err
	}

	return newMessageFromPayload(payload, footer), nil
}

// Header returns the header string for a Paseto message.
func (m Message) Header() string {
	return m.protocol.Header()
}

// UnsafeFooter returns the footer of a Paseto message. Beware that this footer
// is not cryptographically verified at this stage.
func (m Message) UnsafeFooter() []byte {
	return m.footer
}

// Encoded returns the string representation of a Paseto message.
func (m Message) Encoded() string {
	main := m.Header() + encoding.Encode(m.p.bytes())

	if len(m.footer) == 0 {
		return main
	}

	return main + "." + encoding.Encode(m.footer)
}

func newMessageFromPayload(payload payload, footer []byte) Message {
	if protocol, err := protocolForPayload(payload); err == nil {
		return Message{protocol, payload, footer}
	}

	// Assume internal callers won't construct bad payloads
	panic("Sanity check for payload failed")
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

// V2Verify will verify a v4 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m Message) V2Verify(key V2AsymmetricPublicKey) (*Token, error) {
	if packet, err := v2PublicVerify(m, key); err == nil {
		return packet.token()
	} else {
		return nil, err
	}
}

// V2Decrypt will verify a v4 public paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m Message) V2Decrypt(key V2SymmetricKey) (*Token, error) {
	if packet, err := v2LocalDecrypt(m, key); err == nil {
		return packet.token()
	} else {
		return nil, err
	}
}

// V3Decrypt will verify a v4 public paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m Message) V3Decrypt(key V3SymmetricKey, implicit []byte) (*Token, error) {
	if packet, err := v3LocalDecrypt(m, key, implicit); err == nil {
		return packet.token()
	} else {
		return nil, err
	}
}

// V4Verify will verify a v4 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m Message) V4Verify(key V4AsymmetricPublicKey, implicit []byte) (*Token, error) {
	if packet, err := v4PublicVerify(m, key, implicit); err == nil {
		return packet.token()
	} else {
		return nil, err
	}
}

// V4Decrypt will verify a v4 public paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m Message) V4Decrypt(key V4SymmetricKey, implicit []byte) (*Token, error) {
	if packet, err := v4LocalDecrypt(m, key, implicit); err == nil {
		return packet.token()
	} else {
		return nil, err
	}
}
