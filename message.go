package paseto

import (
	"strings"

	"aidanwoods.dev/go-paseto/internal/encoding"
	"github.com/pkg/errors"
)

// Message is a building block type, only use if you need to use Paseto
// cryptography without Paseto's token or validator semantics.
type message struct {
	protocol Protocol
	p        payload
	footer   []byte
}

// NewMessage creates a new message from the given token, with an expected
// protocol. If the given token does not match the given token, or if the
// token cannot be parsed, will return an error instead.
func newMessage(protocol Protocol, token string) (message, error) {
	header, encodedPayload, encodedFooter, err := deconstructToken(token)
	if err != nil {
		return message{}, err
	}

	if header != protocol.Header() {
		return message{}, errors.Errorf("Message header is not valid with the given purpose, expected %s got %s", protocol.Header(), header)
	}

	payloadBytes, err := encoding.Decode(encodedPayload)
	if err != nil {
		return message{}, err
	}

	footer, err := encoding.Decode(encodedFooter)
	if err != nil {
		return message{}, err
	}

	payload, err := protocol.newPayload(payloadBytes)
	if err != nil {
		return message{}, err
	}

	return newMessageFromPayload(payload, footer), nil
}

// Header returns the header string for a Paseto message.
func (m message) header() string {
	return m.protocol.Header()
}

// UnsafeFooter returns the footer of a Paseto message. Beware that this footer
// is not cryptographically verified at this stage.
func (m message) unsafeFooter() []byte {
	return m.footer
}

// Encoded returns the string representation of a Paseto message.
func (m message) encoded() string {
	main := m.header() + encoding.Encode(m.p.bytes())

	if len(m.footer) == 0 {
		return main
	}

	return main + "." + encoding.Encode(m.footer)
}

func newMessageFromPayload(payload payload, footer []byte) message {
	if protocol, err := protocolForPayload(payload); err == nil {
		return message{protocol, payload, footer}
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

	header = parts[0] + "." + parts[1] + "."
	encodedPayload = parts[2]

	if partsLen == 4 {
		encodedFooter = parts[3]
	} else {
		encodedFooter = ""
	}

	return header, encodedPayload, encodedFooter, nil
}

// V2Verify will verify a v2 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v2Verify(key V2AsymmetricPublicKey) (*Token, error) {
	packet, err := v2PublicVerify(m, key)
	if err != nil {
		return nil, err
	}

	return packet.token()
}

// V2Decrypt will decrypt a v2 local paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v2Decrypt(key V2SymmetricKey) (*Token, error) {
	packet, err := v2LocalDecrypt(m, key)
	if err != nil {
		return nil, err
	}

	return packet.token()
}

// V3Verify will verify a v4 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v3Verify(key V3AsymmetricPublicKey, implicit []byte) (*Token, error) {
	packet, err := v3PublicVerify(m, key, implicit)
	if err != nil {
		return nil, err
	}

	return packet.token()
}

// V3Decrypt will decrypt a v3 local paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v3Decrypt(key V3SymmetricKey, implicit []byte) (*Token, error) {
	packet, err := v3LocalDecrypt(m, key, implicit)
	if err != nil {
		return nil, err
	}

	return packet.token()
}

// V4Verify will verify a v4 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v4Verify(key V4AsymmetricPublicKey, implicit []byte) (*Token, error) {
	packet, err := v4PublicVerify(m, key, implicit)
	if err != nil {
		return nil, err
	}

	return packet.token()
}

// V4Decrypt will decrypt a v4 local paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v4Decrypt(key V4SymmetricKey, implicit []byte) (*Token, error) {
	packet, err := v4LocalDecrypt(m, key, implicit)
	if err != nil {
		return nil, err
	}

	return packet.token()
}
