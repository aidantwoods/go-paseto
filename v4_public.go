package paseto

import (
	"crypto/ed25519"

	"github.com/aidantwoods/go-paseto/internal/encoding"
	"github.com/pkg/errors"
)

func V4PublicSign(packet Packet, key V4AsymmetricSecretKey, implicit []byte) Message {
	data, footer := packet.Content, packet.Footer
	header := []byte(V4Public.Header())

	m2 := encoding.Pae(header, data, footer, implicit)

	sig := ed25519.Sign(key.material, m2)

	if len(sig) != 64 {
		panic("Bad signature length")
	}

	var signature [64]byte
	copy(signature[:], sig)

	return newMessageFromPayload(V4PublicPayload{data, signature}, footer)
}

func V4PublicVerify(message Message, key V4AsymmetricPublicKey, implicit []byte) (Packet, error) {
	var payload V4PublicPayload
	var ok bool

	if payload, ok = message.payload.(V4PublicPayload); message.Header() != V4Public.Header() || !ok {
		var p Packet
		return p, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
	}

	header, footer := []byte(message.Header()), message.footer
	data := payload.message

	m2 := encoding.Pae(header, data, footer, implicit)

	if !ed25519.Verify(key.material, m2, payload.signature[:]) {
		var p Packet
		return p, errors.Errorf("Bad signature")
	}

	return Packet{data, footer}, nil
}
