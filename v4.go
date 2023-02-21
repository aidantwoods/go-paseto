package paseto

import (
	"crypto/ed25519"
	"crypto/hmac"

	"aidanwoods.dev/go-paseto/internal/encoding"
	"aidanwoods.dev/go-paseto/internal/hashing"
	"aidanwoods.dev/go-paseto/internal/random"
	t "aidanwoods.dev/go-result"
	"golang.org/x/crypto/chacha20"
)

func v4PublicSign(packet packet, key V4AsymmetricSecretKey, implicit []byte) message {
	data, footer := packet.content, packet.footer
	header := []byte(V4Public.Header())

	m2 := encoding.Pae(header, data, footer, implicit)

	sig := ed25519.Sign(key.material, m2)
	if len(sig) != 64 {
		panic("Bad signature length")
	}

	var signature [64]byte
	copy(signature[:], sig)

	return newMessageFromPayloadAndFooter(v4PublicPayload{data, signature}, footer)
}

func v4PublicVerify(msg message, key V4AsymmetricPublicKey, implicit []byte) t.Result[packet] {
	payload, ok := msg.p.(v4PublicPayload)
	if msg.header() != V4Public.Header() || !ok {
		return t.Err[packet](errorMessageHeaderVerify(V4Public, msg.header()))
	}

	header, footer := []byte(msg.header()), msg.footer
	data := payload.message

	m2 := encoding.Pae(header, data, footer, implicit)

	if !ed25519.Verify(key.material, m2, payload.signature[:]) {
		return t.Err[packet](errorBadSignature)
	}

	return t.Ok(packet{data, footer})
}

func v4LocalEncrypt(p packet, key V4SymmetricKey, implicit []byte, unitTestNonce []byte) message {
	var nonce [32]byte
	random.UseProvidedOrFillBytes(unitTestNonce, nonce[:])

	encKey, authKey, nonce2 := key.split(nonce)

	cipher, err := chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	cipherText := make([]byte, len(p.content))
	cipher.XORKeyStream(cipherText, p.content)

	header := []byte(V4Local.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, p.footer, implicit)

	var tag [32]byte
	hashing.GenericHash(preAuth, tag[:], authKey[:])

	return newMessageFromPayloadAndFooter(v4LocalPayload{nonce, cipherText, tag}, p.footer)
}

func v4LocalDecrypt(msg message, key V4SymmetricKey, implicit []byte) t.Result[packet] {
	payload, ok := msg.p.(v4LocalPayload)
	if msg.header() != V4Local.Header() || !ok {
		return t.Err[packet](errorMessageHeaderDecrypt(V4Local, msg.header()))
	}

	nonce, cipherText, givenTag := payload.nonce, payload.cipherText, payload.tag
	encKey, authKey, nonce2 := key.split(nonce)

	header := []byte(msg.header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, msg.footer, implicit)

	var expectedTag [32]byte
	hashing.GenericHash(preAuth, expectedTag[:], authKey[:])

	if !hmac.Equal(expectedTag[:], givenTag[:]) {
		return t.Err[packet](errorBadMAC)
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	plainText := make([]byte, len(cipherText))
	cipher.XORKeyStream(plainText, cipherText)

	return t.Ok(packet{plainText, msg.footer})
}
