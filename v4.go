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

func v4PublicSign(packet ClaimsAndFooter, key V4AsymmetricSecretKey, implicit []byte) message {
	data, footer := packet.Claims, packet.Footer
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

func v4PublicVerify(msg message, key V4AsymmetricPublicKey, implicit []byte) t.Result[ClaimsAndFooter] {
	payload, ok := msg.p.(v4PublicPayload)
	if msg.header() != V4Public.Header() || !ok {
		return t.Err[ClaimsAndFooter](errorMessageHeaderVerify(V4Public, msg.header()))
	}

	header, footer := []byte(msg.header()), msg.footer
	data := payload.message

	m2 := encoding.Pae(header, data, footer, implicit)

	if !ed25519.Verify(key.material, m2, payload.signature[:]) {
		return t.Err[ClaimsAndFooter](errorBadSignature)
	}

	return t.Ok(ClaimsAndFooter{data, footer})
}

func v4LocalEncrypt(p ClaimsAndFooter, key V4SymmetricKey, implicit []byte, unitTestNonce []byte) message {
	var nonce [32]byte
	random.UseProvidedOrFillBytes(unitTestNonce, nonce[:])

	encKey, authKey, nonce2 := key.split(nonce)

	cipher := t.NewResult(chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])).
		Expect("cipher should construct")

	cipherText := make([]byte, len(p.Claims))
	cipher.XORKeyStream(cipherText, p.Claims)

	header := []byte(V4Local.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, p.Footer, implicit)

	var tag [32]byte
	hashing.GenericHash(preAuth, tag[:], authKey[:])

	return newMessageFromPayloadAndFooter(v4LocalPayload{nonce, cipherText, tag}, p.Footer)
}

func v4LocalDecrypt(msg message, key V4SymmetricKey, implicit []byte) t.Result[ClaimsAndFooter] {
	payload, ok := msg.p.(v4LocalPayload)
	if msg.header() != V4Local.Header() || !ok {
		return t.Err[ClaimsAndFooter](errorMessageHeaderDecrypt(V4Local, msg.header()))
	}

	nonce, cipherText, givenTag := payload.nonce, payload.cipherText, payload.tag
	encKey, authKey, nonce2 := key.split(nonce)

	header := []byte(msg.header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, msg.footer, implicit)

	var expectedTag [32]byte
	hashing.GenericHash(preAuth, expectedTag[:], authKey[:])

	if !hmac.Equal(expectedTag[:], givenTag[:]) {
		return t.Err[ClaimsAndFooter](errorBadMAC)
	}

	cipher := t.NewResult(chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])).
		Expect("cipher should construct")

	plainText := make([]byte, len(cipherText))
	cipher.XORKeyStream(plainText, cipherText)

	return t.Ok(ClaimsAndFooter{plainText, msg.footer})
}
