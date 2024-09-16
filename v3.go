package paseto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"aidanwoods.dev/go-paseto/internal/encoding"
	"aidanwoods.dev/go-paseto/internal/random"
	t "aidanwoods.dev/go-result"
)

func v3PublicSign(packet TokenClaimsAndFooter, key V3AsymmetricSecretKey, implicit []byte) message {
	data, footer := packet.Claims, packet.Footer
	header := []byte(V3Public.Header())

	m2 := encoding.Pae(key.Public().compressed(), header, data, footer, implicit)

	hash := sha512.Sum384(m2)

	r, s := t.NewTupleResult(ecdsa.Sign(rand.Reader, &key.material, hash[:])).
		Expect("sign should always succeed").
		Destructure()

	var rBytes [48]byte
	var sBytes [48]byte

	r.FillBytes(rBytes[:])
	s.FillBytes(sBytes[:])

	sig := append(rBytes[:], sBytes[:]...)

	if len(sig) != 96 {
		panic("Bad signature length")
	}

	var signature [96]byte
	copy(signature[:], sig)

	return newMessageFromPayloadAndFooter(v3PublicPayload{data, signature}, footer)
}

func v3PublicVerify(msg message, key V3AsymmetricPublicKey, implicit []byte) t.Result[TokenClaimsAndFooter] {
	payload, ok := msg.p.(v3PublicPayload)
	if msg.header() != V3Public.Header() || !ok {
		return t.Err[TokenClaimsAndFooter](errorMessageHeaderVerify(V3Public, msg.header()))
	}

	header, footer := []byte(msg.header()), msg.footer
	data := payload.message

	m2 := encoding.Pae(key.compressed(), header, data, footer, implicit)

	hash := sha512.Sum384(m2)

	r := new(big.Int).SetBytes(payload.signature[:48])
	s := new(big.Int).SetBytes(payload.signature[48:])

	if !ecdsa.Verify(&key.material, hash[:], r, s) {
		return t.Err[TokenClaimsAndFooter](errorBadSignature)
	}

	return t.Ok(TokenClaimsAndFooter{data, footer})
}

func v3LocalEncrypt(p TokenClaimsAndFooter, key V3SymmetricKey, implicit []byte, unitTestNonce []byte) message {
	var nonce [32]byte
	random.UseProvidedOrFillBytes(unitTestNonce, nonce[:])

	encKey, authKey, nonce2 := key.split(nonce)

	blockCipher := t.NewResult(aes.NewCipher(encKey[:])).
		Expect("cipher should construct")

	cipherText := make([]byte, len(p.Claims))
	cipher.NewCTR(blockCipher, nonce2[:]).XORKeyStream(cipherText, p.Claims)

	header := []byte(V3Local.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, p.Footer, implicit)

	hm := hmac.New(sha512.New384, authKey[:])
	t.NewResult(hm.Write(preAuth)).Expect("hmac write should succeed")

	var tag [48]byte
	copy(tag[:], hm.Sum(nil))

	return newMessageFromPayloadAndFooter(v3LocalPayload{nonce, cipherText, tag}, p.Footer)
}

func v3LocalDecrypt(msg message, key V3SymmetricKey, implicit []byte) t.Result[TokenClaimsAndFooter] {
	payload, ok := msg.p.(v3LocalPayload)
	if msg.header() != V3Local.Header() || !ok {
		return t.Err[TokenClaimsAndFooter](errorMessageHeaderDecrypt(V3Local, msg.header()))
	}

	nonce, cipherText, givenTag := payload.nonce, payload.cipherText, payload.tag
	encKey, authKey, nonce2 := key.split(nonce)

	header := []byte(msg.header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, msg.footer, implicit)

	hm := hmac.New(sha512.New384, authKey[:])
	t.NewResult(hm.Write(preAuth)).Expect("hmac write should succeed")

	var expectedTag [48]byte
	copy(expectedTag[:], hm.Sum(nil))

	if !hmac.Equal(expectedTag[:], givenTag[:]) {
		return t.Err[TokenClaimsAndFooter](errorBadMAC)
	}

	blockCipher := t.NewResult(aes.NewCipher(encKey[:])).
		Expect("cipher should construct")

	plainText := make([]byte, len(cipherText))
	cipher.NewCTR(blockCipher, nonce2[:]).XORKeyStream(plainText, cipherText)

	return t.Ok(TokenClaimsAndFooter{plainText, msg.footer})
}
