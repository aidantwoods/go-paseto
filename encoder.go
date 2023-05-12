package paseto

type TokenEncoder[T any] func(T) ClaimsAndFooter

type Encoder[T any] struct {
	encode TokenEncoder[T]
}

func NewEncoder[T any](encode TokenEncoder[T]) Encoder[T] {
	return Encoder[T]{
		encode: encode,
	}
}

// V2Sign signs the token, using the given key.
func (e Encoder[T]) V2Sign(key V2AsymmetricSecretKey, token T) string {
	return v2PublicSign(e.encode(token), key).string()
}

// V2Encrypt signs the token, using the given key.
func (e Encoder[T]) V2Encrypt(key V2SymmetricKey, token T) string {
	return v2LocalEncrypt(e.encode(token), key, nil).string()
}

// V3Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (e Encoder[T]) V3Sign(key V3AsymmetricSecretKey, token T, implicit []byte) string {
	return v3PublicSign(e.encode(token), key, implicit).string()
}

// V3Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (e Encoder[T]) V3Encrypt(key V3SymmetricKey, token T, implicit []byte) string {
	return v3LocalEncrypt(e.encode(token), key, implicit, nil).string()
}

// V4Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (e Encoder[T]) V4Sign(key V4AsymmetricSecretKey, token T, implicit []byte) string {
	return v4PublicSign(e.encode(token), key, implicit).string()
}

// V4Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (e Encoder[T]) V4Encrypt(key V4SymmetricKey, token T, implicit []byte) string {
	return v4LocalEncrypt(e.encode(token), key, implicit, nil).string()
}
