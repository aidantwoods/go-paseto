package paseto

// V2Sign signs the token, using the given key.
func (p TokenClaimsAndFooter) V2Sign(key V2AsymmetricSecretKey) string {
	return v2PublicSign(p, key).string()
}

// V2Encrypt signs the token, using the given key.
func (p TokenClaimsAndFooter) V2Encrypt(key V2SymmetricKey) string {
	return v2LocalEncrypt(p, key, nil).string()
}

// V3Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (p TokenClaimsAndFooter) V3Sign(key V3AsymmetricSecretKey, implicit []byte) string {
	return v3PublicSign(p, key, implicit).string()
}

// V3Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (p TokenClaimsAndFooter) V3Encrypt(key V3SymmetricKey, implicit []byte) string {
	return v3LocalEncrypt(p, key, implicit, nil).string()
}

// V4Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (p TokenClaimsAndFooter) V4Sign(key V4AsymmetricSecretKey, implicit []byte) string {
	return v4PublicSign(p, key, implicit).string()
}

// V4Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (p TokenClaimsAndFooter) V4Encrypt(key V4SymmetricKey, implicit []byte) string {
	return v4LocalEncrypt(p, key, implicit, nil).string()
}
