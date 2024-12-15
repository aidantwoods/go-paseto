package paseto

// KeyType indicates if key is symmetric, private or public
type KeyType string

// KeyVersion indicates the token version the key may be used for
type KeyVersion int

const (
	// Symmetric key used for local tokens
	KeyTypeLocal KeyType = "local"
	// Asymmetric secret key used for public tokens
	KeyTypeSecret KeyType = "secret"
	// Asymmetric public key used for public tokens
	KeyTypePublic KeyType = "public"
)
