package paseto

// keyPurpose indicates if key is symmetric, private or public
type keyPurpose int

// keyVersion indicates the token version the key may be used for
type KeyVersion int

const (
	// Invalid key version
	KeyVersionInvalid KeyVersion = 0
	// Key used for V1 tokens
	KeyVersionV1 KeyVersion = 1
	// Key used for V2 tokens
	KeyVersionV2 KeyVersion = 2
	// Key used for V3 tokens
	KeyVersionV3 KeyVersion = 3
	// Key used for V4 tokens
	KeyVersionV4 KeyVersion = 4

	// Symmetric key used for local tokens
	keyPurposeLocal keyPurpose = 1
	// Asymmetric secret key used for public tokens
	keyPurposeSecret keyPurpose = 2
	// Asymmetric public key used for public tokens
	keyPurposePublic keyPurpose = 3
)

type Key interface {
	// Export raw key data as hex string
	ExportHex() string
	// Export raw key data as byte array
	ExportBytes() []byte
	// Returns purpose of key
	getPurpose() keyPurpose
	// Returns the version of the paseto tokens the key may be used for
	getVersion() KeyVersion
}

// Convert key version to PASERK header string
func KeyVersionToString(version KeyVersion) string {
	switch version {
	case KeyVersionV1:
		return "k1"
	case KeyVersionV2:
		return "k2"
	case KeyVersionV3:
		return "k3"
	case KeyVersionV4:
		return "k4"
	default:
		return ""
	}
}

// Parse key version from PASERK header string (eg. "k2")
func KeyVersionFromString(versionStr string) KeyVersion {
	switch versionStr {
	case "k1":
		return KeyVersionV1
	case "k2":
		return KeyVersionV2
	case "k3":
		return KeyVersionV3
	case "k4":
		return KeyVersionV4
	default:
		return KeyVersionInvalid
	}
}
