package paseto

import "fmt"

// type of PASERK token
type PaserkType int

// Error indicating the given paserk import/export method is not yet implemented on the key type.
type NotImplementedError struct {
	keyTypeStr    string
	paserkTypeStr string
}

// Error indicating the given paserk type is not valid for the key type.
type InvalidPaserkTypeError struct {
	keyTypeStr    string
	paserkTypeStr string
}

const (
	// Invalid Paserk token type
	PaserkTypeInvalid PaserkType = 0
	// Unique Identifier for a separate PASERK for local PASETOs
	PaserkTypeLid PaserkType = 1
	// Symmetric key for local tokens
	PaserkTypeLocal PaserkType = 2
	// Symmetric key wrapped using asymmetric encryption
	PaserkTypeSeal PaserkType = 3
	// Symmetric key wrapped by another symmetric key
	PaserkTypeLocalWrap PaserkType = 4
	// Symmetric key wrapped using password-based encryption
	PaserkTypeLocalPw PaserkType = 5
	// Unique Identifier for a separate PASERK for public PASETOs. (Secret Key)
	PaserkTypeSid PaserkType = 6
	// Public key for verifying public tokens
	PaserkTypePublic PaserkType = 7
	// Unique Identifier for a separate PASERK for public PASETOs. (Public Key)
	PaserkTypePid PaserkType = 8
	// Secret key for signing public tokens
	PaserkTypeSecret PaserkType = 9
	// Asymmetric secret key wrapped by another symmetric key
	PaserkTypeSecretWrap PaserkType = 10
	// Asymmetric secret key wrapped using password-based encryption
	PaserkTypeSecretPw PaserkType = 11
)

// Convert token type to PASERK header string `type`
func PaserkTypeToString(paserkType PaserkType) string {
	switch paserkType {
	case PaserkTypeLid:
		return "lid"
	case PaserkTypeLocal:
		return "local"
	case PaserkTypeSeal:
		return "seal"
	case PaserkTypeLocalWrap:
		return "local-wrap"
	case PaserkTypeLocalPw:
		return "local-pw"
	case PaserkTypeSid:
		return "sid"
	case PaserkTypePublic:
		return "public"
	case PaserkTypePid:
		return "pid"
	case PaserkTypeSecret:
		return "secret"
	case PaserkTypeSecretWrap:
		return "secret-wrap"
	case PaserkTypeSecretPw:
		return "secret-pw"
	default:
		return ""
	}
}

// Parse token type from string value of `type` field of PASERK token
func PaserkTypeFromString(typeStr string) PaserkType {
	switch typeStr {
	case "lid":
		return PaserkTypeLid
	case "local":
		return PaserkTypeLocal
	case "seal":
		return PaserkTypeSeal
	case "local-wrap":
		return PaserkTypeLocalWrap
	case "local-pw":
		return PaserkTypeLocalPw
	case "sid":
		return PaserkTypeSid
	case "public":
		return PaserkTypePublic
	case "pid":
		return PaserkTypePid
	case "secret":
		return PaserkTypeSecret
	case "secret-wrap":
		return PaserkTypeSecretWrap
	case "secret-pw":
		return PaserkTypeSecretPw
	default:
		return PaserkTypeInvalid
	}
}

// Checks if the representation (paserk token type) is available for the key
func (paserkType PaserkType) isAvailableForKey(key Key) bool {
	switch key.getPurpose() {
	case keyPurposeLocal:
		switch paserkType {
		case PaserkTypeLid,
			PaserkTypeLocal,
			PaserkTypeSeal,
			PaserkTypeLocalWrap,
			PaserkTypeLocalPw:
			return true
		default:
			return false
		}
	case keyPurposePublic:
		switch paserkType {
		case PaserkTypePid,
			PaserkTypePublic:
			return true
		default:
			return false
		}
	case keyPurposeSecret:
		switch paserkType {
		case PaserkTypeSid,
			PaserkTypeSecret,
			PaserkTypeSecretWrap,
			PaserkTypeSecretPw:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func (e NotImplementedError) Error() string {
	return fmt.Sprintf("PASERK type %s is not yet implemented on key type %s", e.paserkTypeStr, e.keyTypeStr)
}

func (e InvalidPaserkTypeError) Error() string {
	return fmt.Sprintf("PASERK type %s is invalid for key type %s", e.paserkTypeStr, e.keyTypeStr)
}
