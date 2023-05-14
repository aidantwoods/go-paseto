package paserk

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"hash"
	"strconv"
	"strings"

	"aidanwoods.dev/go-paseto/v2"
)

// PaserkType reflects the type field of a PASERK
type PaserkType string

const (
	// Unique Identifier for a separate PASERK for local PASETOs
	PaserkTypeLid PaserkType = "lid"
	// Symmetric key for local tokens
	PaserkTypeLocal PaserkType = "local"
	// Symmetric key wrapped using asymmetric encryption
	PaserkTypeSeal PaserkType = "seal"
	// Symmetric key wrapped by another symmetric key
	PaserkTypeLocalWrap PaserkType = "local-wrap"
	// Symmetric key wrapped using password-based encryption
	PaserkTypeLocalPw PaserkType = "local-pw"
	// Unique Identifier for a separate PASERK for public PASETOs. (Secret Key)
	PaserkTypeSid PaserkType = "sid"
	// Public key for verifying public tokens
	PaserkTypePublic PaserkType = "public"
	// Unique Identifier for a separate PASERK for public PASETOs. (Public Key)
	PaserkTypePid PaserkType = "pid"
	// Secret key for signing public tokens
	PaserkTypeSecret PaserkType = "secret"
	// Asymmetric secret key wrapped by another symmetric key
	PaserkTypeSecretWrap PaserkType = "secret-wrap"
	// Asymmetric secret key wrapped using password-based encryption
	PaserkTypeSecretPw PaserkType = "secret-pw"
)

func parsePaserkType(s string) (PaserkType, error) {
	switch PaserkType(s) {
	case PaserkTypeLid:
		return PaserkTypeLid, nil
	case PaserkTypeLocal:
		return PaserkTypeLocal, nil
	case PaserkTypeSeal:
		return PaserkTypeSeal, nil
	case PaserkTypeLocalWrap:
		return PaserkTypeLocalWrap, nil
	case PaserkTypeLocalPw:
		return PaserkTypeLocalPw, nil
	case PaserkTypeSid:
		return PaserkTypeSid, nil
	case PaserkTypePublic:
		return PaserkTypePublic, nil
	case PaserkTypePid:
		return PaserkTypePid, nil
	case PaserkTypeSecret:
		return PaserkTypeSecret, nil
	case PaserkTypeSecretWrap:
		return PaserkTypeSecretWrap, nil
	case PaserkTypeSecretPw:
		return PaserkTypeSecretPw, nil
	default:
		return "", errors.New("invalid PASERK type")
	}
}

func (paserkType PaserkType) supportsKeyType(kt paseto.KeyType) bool {
	switch paserkType {
	case PaserkTypeLocal:
		return kt == paseto.KeyTypeLocal
	case PaserkTypeSecret:
		return kt == paseto.KeyTypeSecret
	case PaserkTypePublic:
		return kt == paseto.KeyTypePublic
	default:
		return false
	}
}

// SerializeKey exports a local/secret/public key as a PASERK
func SerializeKey(k Key) (string, error) {
	var paserkType PaserkType
	switch k.Type() {
	case paseto.KeyTypeLocal:
		paserkType = PaserkTypeLocal
	case paseto.KeyTypeSecret:
		paserkType = PaserkTypeSecret
	case paseto.KeyTypePublic:
		paserkType = PaserkTypePublic
	default:
		return "", errors.New("invalid key type")
	}
	header := "k" + strconv.Itoa(int(k.Version())) + "." + string(paserkType) + "."
	data := base64.RawURLEncoding.EncodeToString(k.ExportBytes())
	return header + data, nil
}

// SerializeKeyID exports a local/secret/public key's identity as a lid/sid/pid PASERK
func SerializeKeyID(k Key) (string, error) {
	var paserkType PaserkType
	switch k.Type() {
	case paseto.KeyTypeLocal:
		paserkType = PaserkTypeLid
	case paseto.KeyTypeSecret:
		paserkType = PaserkTypeSid
	case paseto.KeyTypePublic:
		paserkType = PaserkTypePid
	default:
		return "", errors.New("invalid key type")
	}
	var h hash.Hash
	switch k.Version() {
	case 1, 3:
		h = sha512.New384()
	case 2, 4:
		h, _ = blake2b.New(33, nil)
	default:
		return "", errors.New("invalid key version")
	}
	header := "k" + strconv.Itoa(int(k.Version())) + "." + string(paserkType) + "."
	h.Write([]byte(header))
	s, err := SerializeKey(k)
	if err != nil {
		return "", err
	}
	h.Write([]byte(s))
	data := base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:33])
	return header + data, nil
}

type KnownKeyTypes interface {
	paseto.V2SymmetricKey |
		paseto.V2AsymmetricSecretKey |
		paseto.V2AsymmetricPublicKey |
		paseto.V3SymmetricKey |
		paseto.V3AsymmetricSecretKey |
		paseto.V3AsymmetricPublicKey |
		paseto.V4SymmetricKey |
		paseto.V4AsymmetricSecretKey |
		paseto.V4AsymmetricPublicKey
	Key
}

// DeserializeKey constructs a local/secret/public key of type T from a given
// PASERK, given that it matches type and version of T
func DeserializeKey[T KnownKeyTypes](paserkStr string) (T, error) {
	var t T
	frags := strings.Split(paserkStr, ".")
	if len(frags) != 3 {
		return t, fmt.Errorf("invalid PASERK: %s", paserkStr)
	}
	if len(frags[0]) != 2 || frags[0][0] != 'k' {
		return t, fmt.Errorf("invalid PASERK version field")
	}
	version, err := strconv.Atoi(frags[0][1:])
	if err != nil {
		return t, fmt.Errorf("invalid PASERK version number")
	}
	typ, err := parsePaserkType(frags[1])
	if err != nil {
		return t, err
	}
	data, err := base64.RawURLEncoding.DecodeString(frags[2])
	if err != nil {
		return t, fmt.Errorf("cannot decode data part of PASERK: %w", err)
	}

	if t.Version() != paseto.KeyVersion(version) || !typ.supportsKeyType(t.Type()) {
		return t, fmt.Errorf("cannot decode PASERK of type 'k%d.%s', expected 'k%d.%s'", version, typ, t.Version(), t.Type())
	}

	var key Key
	switch version {
	case 2:
		switch typ {
		case PaserkTypeLocal:
			key, err = paseto.V2SymmetricKeyFromBytes(data)
		case PaserkTypeSecret:
			key, err = paseto.NewV2AsymmetricSecretKeyFromBytes(data)
		case PaserkTypePublic:
			key, err = paseto.NewV2AsymmetricPublicKeyFromBytes(data)
		}
	case 3:
		switch typ {
		case PaserkTypeLocal:
			key, err = paseto.V3SymmetricKeyFromBytes(data)
		case PaserkTypeSecret:
			key, err = paseto.NewV3AsymmetricSecretKeyFromBytes(data)
		case PaserkTypePublic:
			key, err = paseto.NewV3AsymmetricPublicKeyFromBytes(data)
		}
	case 4:
		switch typ {
		case PaserkTypeLocal:
			key, err = paseto.V4SymmetricKeyFromBytes(data)
		case PaserkTypeSecret:
			key, err = paseto.NewV4AsymmetricSecretKeyFromBytes(data)
		case PaserkTypePublic:
			key, err = paseto.NewV4AsymmetricPublicKeyFromBytes(data)
		}
	default:
		return t, fmt.Errorf("unsupported PASERK version %d", version)
	}
	if err != nil {
		return t, fmt.Errorf("can't construct key from data part of PASERK: %w", err)
	}
	if key == nil {
		return t, fmt.Errorf("deserializing of key of type %T is not implemented", t)
	}
	return key.(T), nil
}
