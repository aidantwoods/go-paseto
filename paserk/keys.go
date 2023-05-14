package paserk

import (
	"aidanwoods.dev/go-paseto/v2"
)

type Key interface {
	ExportBytes() []byte
	Type() paseto.KeyType
	Version() paseto.KeyVersion
}

var _ Key = &paseto.V2SymmetricKey{}
var _ Key = &paseto.V2AsymmetricSecretKey{}
var _ Key = &paseto.V2AsymmetricPublicKey{}
var _ Key = &paseto.V3SymmetricKey{}
var _ Key = &paseto.V3AsymmetricSecretKey{}
var _ Key = &paseto.V3AsymmetricPublicKey{}
var _ Key = &paseto.V4SymmetricKey{}
var _ Key = &paseto.V4AsymmetricSecretKey{}
var _ Key = &paseto.V4AsymmetricPublicKey{}
