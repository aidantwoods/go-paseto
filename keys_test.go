package paseto_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

func TestV2AsymmetricSecretKeyImport(t *testing.T) {
	badKey := "4737385058576e39434c7537735233507544516e3337744f4245666e53376835636d664437784b646e44663454435257594a6356443530465177704a694b6f4c"

	_, err := paseto.NewV2AsymmetricSecretKeyFromHex(badKey)
	require.Error(t, err)
	require.NotErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})

	goodKey := "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"

	_, err = paseto.NewV2AsymmetricSecretKeyFromHex(goodKey)
	require.NoError(t, err)
}

func TestV4AsymmetricSecretKeyImport(t *testing.T) {
	badKey := "4737385058576e39434c7537735233507544516e3337744f4245666e53376835636d664437784b646e44663454435257594a6356443530465177704a694b6f4c"

	_, err := paseto.NewV4AsymmetricSecretKeyFromHex(badKey)
	require.Error(t, err)
	require.NotErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})

	goodKey := "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"

	_, err = paseto.NewV4AsymmetricSecretKeyFromHex(goodKey)
	require.NoError(t, err)
}

func TestGoObjectsImports(t *testing.T) {
	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, err = paseto.NewV2AsymmetricPublicKeyFromEd25519(ed25519Pub)
	require.NoError(t, err)
	_, err = paseto.NewV2AsymmetricSecretKeyFromEd25519(ed25519Priv)
	require.NoError(t, err)

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ecdsaPub := ecdsaPriv.PublicKey

	_, err = paseto.NewV3AsymmetricPublicKeyFromEcdsa(ecdsaPub)
	require.NoError(t, err)
	_, err = paseto.NewV3AsymmetricSecretKeyFromEcdsa(*ecdsaPriv)
	require.NoError(t, err)

	_, err = paseto.NewV4AsymmetricPublicKeyFromEd25519(ed25519Pub)
	require.NoError(t, err)
	_, err = paseto.NewV4AsymmetricSecretKeyFromEd25519(ed25519Priv)
	require.NoError(t, err)
}

func TestBadEcdsaCurveImport(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaPub := ecdsaPriv.PublicKey

	_, err = paseto.NewV3AsymmetricPublicKeyFromEcdsa(ecdsaPub)
	require.Error(t, err)
	_, err = paseto.NewV3AsymmetricSecretKeyFromEcdsa(*ecdsaPriv)
	require.Error(t, err)
}
