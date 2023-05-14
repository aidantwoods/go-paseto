package paserk

import (
	"aidanwoods.dev/go-paseto/v2"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSerializeKey(t *testing.T) {
	k, _ := paseto.NewV4AsymmetricPublicKeyFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	s, err := SerializeKey(k)
	require.NoError(t, err)
	require.Equal(t, "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", s)
}

func TestDeserializeKey(t *testing.T) {
	k, err := DeserializeKey[paseto.V4AsymmetricPublicKey]("k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	require.NoError(t, err)
	require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", k.ExportHex())
}

func TestDeserializeKeyFailure(t *testing.T) {
	_, err := DeserializeKey[paseto.V4AsymmetricPublicKey]("kx.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	require.Error(t, err)
	require.Equal(t, "invalid PASERK version number", err.Error())

	_, err = DeserializeKey[paseto.V4AsymmetricPublicKey]("k4.something.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	require.Error(t, err)
	require.Equal(t, "invalid PASERK type", err.Error())

	_, err = DeserializeKey[paseto.V4AsymmetricPublicKey]("k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	require.Error(t, err)
	require.Equal(t, "cannot decode PASERK of type 'k4.secret', expected 'k4.public'", err.Error())

	_, err = DeserializeKey[paseto.V4AsymmetricPublicKey]("k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	require.Error(t, err)
	require.Equal(t, "cannot decode PASERK of type 'k2.public', expected 'k4.public'", err.Error())
}

func TestSerializeKeyID(t *testing.T) {
	k, _ := paseto.V4SymmetricKeyFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	s, err := SerializeKeyID(k)
	require.NoError(t, err)
	require.Equal(t, "k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559", s)
}
