package paseto_test

import (
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

func TestV2AsymmetricSecretKeyImport(t *testing.T) {
	badKey := "4737385058576e39434c7537735233507544516e3337744f4245666e53376835636d664437784b646e44663454435257594a6356443530465177704a694b6f4c"

	_, err := paseto.NewV2AsymmetricSecretKeyFromHex(badKey)
	require.Error(t, err)

	goodKey := "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"

	_, err = paseto.NewV2AsymmetricSecretKeyFromHex(goodKey)
	require.NoError(t, err)
}

func TestV4AsymmetricSecretKeyImport(t *testing.T) {
	badKey := "4737385058576e39434c7537735233507544516e3337744f4245666e53376835636d664437784b646e44663454435257594a6356443530465177704a694b6f4c"

	_, err := paseto.NewV4AsymmetricSecretKeyFromHex(badKey)
	require.Error(t, err)

	goodKey := "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"

	_, err = paseto.NewV4AsymmetricSecretKeyFromHex(goodKey)
	require.NoError(t, err)
}
