package paseto_test

import (
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

func TestUnwrapEmptyFooter(t *testing.T) {
	token := "v4.local.aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ."

	parser := paseto.NewParser()
	footer, err := parser.UnsafeParseFooter(paseto.V4Local, token)
	require.NoError(t, err)
	require.Empty(t, footer)
}
