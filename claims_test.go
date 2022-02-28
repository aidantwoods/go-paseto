package paseto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAllClaimsPassV2(t *testing.T) {
	token := NewToken()

	token.SetAudience("a")
	token.SetJti("b")
	token.SetIssuer("c")
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetSubject("d")

	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := NewV2SymmetricKey()
	secretKey := NewV2AsymmetricSecretKey()

	encrypted, err := token.V2Encrypt(key)
	require.NoError(t, err)

	signed, err := token.V2Sign(secretKey)
	require.NoError(t, err)

	parser := MakeParser(nil)
	parser.AddRule(ForAudience("a"))
	parser.AddRule(IdentifiedBy("b"))
	parser.AddRule(IssuedBy("c"))
	parser.AddRule(NotExpired())
	parser.AddRule(Subject("d"))
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err = parser.ParseV2Local(key, *encrypted)
	require.NoError(t, err)

	_, err = parser.ParseV2Public(secretKey.Public(), *signed)
	require.NoError(t, err)
}

func TestAllClaimsPassV3(t *testing.T) {
	token := NewToken()

	token.SetAudience("a")
	token.SetJti("b")
	token.SetIssuer("c")
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetSubject("d")

	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := NewV3SymmetricKey()

	encrypted, err := token.V3Encrypt(key, nil)
	require.NoError(t, err)

	parser := MakeParser(nil)
	parser.AddRule(ForAudience("a"))
	parser.AddRule(IdentifiedBy("b"))
	parser.AddRule(IssuedBy("c"))
	parser.AddRule(NotExpired())
	parser.AddRule(Subject("d"))
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err = parser.ParseV3Local(key, *encrypted, nil)
	require.NoError(t, err)
}

func TestAllClaimsPassV4(t *testing.T) {
	token := NewToken()

	token.SetAudience("a")
	token.SetJti("b")
	token.SetIssuer("c")
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetSubject("d")

	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := NewV4SymmetricKey()
	secretKey := NewV4AsymmetricSecretKey()

	encrypted, err := token.V4Encrypt(key, nil)
	require.NoError(t, err)

	signed, err := token.V4Sign(secretKey, nil)
	require.NoError(t, err)

	parser := MakeParser(nil)
	parser.AddRule(ForAudience("a"))
	parser.AddRule(IdentifiedBy("b"))
	parser.AddRule(IssuedBy("c"))
	parser.AddRule(NotExpired())
	parser.AddRule(Subject("d"))
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err = parser.ParseV4Local(key, *encrypted, nil)
	require.NoError(t, err)

	_, err = parser.ParseV4Public(secretKey.Public(), *signed, nil)
	require.NoError(t, err)
}

func TestFutureIat(t *testing.T) {
	token := NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now().Add(35 * time.Minute))

	key := NewV4SymmetricKey()

	encrypted, err := token.V4Encrypt(key, nil)
	require.NoError(t, err)

	parser := MakeParser(nil)
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err = parser.ParseV4Local(key, *encrypted, nil)
	require.Error(t, err)
}

func TestFutureNbf(t *testing.T) {
	token := NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now().Add(35 * time.Second))
	token.SetIssuedAt(time.Now())

	key := NewV4SymmetricKey()

	encrypted, err := token.V4Encrypt(key, nil)
	require.NoError(t, err)

	parser := MakeParser(nil)
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err = parser.ParseV4Local(key, *encrypted, nil)
	require.Error(t, err)
}

func TestPastExp(t *testing.T) {
	token := NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(29 * time.Second))
	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := NewV4SymmetricKey()

	encrypted, err := token.V4Encrypt(key, nil)
	require.NoError(t, err)

	parser := MakeParser(nil)
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err = parser.ParseV4Local(key, *encrypted, nil)
	require.Error(t, err)
}
