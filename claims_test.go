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

	encrypted := token.V2Encrypt(key)

	signed := token.V2Sign(secretKey)

	parser := NewParser()
	parser.AddRule(ForAudience("a"))
	parser.AddRule(IdentifiedBy("b"))
	parser.AddRule(IssuedBy("c"))
	parser.AddRule(NotExpired())
	parser.AddRule(Subject("d"))
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV2Local(key, encrypted)
	require.NoError(t, err)

	_, err = parser.ParseV2Public(secretKey.Public(), signed)
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

	encrypted := token.V3Encrypt(key, nil)

	parser := NewParser()
	parser.AddRule(ForAudience("a"))
	parser.AddRule(IdentifiedBy("b"))
	parser.AddRule(IssuedBy("c"))
	parser.AddRule(NotExpired())
	parser.AddRule(Subject("d"))
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV3Local(key, encrypted, nil)
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

	encrypted := token.V4Encrypt(key, nil)

	signed := token.V4Sign(secretKey, nil)

	parser := NewParser()
	parser.AddRule(ForAudience("a"))
	parser.AddRule(IdentifiedBy("b"))
	parser.AddRule(IssuedBy("c"))
	parser.AddRule(NotExpired())
	parser.AddRule(Subject("d"))
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.NoError(t, err)

	_, err = parser.ParseV4Public(secretKey.Public(), signed, nil)
	require.NoError(t, err)
}

func TestFutureIat(t *testing.T) {
	token := NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now().Add(35 * time.Second))

	key := NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := NewParser()
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.Error(t, err)
}

func TestFutureNbf(t *testing.T) {
	token := NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now().Add(35 * time.Second))
	token.SetIssuedAt(time.Now())

	key := NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := NewParser()
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.Error(t, err)
}

func TestPastExp(t *testing.T) {
	token := NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(29 * time.Second))
	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := NewParser()
	parser.AddRule(ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.Error(t, err)
}

func TestReadMeExample(t *testing.T) {
	token := NewToken()

	token.SetAudience("audience")
	token.SetJti("identifier")
	token.SetIssuer("issuer")
	token.SetSubject("subject")

	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now())
	token.SetIssuedAt(time.Now())

	secretKeyHex := "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	secretKey, _ := NewV4AsymmetricSecretKeyFromHex(secretKeyHex)

	signed := token.V4Sign(secretKey, nil)

	parser := NewParser()
	parser.AddRule(ForAudience("audience"))
	parser.AddRule(IdentifiedBy("identifier"))
	parser.AddRule(IssuedBy("issuer"))
	parser.AddRule(Subject("subject"))
	parser.AddRule(NotExpired())
	parser.AddRule(ValidAt(time.Now()))

	publicKeyHex := "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	publicKey, _ := NewV4AsymmetricPublicKeyFromHex(publicKeyHex)

	parsedToken, err := parser.ParseV4Public(publicKey, signed, nil)
	require.NoError(t, err)
	require.Equal(t, token.ClaimsJSON(), parsedToken.ClaimsJSON())
}
