package paseto_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

func TestAllClaimsPassV2(t *testing.T) {
	token := paseto.NewToken()

	token.SetAudience("a")
	token.SetJti("b")
	token.SetIssuer("c")
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetSubject("d")

	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := paseto.NewV2SymmetricKey()
	secretKey := paseto.NewV2AsymmetricSecretKey()

	encrypted := token.V2Encrypt(key)

	signed := token.V2Sign(secretKey)

	parser := paseto.NewParser()
	parser.AddRule(paseto.ForAudience("a"))
	parser.AddRule(paseto.IdentifiedBy("b"))
	parser.AddRule(paseto.IssuedBy("c"))
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.Subject("d"))
	parser.AddRule(paseto.ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV2Local(key, encrypted)
	require.NoError(t, err)

	_, err = parser.ParseV2Public(secretKey.Public(), signed)
	require.NoError(t, err)
}

func TestAllClaimsPassV3(t *testing.T) {
	token := paseto.NewToken()

	token.SetAudience("a")
	token.SetJti("b")
	token.SetIssuer("c")
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetSubject("d")

	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := paseto.NewV3SymmetricKey()
	secretKey := paseto.NewV3AsymmetricSecretKey()

	encrypted := token.V3Encrypt(key, nil)

	signed := token.V3Sign(secretKey, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.ForAudience("a"))
	parser.AddRule(paseto.IdentifiedBy("b"))
	parser.AddRule(paseto.IssuedBy("c"))
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.Subject("d"))
	parser.AddRule(paseto.ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV3Local(key, encrypted, nil)
	require.NoError(t, err)

	_, err = parser.ParseV3Public(secretKey.Public(), signed, nil)
	require.NoError(t, err)
}

func TestAllClaimsPassV4(t *testing.T) {
	token := paseto.NewToken()

	token.SetAudience("a")
	token.SetJti("b")
	token.SetIssuer("c")
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetSubject("d")

	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := paseto.NewV4SymmetricKey()
	secretKey := paseto.NewV4AsymmetricSecretKey()

	encrypted := token.V4Encrypt(key, nil)

	signed := token.V4Sign(secretKey, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.ForAudience("a"))
	parser.AddRule(paseto.IdentifiedBy("b"))
	parser.AddRule(paseto.IssuedBy("c"))
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.Subject("d"))
	parser.AddRule(paseto.ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.NoError(t, err)

	_, err = parser.ParseV4Public(secretKey.Public(), signed, nil)
	require.NoError(t, err)
}

type CustomToken struct {
	A      string
	B      string
	C      time.Time
	D      int
	Footer string `json:"-"`
}

func (t CustomToken) GetAudience() (string, error) {
	return t.A, nil
}

func (t CustomToken) GetSubject() (string, error) {
	return t.B, nil
}

func (t CustomToken) GetExpiration() (time.Time, error) {
	return t.C, nil
}

func DLessThan(x int) func(t CustomToken) error {
	return func(t CustomToken) error {
		if t.D >= x {
			return fmt.Errorf("D too large")
		}

		return nil
	}
}

func CustomTokenFromClaimsAndFooter(caf paseto.ClaimsAndFooter) (*CustomToken, error) {
	token := new(CustomToken)

	if err := json.Unmarshal(caf.Claims, token); err != nil {
		return nil, err
	}

	token.Footer = string(caf.Footer)

	return token, nil
}

func ClaimsAndFooterFromCustomToken(token CustomToken) paseto.ClaimsAndFooter {
	claims, err := json.Marshal(token)
	if err != nil {
		panic("cannot serialise")
	}

	return paseto.NewClaimsAndFooter(claims, []byte(token.Footer))
}

func TestAllClaimsPassStruct(t *testing.T) {
	token := CustomToken{
		A:      "audience",
		B:      "subject",
		C:      time.Now().Add(time.Minute),
		D:      6,
		Footer: "footer",
	}

	key := paseto.NewV4SymmetricKey()
	secretKey := paseto.NewV4AsymmetricSecretKey()

	encoder := paseto.NewEncoder(ClaimsAndFooterFromCustomToken)

	encrypted := encoder.V4Encrypt(key, token, nil)

	signed := encoder.V4Sign(secretKey, token, nil)

	parser := paseto.NewParserT(CustomTokenFromClaimsAndFooter)
	parser.AddRule(paseto.ForAudienceT[CustomToken]("audience"))
	parser.AddRule(paseto.SubjectT[CustomToken]("subject"))
	parser.AddRule(paseto.NotExpiredT[CustomToken]())
	parser.AddRule(DLessThan(10))

	t1, err := parser.ParseV4Local(key, encrypted, nil)
	require.NoError(t, err)
	require.Equal(t, token.Footer, t1.Footer)

	_, err = parser.ParseV4Public(secretKey.Public(), signed, nil)
	require.NoError(t, err)
}

func TestFutureIat(t *testing.T) {
	token := paseto.NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now().Add(35 * time.Second))

	key := paseto.NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})
}

func TestFutureNbf(t *testing.T) {
	token := paseto.NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now().Add(35 * time.Second))
	token.SetIssuedAt(time.Now())

	key := paseto.NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})
}

func TestFutureNbfNotBeforeNbfRule(t *testing.T) {
	token := paseto.NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now())
	token.SetIssuedAt(time.Now().Add(-2 * time.Second))

	key := paseto.NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.NotBeforeNbf())

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.NoError(t, err)
}

func TestFutureNbfNotBeforeNbfRuleError(t *testing.T) {
	token := paseto.NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now().Add(35 * time.Second))
	token.SetIssuedAt(time.Now())

	key := paseto.NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.NotBeforeNbf())

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})
}

func TestPastExp(t *testing.T) {
	token := paseto.NewToken()

	// simulated check will be 30 seconds from now
	token.SetExpiration(time.Now().Add(29 * time.Second))
	token.SetNotBefore(time.Now().Add(25 * time.Second))
	token.SetIssuedAt(time.Now())

	key := paseto.NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now().Add(30 * time.Second)))

	_, err := parser.ParseV4Local(key, encrypted, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})
}

func TestReadMeExample(t *testing.T) {
	token := paseto.NewToken()

	token.SetAudience("audience")
	token.SetJti("identifier")
	token.SetIssuer("issuer")
	token.SetSubject("subject")

	token.SetExpiration(time.Now().Add(time.Minute))
	token.SetNotBefore(time.Now())
	token.SetIssuedAt(time.Now())

	secretKeyHex := "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	secretKey, _ := paseto.NewV4AsymmetricSecretKeyFromHex(secretKeyHex)

	signed := token.V4Sign(secretKey, nil)

	parser := paseto.NewParser()
	parser.AddRule(paseto.ForAudience("audience"))
	parser.AddRule(paseto.IdentifiedBy("identifier"))
	parser.AddRule(paseto.IssuedBy("issuer"))
	parser.AddRule(paseto.Subject("subject"))
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	publicKeyHex := "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	publicKey, _ := paseto.NewV4AsymmetricPublicKeyFromHex(publicKeyHex)

	parsedToken, err := parser.ParseV4Public(publicKey, signed, nil)
	require.NoError(t, err)
	require.Equal(t, token.ClaimsJSON(), parsedToken.ClaimsJSON())
}
