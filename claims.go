package paseto

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// Rule validates a given token for certain required preconditions (defined by
// the rule itself). If validation fails a Rule MUST return an error, otherwise
// error MUST be nil.
type Rule[T any] func(token T) error

type TokenAudience interface {
	GetAudience() (string, error)
}

type TokenExpiration interface {
	GetExpiration() (time.Time, error)
}

type TokenIssuedAt interface {
	GetIssuedAt() (time.Time, error)
}

type TokenIssuer interface {
	GetIssuer() (string, error)
}

type TokenJti interface {
	GetJti() (string, error)
}

type TokenNotBefore interface {
	GetNotBefore() (time.Time, error)
}

type TokenSubject interface {
	GetSubject() (string, error)
}

// ForAudienceT requires that the given audience matches the audience field of the
// token.
func ForAudienceT[T TokenAudience](audience string) Rule[T] {
	return func(token T) error {
		tAud, err := token.GetAudience()
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(tAud), []byte(audience)) == 0 {
			return fmt.Errorf("this token is not intended for `%s'. `%s' found", audience, tAud)
		}

		return nil
	}
}

// ForAudience requires that the given audience matches the "aud" field of the
// token.
var ForAudience = ForAudienceT[Token]

// IdentifiedByT requires that the given identifier matches the jti field of
// the token.
func IdentifiedByT[T TokenJti](identifier string) Rule[T] {
	return func(token T) error {
		tJti, err := token.GetJti()
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(tJti), []byte(identifier)) == 0 {
			return fmt.Errorf("this token is not identified by `%s'. `%s' found", identifier, tJti)
		}

		return nil
	}
}

// IdentifiedBy requires that the given identifier matches the "jti" field of
// the token.
var IdentifiedBy = IdentifiedByT[Token]

// IssuedByT requires that the given issuer matches the issuer field of the token.
func IssuedByT[T TokenIssuer](issuer string) Rule[T] {
	return func(token T) error {
		tIss, err := token.GetIssuer()
		if err != nil {
			return err
		}

		tIssBytes := []byte(tIss)
		issBytes := []byte(issuer)

		if subtle.ConstantTimeCompare(tIssBytes, issBytes) == 0 {
			return fmt.Errorf("this token is not issued by `%s'. `%s' found", issuer, tIss)
		}

		return nil
	}
}

// IssuedBy requires that the given issuer matches the "iss" field of the token.
var IssuedBy = IssuedByT[Token]

// NotBeforeNbfT requires that the token is allowed to be used according to the time
// when this rule is checked and the not before field of a token. Beware that this
// rule does not validate the token's issued at or expiration fields, or even require
// their presence.
func NotBeforeNbfT[T TokenNotBefore]() Rule[T] {
	return func(token T) error {
		nbf, err := token.GetNotBefore()
		if err != nil {
			return err
		}

		if time.Now().Before(nbf) {
			return fmt.Errorf("this token is not valid, yet")
		}

		return nil
	}
}

// NotBeforeNbf requires that the token is allowed to be used according to the time
// when this rule is checked and the not before field of a token. Beware that this
// rule does not validate the token's issued at or expiration fields, or even require
// their presence.
var NotBeforeNbf = NotBeforeNbfT[Token]

// NotExpiredT requires that the token has not expired according to the time
// when this rule is checked and the expiration field of a token. Beware that this
// rule does not validate the token's issued at or not before fields, or even require
// their presence.
func NotExpiredT[T TokenExpiration]() Rule[T] {
	return func(token T) error {
		exp, err := token.GetExpiration()
		if err != nil {
			return err
		}

		if time.Now().After(exp) {
			return fmt.Errorf("this token has expired")
		}

		return nil
	}
}

// NotExpired requires that the token has not expired according to the time
// when this rule is checked and the expiration field of a token. Beware that this
// rule does not validate the token's issued at or not before fields, or even require
// their presence.
var NotExpired = NotExpiredT[Token]

// SubjectT requires that the given subject matches the subject field of the token.
func SubjectT[T TokenSubject](subject string) Rule[T] {
	return func(token T) error {
		tSub, err := token.GetSubject()
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(tSub), []byte(subject)) == 0 {
			return fmt.Errorf("this token is not related to `%s'. `%s' found", subject, tSub)
		}

		return nil
	}
}

// Subject requires that the given subject matches the subject field of the token.
var Subject = SubjectT[Token]

type TokenValidAt interface {
	TokenIssuedAt
	TokenNotBefore
	TokenExpiration
}

// ValidAtT requires that the token has not expired according to the given time
// and the expiration field, and that the given time is both after the token's issued
// at time, and the token's not before time.
func ValidAtT[T TokenValidAt](t time.Time) Rule[T] {
	return func(token T) error {
		iat, err := token.GetIssuedAt()
		if err != nil {
			return err
		}
		if t.Before(iat) {
			return fmt.Errorf("the ValidAt time is before this token was issued")
		}

		nbf, err := token.GetNotBefore()
		if err != nil {
			return err
		}
		if t.Before(nbf) {
			return fmt.Errorf("the ValidAt time is before this token's not before time")
		}

		exp, err := token.GetExpiration()
		if err != nil {
			return err
		}
		if t.After(exp) {
			return fmt.Errorf("the ValidAt time is after this token expires")
		}

		return nil
	}
}

// ValidAt requires that the token has not expired according to the given time
// and the expiration field, and that the given time is both after the token's issued
// at time, and the token's not before time.
var ValidAt = ValidAtT[Token]

// GetAudience returns the token's "aud" field, or error if not found or not a
// string.
func (t Token) GetAudience() (string, error) {
	return t.GetString("aud")
}

// GetExpiration returns the token's "exp" field, or error if not found or not a
// a RFC3339 compliant time.
func (t Token) GetExpiration() (time.Time, error) {
	return t.GetTime("exp")
}

// GetIssuedAt returns the token's "iat" field, or error if not found or not a
// a RFC3339 compliant time.
func (t Token) GetIssuedAt() (time.Time, error) {
	return t.GetTime("iat")
}

// GetIssuer returns the token's "iss" field, or error if not found or not a
// string.
func (t Token) GetIssuer() (string, error) {
	return t.GetString("iss")
}

// GetJti returns the token's "jti" field, or error if not found or not a
// string.
func (t Token) GetJti() (string, error) {
	return t.GetString("jti")
}

// GetNotBefore returns the token's "nbf" field, or error if not found or not a
// a RFC3339 compliant time.
func (t Token) GetNotBefore() (time.Time, error) {
	return t.GetTime("nbf")
}

// GetSubject returns the token's "sub" field, or error if not found or not a
// string.
func (t Token) GetSubject() (string, error) {
	return t.GetString("sub")
}

// SetAudience sets the token's "aud" field.
func (t *Token) SetAudience(audience string) {
	t.SetString("aud", audience)
}

// SetExpiration sets the token's "exp" field.
func (t *Token) SetExpiration(exp time.Time) {
	t.SetTime("exp", exp)
}

// SetIssuedAt sets the token's "iat" field.
func (t *Token) SetIssuedAt(iat time.Time) {
	t.SetTime("iat", iat)
}

// SetIssuer sets the token's "iss" field.
func (t *Token) SetIssuer(issuer string) {
	t.SetString("iss", issuer)
}

// SetJti sets the token's "jti" field.
func (t *Token) SetJti(identifier string) {
	t.SetString("jti", identifier)
}

// SetNotBefore sets the token's "nbf" field.
func (t *Token) SetNotBefore(nbf time.Time) {
	t.SetTime("nbf", nbf)
}

// SetSubject sets the token's "sub" field.
func (t *Token) SetSubject(subject string) {
	t.SetString("sub", subject)
}
