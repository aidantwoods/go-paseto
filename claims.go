package paseto

import (
	"crypto/subtle"
	"errors"
	"time"
)

// Rule validates a given token for certain required preconditions (defined by
// the rule itself). If validation fails a Rule MUST return an error, otherwise
// error MUST be nil.
type Rule func(token Token) error

// ForAudience requires that the given audience matches the "aud" field of the
// token.
func ForAudience(audience string) Rule {
	return func(token Token) error {
		tAud, err := token.GetAudience()
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(tAud), []byte(audience)) == 0 {
			return errors.New(
				"this token is not intended for `" +
					audience + "`. `" + tAud + "` found",
			)
		}

		return nil
	}
}

// IdentifiedBy requires that the given identifier matches the "jti" field of
// the token.
func IdentifiedBy(identifier string) Rule {
	return func(token Token) error {
		tJti, err := token.GetJti()
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(tJti), []byte(identifier)) == 0 {
			return errors.New(
				"this token is not identified by `" +
					identifier + "`. `" + tJti + "` found",
			)
		}

		return nil
	}
}

// IssuedBy requires that the given issuer matches the "iss" field of the token.
func IssuedBy(issuer string) Rule {
	return func(token Token) error {
		tIss, err := token.GetIssuer()
		if err != nil {
			return err
		}

		tIssBytes := []byte(tIss)
		issBytes := []byte(issuer)

		if subtle.ConstantTimeCompare(tIssBytes, issBytes) == 0 {
			return errors.New(
				"this token is not issued by `" +
					issuer + "`. `" + tIss + "` found",
			)
		}

		return nil
	}
}

// NotExpired requires that the token has not expired according to the time
// when this rule is created and the "exp" field of a token. Beware that this
// rule does not validate the token's "iat" or "nbf" fields, or even require
// their presence.
func NotExpired() Rule {
	return func(token Token) error {
		exp, err := token.GetExpiration()
		if err != nil {
			return err
		}

		if time.Now().After(exp) {
			return errors.New("this token has expired")
		}

		return nil
	}
}

// Subject requires that the given subject matches the "sub" field of the token.
func Subject(subject string) Rule {
	return func(token Token) error {
		tSub, err := token.GetSubject()
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(tSub), []byte(subject)) == 0 {
			return errors.New(
				"this token is not related to `" +
					subject + "`. `" + tSub + "` found",
			)
		}

		return nil
	}
}

// ValidAt requires that the token has not expired according to the given time
// and the "exp" field, and that the given time is both after the token's issued
// at time "iat", and the token's not before time "nbf".
func ValidAt(t time.Time) Rule {
	return func(token Token) error {
		iat, err := token.GetIssuedAt()
		if err != nil {
			return err
		}
		if t.Before(iat) {
			return errors.New("the ValidAt time is before this token was issued")
		}

		nbf, err := token.GetNotBefore()
		if err != nil {
			return err
		}
		if t.Before(nbf) {
			return errors.New("the ValidAt time is before this token's not before time")
		}

		exp, err := token.GetExpiration()
		if err != nil {
			return err
		}
		if t.After(exp) {
			return errors.New("the ValidAt time is after this token expires")
		}

		return nil
	}
}

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
