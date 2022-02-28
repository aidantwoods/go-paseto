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
		var tAud *string
		var err error

		if tAud, err = token.GetAudience(); err != nil {
			return err
		}

		tAudBytes := []byte(*tAud)
		audBytes := []byte(audience)

		if subtle.ConstantTimeCompare(tAudBytes, audBytes) == 1 {
			return nil
		}

		return errors.New(
			"this token is not intended for `" +
				audience + "`. `" + *tAud + "` found",
		)
	}
}

// IdentifiedBy requires that the given identifier matches the "jti" field of
// the token.
func IdentifiedBy(identifier string) Rule {
	return func(token Token) error {
		var tJti *string
		var err error

		if tJti, err = token.GetJti(); err != nil {
			return err
		}

		tJtiBytes := []byte(*tJti)
		jtiBytes := []byte(identifier)

		if subtle.ConstantTimeCompare(tJtiBytes, jtiBytes) == 0 {
			return errors.New(
				"this token is not identified by `" +
					identifier + "`. `" + *tJti + "` found",
			)
		}

		return nil
	}
}

// IssuedBy requires that the given issuer matches the "iss" field of the token.
func IssuedBy(issuer string) Rule {
	return func(token Token) error {
		var tIss *string
		var err error

		if tIss, err = token.GetIssuer(); err != nil {
			return err
		}

		tIssBytes := []byte(*tIss)
		issBytes := []byte(issuer)

		if subtle.ConstantTimeCompare(tIssBytes, issBytes) == 0 {
			return errors.New(
				"this token is not issued by `" +
					issuer + "`. `" + *tIss + "` found",
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
		var exp *time.Time
		var err error

		if exp, err = token.GetExpiration(); err != nil {
			return err
		}

		now := time.Now()

		if now.After(*exp) {
			return errors.New("this token has expired")
		}

		return nil
	}
}

// Subject requires that the given subject matches the "sub" field of the token.
func Subject(subject string) Rule {
	return func(token Token) error {
		var tSub *string
		var err error

		if tSub, err = token.GetSubject(); err != nil {
			return err
		}

		tSubBytes := []byte(*tSub)
		subBytes := []byte(subject)

		if subtle.ConstantTimeCompare(tSubBytes, subBytes) == 1 {
			return nil
		}

		return errors.New("this token is not related to `" + subject + "`. `" + *tSub + "` found")
	}
}

// ValidAt requires that the token has not expired according to the given time
// and the "exp" field, and that the given time is both after the token's issued
// at time "iat", and the token's not before time "nbf".
func ValidAt(t time.Time) Rule {
	return func(token Token) error {
		var err error

		var iat *time.Time
		if iat, err = token.GetIssuedAt(); err != nil {
			return err
		}
		if t.Before(*iat) {
			return errors.New("the ValidAt time is before this token was issued")
		}

		var nbf *time.Time
		if nbf, err = token.GetNotBefore(); err != nil {
			return err
		}
		if t.Before(*nbf) {
			return errors.New("the ValidAt time is before this token's not before time")
		}

		var exp *time.Time
		if exp, err = token.GetExpiration(); err != nil {
			return err
		}
		if t.After(*exp) {
			return errors.New("the ValidAt time is after this token expires")
		}

		return nil
	}
}

// GetAudience returns the token's "aud" field, or error if not found or not a
// string.
func (t Token) GetAudience() (*string, error) {
	return t.GetString("aud")
}

// GetExpiration returns the token's "exp" field, or error if not found or not a
// a RFC3339 compliant time.
func (t Token) GetExpiration() (*time.Time, error) {
	var expStr string

	if err := t.Get("exp", &expStr); err != nil {
		return nil, err
	}

	exp, err := time.Parse(time.RFC3339, expStr)

	return &exp, err
}

// GetIssuedAt returns the token's "iat" field, or error if not found or not a
// a RFC3339 compliant time.
func (t Token) GetIssuedAt() (*time.Time, error) {
	var iatStr string

	if err := t.Get("iat", &iatStr); err != nil {
		return nil, err
	}

	iat, err := time.Parse(time.RFC3339, iatStr)

	return &iat, err
}

// GetIssuer returns the token's "iss" field, or error if not found or not a
// string.
func (t Token) GetIssuer() (*string, error) {
	return t.GetString("iss")
}

// GetJti returns the token's "jti" field, or error if not found or not a
// string.
func (t Token) GetJti() (*string, error) {
	return t.GetString("jti")
}

// GetNotBefore returns the token's "nbf" field, or error if not found or not a
// a RFC3339 compliant time.
func (t Token) GetNotBefore() (*time.Time, error) {
	var nbfStr *string

	if err := t.Get("nbf", &nbfStr); err != nil {
		return nil, err
	}

	nbf, err := time.Parse(time.RFC3339, *nbfStr)

	return &nbf, err
}

// GetSubject returns the token's "sub" field, or error if not found or not a
// string.
func (t Token) GetSubject() (*string, error) {
	return t.GetString("sub")
}

// SetAudience sets the token's "aud" field.
func (t *Token) SetAudience(audience string) {
	t.SetString("aud", audience)
}

// SetExpiration sets the token's "exp" field.
func (t *Token) SetExpiration(exp time.Time) {
	t.SetString("exp", exp.Format(time.RFC3339))
}

// SetIssuedAt sets the token's "iat" field.
func (t *Token) SetIssuedAt(iat time.Time) {
	t.SetString("iat", iat.Format(time.RFC3339))
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
	t.SetString("nbf", nbf.Format(time.RFC3339))
}

// SetSubject sets the token's "sub" field.
func (t *Token) SetSubject(subject string) {
	t.SetString("sub", subject)
}
