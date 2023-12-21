package paseto

import (
	"time"

	t "aidanwoods.dev/go-result"
)

type TokenDecoder[T any] func(ClaimsAndFooter) (*T, error)

// Parser is used to verify or decrypt a token, and can be provided with
// a set of rules.
type Parser[T any] struct {
	rules  []Rule[T]
	decode TokenDecoder[T]
}

// NewParser returns a parser with NotExpired rule preloaded.
func NewParser() Parser[Token] {
	return Parser[Token]{
		rules:  []Rule[Token]{NotExpired()},
		decode: StdDecoder,
	}
}

// NewParser returns a parser with NotExpired rule preloaded.
func NewParserT[T TokenExpiration](decoder TokenDecoder[T]) Parser[T] {
	return Parser[T]{
		rules:  []Rule[T]{NotExpiredT[T]()},
		decode: decoder,
	}
}

// NewParserWithoutExpiryCheck returns a parser with no currently set rules.
func NewParserWithoutExpiryCheck() Parser[Token] {
	return Parser[Token]{
		rules:  []Rule[Token]{},
		decode: StdDecoder,
	}
}

// NewParserForValidNow returns a parser that will require parsed tokens to be
// valid "now".
func NewParserForValidNow() Parser[Token] {
	return Parser[Token]{
		rules:  []Rule[Token]{ValidAt(time.Now())},
		decode: StdDecoder,
	}
}

// MakeParser allows a parser to be constructed with a specified set of rules.
func MakeParser(rules []Rule[Token]) Parser[Token] {
	return Parser[Token]{
		rules:  rules,
		decode: StdDecoder,
	}
}

// MakeParser allows a parser to be constructed with a specified set of rules.
func MakeParserT[T any](decoder TokenDecoder[T], rules []Rule[T]) Parser[T] {
	return Parser[T]{
		rules:  rules,
		decode: decoder,
	}
}

// ParseV2Local will parse and decrypt a v2 local paseto and validate against
// any parser rules. Error if parsing, decryption, or any rule fails.
func (p Parser[T]) ParseV2Local(key V2SymmetricKey, tainted string) (*T, error) {
	return t.Chain3[T, T, ClaimsAndFooter](
		newMessage(V2Local, tainted)).
		AndThen(func(m message) t.Result[ClaimsAndFooter] { return m.v2Decrypt(key) }).
		AndThen(func(caf ClaimsAndFooter) t.Result[T] { return t.NewPtrResult(p.decode(caf)) }).
		AndThen(p.validate).
		Results()
}

// ParseV2Public will parse and verify a v2 public paseto and validate against
// any parser rules. Error if parsing, verification, or any rule fails.
func (p Parser[T]) ParseV2Public(key V2AsymmetricPublicKey, tainted string) (*T, error) {
	return t.Chain3[T, T, ClaimsAndFooter](
		newMessage(V2Public, tainted)).
		AndThen(func(m message) t.Result[ClaimsAndFooter] { return m.v2Verify(key) }).
		AndThen(func(caf ClaimsAndFooter) t.Result[T] { return t.NewPtrResult(p.decode(caf)) }).
		AndThen(p.validate).
		Results()
}

// ParseV3Local will parse and decrypt a v3 local paseto and validate against
// any parser rules. Error if parsing, decryption, or any rule fails.
func (p Parser[T]) ParseV3Local(key V3SymmetricKey, tainted string, implicit []byte) (*T, error) {
	return t.Chain3[T, T, ClaimsAndFooter](
		newMessage(V3Local, tainted)).
		AndThen(func(m message) t.Result[ClaimsAndFooter] { return m.v3Decrypt(key, implicit) }).
		AndThen(func(caf ClaimsAndFooter) t.Result[T] { return t.NewPtrResult(p.decode(caf)) }).
		AndThen(p.validate).
		Results()
}

// ParseV3Public will parse and verify a v3 public paseto and validate against
// any parser rules. Error if parsing, verification, or any rule fails.
func (p Parser[T]) ParseV3Public(key V3AsymmetricPublicKey, tainted string, implicit []byte) (*T, error) {
	return t.Chain3[T, T, ClaimsAndFooter](
		newMessage(V3Public, tainted)).
		AndThen(func(m message) t.Result[ClaimsAndFooter] { return m.v3Verify(key, implicit) }).
		AndThen(func(caf ClaimsAndFooter) t.Result[T] { return t.NewPtrResult(p.decode(caf)) }).
		AndThen(p.validate).
		Results()
}

// ParseV4Local will parse and decrypt a v4 local paseto and validate against
// any parser rules. Error if parsing, decryption, or any rule fails.
func (p Parser[T]) ParseV4Local(key V4SymmetricKey, tainted string, implicit []byte) (*T, error) {
	return t.Chain3[T, T, ClaimsAndFooter](
		newMessage(V4Local, tainted)).
		AndThen(func(m message) t.Result[ClaimsAndFooter] { return m.v4Decrypt(key, implicit) }).
		AndThen(func(caf ClaimsAndFooter) t.Result[T] { return t.NewPtrResult(p.decode(caf)) }).
		AndThen(p.validate).
		Results()
}

// ParseV4Public will parse and verify a v4 public paseto and validate against
// any parser rules. Error if parsing, verification, or any rule fails.
func (p Parser[T]) ParseV4Public(key V4AsymmetricPublicKey, tainted string, implicit []byte) (*T, error) {
	return t.Chain3[T, T, ClaimsAndFooter](
		newMessage(V4Public, tainted)).
		AndThen(func(m message) t.Result[ClaimsAndFooter] { return m.v4Verify(key, implicit) }).
		AndThen(func(caf ClaimsAndFooter) t.Result[T] { return t.NewPtrResult(p.decode(caf)) }).
		AndThen(p.validate).
		Results()
}

// UnsafeParseFooter returns the footer of a Paseto message. Beware that this
// footer is not cryptographically verified at this stage, nor are any claims
// validated.
func (p Parser[T]) UnsafeParseFooter(protocol Protocol, tainted string) ([]byte, error) {
	return t.Chain[[]byte](
		newMessage(protocol, tainted)).
		Map(message.unsafeFooter).
		ResultsMappingEmpty()
}

// SetRules will overwrite any currently set rules with those specified.
func (p *Parser[T]) SetRules(rules []Rule[T]) {
	p.rules = rules
}

// AddRule will add the given rule(s) to any already specified.
func (p *Parser[T]) AddRule(rule ...Rule[T]) {
	p.rules = append(p.rules, rule...)
}

func (p Parser[T]) validate(token T) t.Result[T] {
	for _, rule := range p.rules {
		if err := rule(token); err != nil {
			return t.Err[T](newRuleError(err))
		}
	}

	return t.Ok(token)
}
