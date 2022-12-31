package paseto

import "fmt"

// Any cryptography issue (with the token) or formatting error.
// This does not include cryptography errors with input key material, these will
// return regular errors.
type TokenError struct {
	e error
}

func (e *TokenError) Error() string {
	return e.e.Error()
}

func (_ *TokenError) Is(e error) bool {
	_, ok := e.(*TokenError)
	return ok
}

func (e *TokenError) Unwrap() error {
	return e.e
}

func (e *TokenError) wrapWith(msg string) *TokenError {
	return &TokenError{fmt.Errorf("%s: %w", msg, e)}
}

// Any error which is the result of a rule failure (distinct from a TokenError)
// Can be used to detect cryptographically valid tokens which have failed only
// due to a rule failure: which may warrant a slightly different processing
// follow up.
type RuleError struct {
	e error
}

func (e *RuleError) Error() string {
	return e.e.Error()
}

func (_ *RuleError) Is(e error) bool {
	_, ok := e.(*RuleError)
	return ok
}

func (e *RuleError) Unwrap() error {
	return e.e
}

func errorKeyLength(expected, given int) error {
	return fmt.Errorf("key length incorrect (%d), expected %d", given, expected)
}

func errorSeedLength(expected, given int) error {
	return fmt.Errorf("seed length incorrect (%d), expected %d", given, expected)
}

func errorMessageParts(given int) error {
	return fmt.Errorf("invalid number of message parts in token (%d)", given)
}

func errorMessageHeader(expected Protocol, givenHeader string) error {
	return fmt.Errorf("message header `%s' is not valid, expected `%s'", givenHeader, expected.Header())
}

func errorMessageHeaderDecrypt(expected Protocol, givenHeader string) error {
	return fmt.Errorf("cannot decrypt message: %w", errorMessageHeader(expected, givenHeader))
}

func errorMessageHeaderVerify(expected Protocol, givenHeader string) error {
	return fmt.Errorf("cannot verify message: %w", errorMessageHeader(expected, givenHeader))
}

var unsupportedPasetoVersion = fmt.Errorf("unsupported PASETO version")
var unsupportedPasetoPurpose = fmt.Errorf("unsupported PASETO purpose")
var unsupportedPayload = fmt.Errorf("unsupported payload")

var errorPayloadShort = fmt.Errorf("payload is not long enough to be a valid PASETO message")
var errorBadSignature = fmt.Errorf("bad signature")
var errorBadMAC = fmt.Errorf("bad message authentication code")

var errorKeyInvalid = fmt.Errorf("key was not valid")

func errorDecrypt(err error) error {
	return fmt.Errorf("the message could not be decrypted: %w", err)
}
