package paseto

import "fmt"

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

func errorDecrypt(err error) error {
	return fmt.Errorf("the message could not be decrypted: %w", err)
}
