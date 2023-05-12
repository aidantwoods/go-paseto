// A Go implementation of PASETO.
// Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the many design deficits
// that plague the JOSE standards.
package paseto

import (
	"fmt"

	t "aidanwoods.dev/go-result"
)

// Purpose represents either local or public paseto mode
type Purpose string

const (
	// Local is a paseto mode which encrypts the token
	Local Purpose = "local"
	// Public is a paseto mode which signs the token
	Public Purpose = "public"
)

// Version represents a valid paseto version
type Version string

const (
	// Version2 corresponds to paseto v2 tokens
	Version2 Version = "v2"
	// Version3 corresponds to paseto v3 tokens
	Version3 Version = "v3"
	// Version4 corresponds to paseto v4 tokens
	Version4 Version = "v4"
)

var (
	// V2Local represents a v2 protocol in local mode
	V2Local = Protocol{Version2, Local}
	// V2Public represents a v2 protocol in public mode
	V2Public = Protocol{Version2, Public}
	// V3Local represents a v3 protocol in local mode
	V3Local = Protocol{Version3, Local}
	// V3Public represents a v3 protocol in public mode
	V3Public = Protocol{Version3, Public}
	// V4Local represents a v4 protocol in local mode
	V4Local = Protocol{Version4, Local}
	// V4Public represents a v4 protocol in public mode
	V4Public = Protocol{Version4, Public}
)

// Protocol represents a set of cryptographic operations for paseto
type Protocol struct {
	version Version
	purpose Purpose
}

// NewProtocol creates a new protocol with a given version and purpose (both
// must be valid)
func NewProtocol(version Version, purpose Purpose) (Protocol, error) {
	switch version {
	default:
		return Protocol{}, unsupportedPasetoVersion
	case Version2:
		switch purpose {
		default:
			return Protocol{}, unsupportedPasetoPurpose
		case Local:
			return V2Local, nil
		case Public:
			return V2Public, nil
		}
	case Version3:
		switch purpose {
		default:
			return Protocol{}, unsupportedPasetoPurpose
		case Local:
			return V3Local, nil
		case Public:
			return V2Public, nil
		}
	case Version4:
		switch purpose {
		default:
			return Protocol{}, unsupportedPasetoPurpose
		case Local:
			return V4Local, nil
		case Public:
			return V4Public, nil
		}
	}
}

// Header computes the header for the protocol
func (p Protocol) Header() string {
	return fmt.Sprintf("%s.%s.", p.version, p.purpose)
}

// Version returns the version for a protocol
func (p Protocol) Version() Version {
	return p.version
}

// Purpose returns the purpose for a protocol
func (p Protocol) Purpose() Purpose {
	return p.purpose
}

func upcastPayload[P payload](p P) payload {
	return p
}

func (p Protocol) newPayload(bytes []byte) t.Result[payload] {
	switch p.version {
	default:
		return t.Err[payload](unsupportedPasetoVersion)
	case Version2:
		switch p.purpose {
		default:
			return t.Err[payload](unsupportedPasetoPurpose)
		case Local:
			return t.Map(newV2LocalPayload(bytes), upcastPayload[v2LocalPayload])
		case Public:
			return t.Map(newV2PublicPayload(bytes), upcastPayload[v2PublicPayload])
		}
	case Version3:
		switch p.purpose {
		default:
			return t.Err[payload](unsupportedPasetoPurpose)
		case Local:
			return t.Map(newV3LocalPayload(bytes), upcastPayload[v3LocalPayload])
		case Public:
			return t.Map(newV3PublicPayload(bytes), upcastPayload[v3PublicPayload])
		}
	case Version4:
		switch p.purpose {
		default:
			return t.Err[payload](unsupportedPasetoPurpose)
		case Local:
			return t.Map(newV4LocalPayload(bytes), upcastPayload[v4LocalPayload])
		case Public:
			return t.Map(newV4PublicPayload(bytes), upcastPayload[v4PublicPayload])
		}
	}
}

type payload interface {
	bytes() []byte
}

func protocolForPayload(payload payload) t.Result[Protocol] {
	switch payload.(type) {
	default:
		return t.Err[Protocol](unsupportedPayload)
	case v2LocalPayload:
		return t.Ok(V2Local)
	case v2PublicPayload:
		return t.Ok(V2Public)
	case v3LocalPayload:
		return t.Ok(V3Local)
	case v3PublicPayload:
		return t.Ok(V3Public)
	case v4LocalPayload:
		return t.Ok(V4Local)
	case v4PublicPayload:
		return t.Ok(V4Public)
	}
}

type ClaimsAndFooter struct {
	Claims []byte
	Footer []byte
}

func NewClaimsAndFooter(claims []byte, footer []byte) ClaimsAndFooter {
	return ClaimsAndFooter{
		Claims: claims,
		Footer: footer,
	}
}
