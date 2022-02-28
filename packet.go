package paseto

type packet struct {
	content []byte
	footer  []byte
}

func newPacket(content []byte, footer []byte) packet {
	return packet{content, footer}
}

func (p packet) token() (*Token, error) {
	return NewTokenFromClaimsJSON(p.content, p.footer)
}
