package paseto

type Packet struct {
	Content []byte
	Footer  []byte
}

func NewPacket(content []byte, footer []byte) Packet {
	return Packet{content, footer}
}

func (p Packet) token() (*Token, error) {
	return NewTokenFromClaimsJson(p.Content, p.Footer)
}
