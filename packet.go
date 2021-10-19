package paseto

type Packet struct {
	Content []byte
	Footer  []byte
}

func NewPacket(content []byte, footer []byte) Packet {
	return Packet{content, footer}
}
