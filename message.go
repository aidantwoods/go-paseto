package paseto

type Message struct {
	Protocol Protocol
	Payload  Payload
	Footer   []byte
}

func (m Message) Header() string {
	return m.Protocol.Header()
}
