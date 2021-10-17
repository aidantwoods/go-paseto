package paseto

type Message struct {
	Payload Payload
	Footer  []byte
}
