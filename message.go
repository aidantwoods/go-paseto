package paseto

type Message struct {
	Version Version
	Purpose Purpose
	Payload Payload
	Footer  []byte
}
