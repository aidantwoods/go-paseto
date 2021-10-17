package paseto

type Payload interface {
	encoded() []string
}
