package paseto

// Purpose represents either local or public paseto mode
type Purpose string

const (
	// Local is a paseto mode which encrypts the token
	Local Purpose = "local"
	// Public is a paseto mode which signs the token
	Public Purpose = "public"
)
