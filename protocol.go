package paseto

import (
	"fmt"
)

type Protocol struct {
	Version Version
	Purpose Purpose
}

func (p Protocol) Header() string {
	return fmt.Sprintf("%s.%s", p.Version, p.Purpose)
}
