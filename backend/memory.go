package backend

import "strings"

// InMemory is a authentication backend
// that uses a user password map
// it does not use groups
type InMemory struct {
	authData map[string]string
}

// NewInMemory creates a new in memory backen
// a memoryBackend uses user, password from a map and ignores groups
func NewInMemory(data map[string]string) *InMemory {
	return &InMemory{
		authData: data,
	}
}

// Authenticate does the authentication
func (b InMemory) Authenticate(user string, password string, _ []string) (bool, error) {
	p, ok := b.authData[user]
	if !ok {
		return false, nil
	}
	return strings.EqualFold(p, password), nil
}
