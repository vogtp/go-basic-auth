package backend

import (
	"fmt"
	"strings"
)

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
func (m InMemory) Authenticate(user string, password string, _ []string) (bool, error) {
	p, ok := m.authData[user]
	if !ok {
		return false, fmt.Errorf("Wrong user %s or password", user)
	}
	if strings.EqualFold(p, password) {
		return true, nil
	}
	return false, fmt.Errorf("Wrong user %s or password", user)
}
