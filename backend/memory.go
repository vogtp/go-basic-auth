package backend

import "strings"

// a memoryBackend uses user, password from a map and ignores groups
type memoryBackend struct {
	authData map[string]string
}

// creates a new in memory backen
// a memoryBackend uses user, password from a map and ignores groups
func NewMemoryBackend(data map[string]string) *memoryBackend {
	return &memoryBackend{
		authData: data,
	}
}

func (b memoryBackend) Authenticate(user string, password string, _ []string) (bool, error) {
	p, ok := b.authData[user]
	if !ok {
		return false, nil
	}
	return strings.EqualFold(p, password), nil
}
