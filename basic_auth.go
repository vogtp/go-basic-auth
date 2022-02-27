package auth

import (
	"crypto/rand"
	"io/fs"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/vogtp/go-basic-auth/backend"
	"github.com/vogtp/go-hcl"
)

var log = hcl.LibraryLogger("basic-auth")

// Backender defines the interface to the auth backends
type Backender interface {
	Authenticate(user string, password string, authGroups []string) (bool, error)
}

// Backend provides basic HTTP Auth against a AuthBackend
type Backend struct {
	authBackend []Backender
	authGroups  []string
	cookieStore *sessions.CookieStore
	noAuthMsg   string
	dbg         bool
}

// Option is a func to configure basic auth
type Option func(*Backend)

// WithBackend sets a authentication backend
func WithBackend(b Backender) Option {
	return func(auth *Backend) {
		auth.authBackend = append(auth.authBackend, b)
	}
}

// WithLdap is a convience function to add a LDAP server
func WithLdap(server, baseDN, domainName string) Option {
	return WithBackend(backend.NewLdap(server, 389, baseDN, domainName))
}

// WithInMemory is a convience function to add a in memory authentication
func WithInMemory(data map[string]string) Option {
	return WithBackend(backend.NewInMemory(data))
}

// WithGroup sets groups that the user has to be in to be authorised
func WithGroup(authGroups ...string) Option {
	return func(auth *Backend) {
		auth.authGroups = append(auth.authGroups, authGroups...)
	}
}

// WithFailMsg sets a custom message on auth failure
func WithFailMsg(msg string) Option {
	return func(auth *Backend) {
		auth.noAuthMsg = msg
	}
}

// Debug forces for log output
func Debug() Option {
	return func(auth *Backend) {
		auth.dbg = true
	}
}

// New creates a new BasicAuth authenticator with sever and base DN
// user must be in one of the authGroups to be successfully authenticated
func New(opts ...Option) *Backend {
	b := &Backend{noAuthMsg: "Unauthorized"}
	for _, opt := range opts {
		opt(b)
	}
	if b.authBackend == nil {
		panic("No backend is given")
	}

	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	b.cookieStore = sessions.NewCookieStore(generateKey(32))
	return b
}

func (b Backend) getAuth(_ http.ResponseWriter, r *http.Request) bool {
	b.debug("getting basic auth")
	upn, pw, ok := r.BasicAuth()
	if !ok {
		b.debug("basic auth not OK: %s %v", upn, ok)
		return false
	}
	b.debug("searching in backends")
	for _, auth := range b.authBackend {
		authOk, err := auth.Authenticate(upn, pw, b.authGroups)
		if err != nil {
			log.Printf("auth backend error: %v", err)
		}
		if authOk {
			return true
		}
	}
	return false
}

var keyFile = "session.key"

func generateKey(keyLen int) []byte {
	k, err := ioutil.ReadFile(keyFile)
	if err == nil && len(k) == keyLen {
		return k
	}
	log.Print("Generating a new session key")
	key := make([]byte, keyLen)
	_, err = rand.Read(key)
	if err != nil {
		log.Error("cannot generate cookie key: %v", err)
		panic(err)
	}
	ioutil.WriteFile(keyFile, key, fs.ModeExclusive)
	return key
}

func (b Backend) debug(format string, v ...interface{}) {
	if !b.dbg || !log.IsDebug() {
		return
	}
	log.Debugf(format, v...)
}
