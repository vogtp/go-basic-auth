package auth

import (
	"crypto/rand"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/vogtp/go-basic-auth/backend"
)

// Defines what a backend must be able to do
type AuthBackend interface {
	Authenticate(user string, password string, authGroups []string) (bool, error)
}

// Basic HTTP Auth against a AuthBackend
type basicAuth struct {
	authBackend []AuthBackend
	authGroups  []string
	cookieStore *sessions.CookieStore
	noAuthMsg   string
	dbg         bool
}

type Option func(*basicAuth)

//Ad a authBackend to Authentication
func Backend(b AuthBackend) Option {
	return func(auth *basicAuth) {
		auth.authBackend = append(auth.authBackend, b)
	}
}

// Convience function to add a LDAP server
func AdLdap(server, baseDN, domainName string) Option {
	return Backend(backend.NewAdLdap(server, baseDN, domainName))
}

// Convience function to add a in memory authentication
func Memory(data map[string]string) Option {
	return Backend(backend.NewMemoryBackend(data))
}

// Groups that authorised the user
func AuthGroups(authGroups ...string) Option {
	return func(auth *basicAuth) {
		auth.authGroups = append(auth.authGroups, authGroups...)
	}
}

// Custom message
func NoAuthMsg(msg string) Option {
	return func(auth *basicAuth) {
		auth.noAuthMsg = msg
	}
}

func Debug() Option {
	return func(auth *basicAuth) {
		auth.dbg = true
	}
}

// creates a new BasicAuth authenticator with sever and base DN
// user must be in one of the authGroups to be successfully authenticated
func New(opts ...Option) *basicAuth {
	ba := &basicAuth{noAuthMsg: "Unauthorized"}
	for _, opt := range opts {
		opt(ba)
	}
	if ba.authBackend == nil {
		log.Panic("No LDAP server is given")
	}

	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	ba.cookieStore = sessions.NewCookieStore(generateKey(32))
	return ba
}

func (ba basicAuth) getAuth(_ http.ResponseWriter, r *http.Request) bool {
	ba.debug("getting basic auth")
	upn, pw, ok := r.BasicAuth()
	if !ok {
		ba.debug("basic auth not OK: %s %v", upn, ok)
		return false
	}
	ba.debug("searching in backends")
	for _, b := range ba.authBackend {
		authOk, err := b.Authenticate(upn, pw, ba.authGroups)
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
		log.Fatalf("cannot generate cookie key: %v", err)
	}
	ioutil.WriteFile(keyFile, key, fs.ModeExclusive)
	return key
}

func (ba basicAuth) debug(format string, v ...interface{}) {
	if !ba.dbg {
		return
	}
	log.Printf("BasicAuth Debug: "+format, v...)
}
