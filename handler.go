// Package auth provides authentication based on http basic auth
// differen backend can be used
package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Authenticator provides handler funcs
type Authenticator interface {
	Handler(http.HandlerFunc) http.HandlerFunc
	GinHandler() gin.HandlerFunc
}

// BasicAuth creates a new AD BasicAuth authenticator with sever and base DN
// user must be in one of the authGroups to be successfully authenticated
func BasicAuth(opts ...Option) Authenticator {
	return New(opts...)
}

const (
	cookieName    = "basicAuth"
	cookieKeyAuth = "authenticated"
)

// Handler is a handler func that does the authentification for stdlib http
func (ba Backend) Handler(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ba.debug("checking auth")
		session, err := ba.cookieStore.Get(r, cookieName)
		if err != nil {
			ba.debug("error getting cookie %s: %v", cookieName, err)
		}
		if auth, ok := session.Values[cookieKeyAuth].(bool); !ok || !auth {
			ba.debug("no auth session %v calling ad ldap", auth)
			adAuth := ba.getAuth(w, r)
			if !adAuth {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(w, ba.noAuthMsg, http.StatusUnauthorized)
				return
			}
			session.Values[cookieKeyAuth] = true
			session.Save(r, w)
		}
		ba.debug("authenticated calling next handler")
		next.ServeHTTP(w, r)

	})
}

// GinHandler is a handler func that does the authentification for GIN
func (ba Backend) GinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ba.debug("checking auth")
		r := c.Request
		w := c.Writer
		session, err := ba.cookieStore.Get(r, cookieName)
		if err != nil {
			ba.debug("error getting cookie %s: %v", cookieName, err)
		}
		if auth, ok := session.Values[cookieKeyAuth].(bool); !ok || !auth {
			ba.debug("no auth session %v calling ad ldap", auth)
			adAuth := ba.getAuth(w, r)
			if !adAuth {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ba.noAuthMsg})
				return
			}
			session.Values[cookieKeyAuth] = true
			session.Save(r, w)
		}
		ba.debug("authenticated calling next handler")
		// Continue down the chain to handler etc
		c.Next()
	}
}
