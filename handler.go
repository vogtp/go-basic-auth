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

const (
	cookieName    = "basicAuth"
	cookieKeyAuth = "authenticated"
)

// Handler is a handler func that does the authentification for stdlib http
func (b Backend) Handler(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.debug("checking auth")
		session, err := b.cookieStore.Get(r, cookieName)
		if err != nil {
			b.debug("error getting cookie %s: %v", cookieName, err)
		}
		if auth, ok := session.Values[cookieKeyAuth].(bool); !ok || !auth {
			b.debug("no auth session %v calling ad ldap", auth)
			adAuth := b.getAuth(w, r)
			if !adAuth {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(w, b.noAuthMsg, http.StatusUnauthorized)
				return
			}
			session.Values[cookieKeyAuth] = true
			session.Save(r, w)
		}
		b.debug("authenticated calling next handler")
		next.ServeHTTP(w, r)

	})
}

// Gin is a handler func that does the authentification for GIN
func (b Backend) Gin() gin.HandlerFunc {
	return func(c *gin.Context) {
		b.debug("checking auth")
		r := c.Request
		w := c.Writer
		session, err := b.cookieStore.Get(r, cookieName)
		if err != nil {
			b.debug("error getting cookie %s: %v", cookieName, err)
		}
		if auth, ok := session.Values[cookieKeyAuth].(bool); !ok || !auth {
			b.debug("no auth session %v calling ad ldap", auth)
			adAuth := b.getAuth(w, r)
			if !adAuth {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": b.noAuthMsg})
				return
			}
			session.Values[cookieKeyAuth] = true
			session.Save(r, w)
		}
		b.debug("authenticated calling next handler")
		// Continue down the chain to handler etc
		c.Next()
	}
}
