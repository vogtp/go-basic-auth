package auth_test

import (
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/vogtp/go-basic-auth"
)

func ExampleHandleFunc() {
	allowMap := make(map[string]string)
	allowMap["user"] = "password"
	basicAuth := auth.New(
		auth.WithInMemory(allowMap),                            // authorise users in allowMap (no groups used)
		auth.WithLdap("SERVER_NAME", "BASE_DN", "DOMAIN_NAME"), // authorise users for (AD) LDAP
		auth.WithGroup("group"),                                // One or more groups the user has to be in to be authorised
		auth.Debug(),                                           // enable debug output
		auth.WithFailMsg("Use the email address as user name")) // custom error message
	// use as http middleware
	http.HandleFunc("/", basicAuth.Handler(http.NotFound))
	// or use as GIN middleware
	gin := gin.Default()
	gin.Use(basicAuth.Gin())
}
