# go-basic-auth [![Go](https://github.com/vogtp/go-basic-auth/actions/workflows/go.yml/badge.svg)](https://github.com/vogtp/go-basic-auth/actions/workflows/go.yml)[![codecov](https://codecov.io/gh/vogtp/go-basic-auth/branch/main/graph/badge.svg?token=DV0IDZ2FXE)](https://codecov.io/gh/vogtp/go-basic-auth)[![Go Report Card](https://goreportcard.com/badge/github.com/vogtp/go-basic-auth)](https://goreportcard.com/report/github.com/vogtp/go-basic-auth)[![Release](https://img.shields.io/github/release/vogtp/go-basic-auth.svg?style=flat-square)](https://github.com/vogtp/go-basic-auth/releases)[![GoDoc](https://pkg.go.dev/badge/github.com/vogtp/go-basic-auth?status.svg)](https://pkg.go.dev/github.com/vogtp/go-basic-auth?tab=doc)


A go module for simple HTTP basic auth.

Currently a LDAP backend and a simple in memory backend is provided.

```go
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/vogtp/go-basic-auth"
)

func main() {
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

```
