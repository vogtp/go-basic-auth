# go-basic-auth

A go module for simple HTTP basic auth.

Currently a LDAP backend and a simple map backend is provided.

```go

			allowMap := make(map[string]string)
            allowMap["user"] = "password"
			auth := New(
                auth.Memory(allowMap), // authorise users in allowMap (no groups used)
		        auth.AdLdap("SERVER_NAME", "BASE_DN", "DOMAIN_NAME"),  // authorise users for (AD) LDAP
		        auth.AuthGroups("group"),  // One or more groups the user has to be in to be authorised
		        auth.Debug(),  // enable debug output
		        auth.NoAuthMsg("Use the email adress as user name")) // custom error message
			http.HandleFunc("/", auth.Handler(indexHandler))
```