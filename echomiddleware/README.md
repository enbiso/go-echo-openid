# Middleware extension for go echo framework

## 1. OpenID middleware

golang echo openid middleware based on JWKS link

Extension for echo's official JWT middleware to support JWKS URI and RSA256 keys

Along with the existing configurations you can provide authentication URI

```
// JWTOpenIDConfig struct
type JWTOpenIDConfig struct {
	// Authentication endpoint for openID auth
    Authority  string
    // KID (key ID) that has used for signing. Ignore this if you want to use the first default key
	KeyID        string
	// Audience to be verified	
	Audience       string
	// Success handler
	SuccessHandler func(c echo.Context)
}
```

to provide an open ID url you have to do the following in the config

```
e.Use(middleware.JWTWithOpenID(middleware.JWTOpenIDConfig{
    Authority :    "https://id.enbiso.com",
    Audience  :    "enbiso.cuckoo"
}))

```


