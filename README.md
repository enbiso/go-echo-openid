# go-echo-openid

## OpenID middleware extension for go echo framework

golang echo openid middleware based on JWKS link

Extension for echo's official JWT middleware to support JWKS URI and RSA256 keys

Along with the existing configurations you can provide authentication URI

```
// JWTOpenIDConfig struct
type JWTOpenIDConfig struct {
    middleware.JWTConfig
    // Authentication endpoint for openID auth
    AuthEndpoint string
    // KID (key ID) that has used for signing. Ignore this if you want to use the first default key
    KeyID        string
}
```

to provide an open ID url you have to do the following in the config

```
e.Use(middleware.JWTWithOpenID(middleware.JWTOpenIDConfig{
    AuthEndpoint:    https://id.enbiso.com/,		
}))

```


