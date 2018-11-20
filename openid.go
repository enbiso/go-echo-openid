package middleware

import (
	"encoding/json"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/middleware"

	"github.com/labstack/echo"
)

// Jwks response
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys structure
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
	ALG string   `json:"alg"`
}

// OpenIDConfig structure
type OpenIDConfig struct {
	JwksURI string `json:"jwks_uri"`
}

// JWTOpenIDConfig struct
type JWTOpenIDConfig struct {
	middleware.JWTConfig
	AuthEndpoint string
	KeyID        string
}

// JWTWithOpenID middleware creation
func JWTWithOpenID(config JWTOpenIDConfig) echo.MiddlewareFunc {
	loadJwk(config.AuthEndpoint, config.KeyID)
	cert := "-----BEGIN CERTIFICATE-----\n" + jwk.X5c[0] + "\n-----END CERTIFICATE-----"
	signingKey, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	return middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey:     signingKey,
		SigningMethod:  jwk.ALG,
		AuthScheme:     config.AuthScheme,
		BeforeFunc:     config.BeforeFunc,
		Claims:         config.Claims,
		ContextKey:     config.ContextKey,
		ErrorHandler:   config.ErrorHandler,
		Skipper:        config.Skipper,
		SuccessHandler: config.SuccessHandler,
		TokenLookup:    config.TokenLookup,
	})
}

var jwk *JSONWebKeys

func loadJwk(endpoint string, kid string) error {
	if jwk != nil {
		return nil
	}
	cfgResp, err := http.Get(endpoint + ".well-known/openid-configuration")
	if err != nil {
		return err
	}
	var cfg = OpenIDConfig{}
	err = json.NewDecoder(cfgResp.Body).Decode(&cfg)
	if err != nil {
		return err
	}
	resp, err := http.Get(cfg.JwksURI)
	if err != nil {
		return err
	}
	jwks := Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return err
	}
	if kid == "" {
		jwk = &jwks.Keys[0]
	} else {
		for k := range jwks.Keys {
			if kid == jwks.Keys[k].Kid {
				jwk = &jwks.Keys[0]
			}
		}
	}
	return nil
}
