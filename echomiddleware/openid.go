package echomiddleware

import (
	"crypto/subtle"
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
	JwksURI         string `json:"jwks_uri"`
	UserInfoEnpoint string `json:"userinfo_endpoint"`
}

// JWTOpenIDConfig struct
type JWTOpenIDConfig struct {
	Authority      string
	Audience       string
	KeyID          string
	SuccessHandler func(c echo.Context)
}

// UserInfo struct
type UserInfo struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
}

// JWTWithOpenID middleware creation
func JWTWithOpenID(config JWTOpenIDConfig) echo.MiddlewareFunc {
	loadJwk(config.Authority, config.KeyID)
	cert := "-----BEGIN CERTIFICATE-----\n" + jwk.X5c[0] + "\n-----END CERTIFICATE-----"
	signingKey, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))

	mware := middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey:    signingKey,
		SigningMethod: jwk.ALG,
		SuccessHandler: func(c echo.Context) {
			if config.SuccessHandler != nil {
				config.SuccessHandler(c)
			}
		},
	})

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return mware(func(c echo.Context) error {
			token := c.Get("user").(*jwt.Token)
			claims := token.Claims.(jwt.MapClaims)

			err := claims.Valid()
			if err != nil {
				return &echo.HTTPError{
					Code:     http.StatusUnauthorized,
					Message:  "invalid token claim",
					Internal: err,
				}
			}

			if !claims.VerifyIssuer(config.Authority, true) {
				return &echo.HTTPError{
					Code:    http.StatusUnauthorized,
					Message: "invalid token issuer",
				}
			}

			//if !claims.VerifyAudience(config.Audience, true) {
			if verifyAudience(claims, config.Audience, true) {
				return &echo.HTTPError{
					Code:    http.StatusUnauthorized,
					Message: "invalid token audience",
				}
			}
			return next(c)
		})
	}
}

func verifyAudience(m jwt.MapClaims, cmp string, req bool) bool {
	switch m["aud"].(type) {
	case string:
		aud := m["aud"].(string)
		return verifyAud(aud, cmp, req)
	default:
		auds := m["aud"].([]interface{})
		for _, aud := range auds {
			if verifyAud(aud.(string), cmp, req) {
				return true
			}
		}
		return false
	}
}

func verifyAud(aud string, cmp string, required bool) bool {
	if aud == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

// GetUserInfo method
func GetUserInfo() UserInfo {
	userInfoResp, _ := http.Get(cfg.UserInfoEnpoint)
	userInfo := UserInfo{}
	json.NewDecoder(userInfoResp.Body).Decode(&userInfo)
	return userInfo
}

var jwk *JSONWebKeys
var cfg = &OpenIDConfig{}

func loadJwk(endpoint string, kid string) error {
	if jwk != nil {
		return nil
	}
	cfgResp, err := http.Get(endpoint + "/.well-known/openid-configuration")
	if err != nil {
		return err
	}
	err = json.NewDecoder(cfgResp.Body).Decode(cfg)
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
