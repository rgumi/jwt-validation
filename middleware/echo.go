package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/rgumi/jwt-validation/jwks"

	"github.com/labstack/echo"
	echo_mw "github.com/labstack/echo/v4/middleware"
)

func extractTokenFromHeader(req *http.Request) (token string, err error) {
	scheme := "Bearer "
	token = req.Header.Get("Authorization")

	if strings.HasPrefix(token, scheme) {
		return token[len(scheme):], nil
	}
	return "", fmt.Errorf("malformed or missing Authorization header")
}

func JWTValidation(skipper echo_mw.Skipper, closeChan <-chan struct{}, url string) echo.MiddlewareFunc {

	j := jwks.New()
	j.Schedule(url, 5*time.Minute)

	go func() {
		<-closeChan
		j.Cancel()
	}()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rawToken, err := extractTokenFromHeader(c.Request())
			if err != nil {
				return fmt.Errorf("%w: invalid Authorization", err)
			}
			token, err := jwt.Parse(rawToken, j.KeyFunc)
			if err != nil {
				return fmt.Errorf("%w: invalid Authorization", err)
			}

			if token.Valid {
				return next(c)
			}
			return fmt.Errorf("invalid Authorization")
		}
	}
}
