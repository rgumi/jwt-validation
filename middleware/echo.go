package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/ron96G/jwt-validation/jwks"

	echo "github.com/labstack/echo/v4"
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

func handleError(c echo.Context, statusCode int, err error) error {
	resp := c.Response()

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(statusCode)
	resp.Write([]byte("{" + "\"message\":\"" + err.Error() + "\"}"))
	return nil
}

func JWTValidation(skipper echo_mw.Skipper, logger jwks.Logger, closeChan <-chan struct{}, url string) echo.MiddlewareFunc {

	j := jwks.New()
	j.SetLogger(logger)
	j.Schedule(url, 5*time.Minute)

	go func() {
		<-closeChan
		j.Cancel()
	}()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if skipper != nil && skipper(c) {
				return next(c)
			}

			rawToken, err := extractTokenFromHeader(c.Request())
			if err != nil {
				return handleError(c, 401, fmt.Errorf("%w: invalid Authorization", err))
			}

			token, err := jwt.Parse(rawToken, j.KeyFunc)
			if err != nil {
				return handleError(c, 403, fmt.Errorf("%w: invalid Authorization", err))
			}

			if token.Valid {
				return next(c)
			}
			return handleError(c, 403, fmt.Errorf("invalid Authorization"))
		}
	}
}
