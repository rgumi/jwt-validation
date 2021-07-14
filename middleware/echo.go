package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/ron96G/jwt-validation/jwks"
	"github.com/sirupsen/logrus"

	echo "github.com/labstack/echo/v4"
	echo_mw "github.com/labstack/echo/v4/middleware"
)

func extractTokenFromHeader(req *http.Request) (token string, err error) {
	scheme := "Bearer "
	token = req.Header.Get("Authorization")

	fmt.Println("Checking prefix")
	if strings.HasPrefix(token, scheme) {
		fmt.Println("Returning token")
		return token[len(scheme):], nil
	}
	return "", fmt.Errorf("malformed or missing Authorization header")
}

func JWTValidation(skipper echo_mw.Skipper, closeChan <-chan struct{}, url string) echo.MiddlewareFunc {

	j := jwks.New()
	j.Schedule(url, 5*time.Minute)
	j.Log.Logger.SetLevel(logrus.DebugLevel)

	go func() {
		<-closeChan
		j.Cancel()
	}()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if skipper != nil && skipper(c) {
				return next(c)
			}
			c.Logger().Info("Extracting token from header")
			rawToken, err := extractTokenFromHeader(c.Request())
			if err != nil {
				return fmt.Errorf("%s: invalid Authorization", err)
			}
			c.Logger().Info("Parsing token")
			token, err := jwt.Parse(rawToken, j.KeyFunc)
			if err != nil {
				return fmt.Errorf("%s: invalid Authorization", err)
			}

			if token.Valid {
				return next(c)
			}
			return fmt.Errorf("invalid Authorization")
		}
	}
}
