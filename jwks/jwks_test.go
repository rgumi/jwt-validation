package jwks

import (
	"fmt"
	"testing"

	jwt "github.com/golang-jwt/jwt"
)

var (
	tokenString  = `eyJraWQiOiI3NGYxNjAyNS1mZjNkLTQ1M2ItYTkxNy1lY2E5NzU0MjNkZWEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI1MzIxODhjZS1hNzFhLTQ1YjQtYjFkYS1lODRjOWM3NDBiZjMiLCJjbGllbnRJZCI6ImNjYy0tcnVuZG1jLS1kbWMtbWVzc2FnaW5nLWFwaSIsImF6cCI6InN0YXJnYXRlIiwib3JpZ2luWm9uZSI6ImF3cyIsInR5cCI6IkJlYXJlciIsImVudiI6InBsYXlncm91bmQiLCJvcGVyYXRpb24iOiJHRVQiLCJyZXF1ZXN0UGF0aCI6Ii9jY2MvZG1jL21lc3NhZ2luZy9yZXNvdXJjZXMvdjEvbWVzc2FnZSIsIm9yaWdpblN0YXJnYXRlIjoiaHR0cHM6Ly9zdGFyZ2F0ZS1wbGF5Z3JvdW5kLmxpdmUuZGhlaS50ZWxla29tLmRlIiwiaXNzIjoiaHR0cHM6Ly9zdGFyZ2F0ZS1wbGF5Z3JvdW5kLmxpdmUuZGhlaS50ZWxla29tLmRlL2F1dGgvcmVhbG1zL2RlZmF1bHQiLCJleHAiOjE2MjYxNjA0NTAsImlhdCI6MTYyNjE2MDE1MH0.MsJCifbZg0PYlSZuI0PT7TaSHFUH3MocuOvnMZJQZhE0Pil4qyGGjNf4GCyWA5XGaizDCQ1EvyclmZeS0m12ENLXeqAwrbtTohJWSxfp1AcvOgiiDXmV-ErPliAq0iNY2-DmAsPVc_3uc98eZrYmV68UpanHKtfDDdLs1uPnq73X4vbghpjJpi6EEFqAKZ0n93FkO_IwfmR29XTOd94W3CDMwJbS0G6tMlYhQtWYBn9MA8UR6m6GL64TifXYWbIEOUSsCqm-vrq0nW3Q2HD1PIxbhuAg4zH0i7gsDPDuADlIw8SKjVjN-kJgXQUeiRznAkhYmHTfwjicN-CSozu15g`
	jwksResponse = `{
		"keys": [
			{
				"kid": "74f16025-ff3d-453b-a917-eca975423dea",
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n": "yJ1bopo5Ai_q48Z9-nXWDUMWb8F8uBsmw1ACygdIkxRgioMQxgbR_aHSxk-hiHFi51NBdSW7HVRb3QYDobPNza3dgKpu4SD6XbCAB7dqnYMlADH8GMLPN6Mwe3qYTzRFBSgnCk6odUX3J6SyqHb9vpJKG6BDEFMbBAZTwfxAGOCnKcG3v42Mk7_8O2PUJwHEEb51ystGMHDnFooE5YyNS_PLbpK-zkcroYcNYDgR8Pnkui2CtrYQGLfOGuY69IB1BuDCpDJ8ep9KftgsKaCMw_UoOas6nqKik_UeaoO_7qNreurDtmsHKLWQhCVhMjVWaUbWBTsSwErsLWp53t1jNw",
				"e": "AQAB",
				"x5c": [
					"MIIDKTCCAhGgAwIBAgIJAMngF67g+jdGMA0GCSqGSIb3DQEBCwUAMFQxUjBQBgNVBAMTSWh0dHBzOi8vc3RhcmdhdGUtaHlwLWRldi16b25lLWF3cy5kZXYuZGhlaS50ZWxla29tLmRlL2F1dGgvcmVhbG1zL2RlZmF1bHQwHhcNMjEwNDI4MTAwOTQwWhcNMjIwNDIzMTAwOTQxWjBUMVIwUAYDVQQDE0lodHRwczovL3N0YXJnYXRlLWh5cC1kZXYtem9uZS1hd3MuZGV2LmRoZWkudGVsZWtvbS5kZS9hdXRoL3JlYWxtcy9kZWZhdWx0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyJ1bopo5Ai/q48Z9+nXWDUMWb8F8uBsmw1ACygdIkxRgioMQxgbR/aHSxk+hiHFi51NBdSW7HVRb3QYDobPNza3dgKpu4SD6XbCAB7dqnYMlADH8GMLPN6Mwe3qYTzRFBSgnCk6odUX3J6SyqHb9vpJKG6BDEFMbBAZTwfxAGOCnKcG3v42Mk7/8O2PUJwHEEb51ystGMHDnFooE5YyNS/PLbpK+zkcroYcNYDgR8Pnkui2CtrYQGLfOGuY69IB1BuDCpDJ8ep9KftgsKaCMw/UoOas6nqKik/UeaoO/7qNreurDtmsHKLWQhCVhMjVWaUbWBTsSwErsLWp53t1jNwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBvG7gHkif1Vf0E+ZLS6AbZxgajINvi5ffQiKptnUX8/nL/2lR4XuD5DvIKbkSmANndDwuAko5KRAcUDvRpXUm+Y8lTCfBUqReEzCYjuRZl+pNNkLGMqpN72XZVMURiR6a1sG+SF7T5PK54GOrNYstKkc2eBXCFrt/+hqZ9yP/zqQ6ozwd73Z9mfReNyedCg7aXLKM0IKlTVpq+MLOENNjd9WSMXuDdxdjO1U4sWPJTsIrg8OptSTB5m4IY9YwrKj52gmSf09jlzykNXT+TmRpEXxW6+2ITldSHl4haYLgrIWBAF9Vb0CsEp96WN0S5fqI2FubHYni7lkwYakDU4PzL"
				],
				"x5t": "ovUE1GXRJb3NboNmgpDwTn1vM_k",
				"x5t#S256": "cXdNrCOs1YdsF3HKD1DuyI0nXtw25VX1imD6mVG37QQ"
			}
		]
	}`
)

func TestValidation(t *testing.T) {
	j := New()
	j.Unmarshal([]byte(jwksResponse))

	token, err := jwt.Parse(tokenString, j.KeyFunc)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("jwt.Parse should have returned an error as the token is invalid")
	}

	if token.Valid {
		t.Error("The token should not be valid")
	} else {
		fmt.Println("Token is invalid and that is correct")
	}

}
