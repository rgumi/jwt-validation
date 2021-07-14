package jwks

import (
	"errors"
	"fmt"

	jwt "github.com/golang-jwt/jwt"
)

func (j *JWKS) KeyFunc(token *jwt.Token) (interface{}, error) {
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", errors.New("the JWT has an invalid kid"))
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", errors.New("the JWT has an invalid kid"))
	}

	j.mutex.RLock()
	defer j.mutex.RUnlock()
	key, err := j.getKey(kid)
	if err != nil {
		return nil, fmt.Errorf("%w: could not find kid in JWKS", err)
	}

	return key.RSA()
}

func (j *JWKS) getKey(key string) (jwk JWK, err error) {
	var ok bool
	err = fmt.Errorf("unable to find key '%s' in JWKS", key)

	jwk, ok = j.Keys[key]
	if !ok {
		if !j.refreshUnknown {
			return jwk, err
		}

		j.refresh()
		jwk, ok = j.Keys[key]
		if !ok {
			return jwk, err
		}
	}
	return jwk, nil
}
