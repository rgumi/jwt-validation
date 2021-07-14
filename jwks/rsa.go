package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

func (j JWK) RSA() (publicKey *rsa.PublicKey, err error) {

	if j.precomputed != nil {
		var ok bool
		if publicKey, ok = j.precomputed.(*rsa.PublicKey); ok {
			return publicKey, nil
		}
	}

	if j.E == "" || j.N == "" {
		return nil, fmt.Errorf("missing required headers E or N")
	}

	var exponent []byte
	if exponent, err = base64.RawURLEncoding.DecodeString(j.E); err != nil {
		return nil, err
	}

	// Decode the modulus from Base64.
	var modulus []byte
	if modulus, err = base64.RawURLEncoding.DecodeString(j.N); err != nil {
		return nil, err
	}

	// Create the RSA public key.
	publicKey = &rsa.PublicKey{}
	publicKey.E = int(big.NewInt(0).SetBytes(exponent).Uint64())

	// Turn the modulus into a *big.Int.
	publicKey.N = big.NewInt(0).SetBytes(modulus)

	j.precomputed = publicKey
	return
}
