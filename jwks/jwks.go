package jwks

import (
	"context"
	"encoding/json"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
)

type JWK struct {
	Kid         string   `json:"kid"`
	Kty         string   `json:"kty"`
	Alg         string   `json:"alg"`
	Use         string   `json:"use"`
	N           string   `json:"n"`
	E           string   `json:"e"`
	X5c         []string `json:"x5c"`
	X5t         string   `json:"x5t"`
	precomputed interface{}
}

type JWKS struct {
	Keys           map[string]JWK
	URL            *url.URL
	Log            *logrus.Entry
	close          chan (struct{})
	mutex          sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	refreshUnknown bool
}

func New() *JWKS {
	ctx, cancel := context.WithCancel(context.Background())
	j := &JWKS{
		Keys:   map[string]JWK{},
		URL:    &url.URL{},
		mutex:  sync.RWMutex{},
		ctx:    ctx,
		cancel: cancel,
		close:  make(chan struct{}, 1),
	}

	j.Log = logrus.StandardLogger().WithField("app", "jwks")
	return j
}

func (j *JWKS) Cancel() {
	j.cancel()
	j.close <- struct{}{}
}

func (j *JWKS) Unmarshal(data []byte) error {
	k := &struct {
		Keys []JWK `json:"keys"`
	}{}

	if err := json.Unmarshal(data, k); err != nil {
		return err
	}
	if j.Keys == nil {
		j.Keys = map[string]JWK{}
	}
	for _, key := range k.Keys {
		j.Keys[key.Kid] = key
	}
	return nil
}
