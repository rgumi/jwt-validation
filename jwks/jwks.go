package jwks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	defaultMaxRetries   = 3
	defaultRetryTimeout = 500 * time.Millisecond
	defaultTransport    = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		MaxIdleConnsPerHost:   5,
		MaxConnsPerHost:       5,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		TLSHandshakeTimeout:   1 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		ForceAttemptHTTP2:  false,
		DisableCompression: true,
		DisableKeepAlives:  false,
	}

	defaultHttpClient = &http.Client{
		Transport: defaultTransport,
		Timeout:   5 * time.Second,
	}
)

type (
	// Logger defines the logging interface.
	Logger interface {
		Print(i ...interface{})
		Printf(format string, args ...interface{})
		Debug(i ...interface{})
		Debugf(format string, args ...interface{})
		Info(i ...interface{})
		Infof(format string, args ...interface{})
		Warn(i ...interface{})
		Warnf(format string, args ...interface{})
		Error(i ...interface{})
		Errorf(format string, args ...interface{})
		Fatal(i ...interface{})
		Fatalf(format string, args ...interface{})
		Panic(i ...interface{})
		Panicf(format string, args ...interface{})
	}
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
	Log            Logger
	close          chan (struct{})
	mutex          sync.RWMutex
	once           sync.Once
	ctx            context.Context
	cancel         context.CancelFunc
	refreshUnknown bool
	httpClient     *http.Client
	maxRetries     int
	retryTimeout   time.Duration
	refreshRequest chan (struct{})
}

func New() *JWKS {
	ctx, cancel := context.WithCancel(context.Background())
	j := &JWKS{
		Keys:           map[string]JWK{},
		URL:            &url.URL{},
		mutex:          sync.RWMutex{},
		once:           sync.Once{},
		ctx:            ctx,
		cancel:         cancel,
		close:          make(chan struct{}, 1),
		httpClient:     defaultHttpClient,
		maxRetries:     defaultMaxRetries,
		retryTimeout:   defaultRetryTimeout,
		refreshRequest: make(chan struct{}, 1),
		refreshUnknown: true,
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

func (j *JWKS) SetLogger(logger Logger) {
	j.Log = logger
}

func (j *JWKS) SetHttpClient(client *http.Client) {
	j.httpClient = client
}

func (j *JWKS) SetMaxRetries(maxRetries int) {
	j.maxRetries = maxRetries
}

func (j *JWKS) SetRetryTimeout(retryTimeout time.Duration) {
	j.retryTimeout = retryTimeout
}
