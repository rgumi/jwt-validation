package jwks

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"
)

func (j *JWKS) Refresh() {
	j.refreshRequest <- struct{}{}
}

func (j *JWKS) Schedule(rawURL string, refreshTimeout time.Duration) (err error) {

	j.URL, err = url.Parse(rawURL)
	if err != nil {
		return
	}

	go func() {

		// get it once before starting the scheduled job

		for {
			select {
			case <-time.After(refreshTimeout):
				j.Refresh()

			case <-j.refreshRequest:
				j.Log.Info("requested refresh")
				j.refresh()

			case <-j.close:
				j.Log.Info("Canceled")
				return
			}
		}
	}()

	j.Refresh()
	return
}

func (j *JWKS) refresh() {
	j.once.Do(func() {
		go func() {
			retries := 0

			req, err := http.NewRequestWithContext(j.ctx, http.MethodGet, j.URL.String(), nil)
			if err != nil {
				j.Log.Errorf("%s: failed to fresh JWKS", err)
			}

		start:
			j.Log.Debugf("Refreshing JWKS cache from %s", j.URL)
			resp, err := j.httpClient.Do(req)
			if err != nil {
				j.Log.Warnf("%s: failed to refresh JWKS", err.Error())
				// retry
				if retries >= j.maxRetries {
					j.Log.Errorf("%s: %s: failed to refresh JWKS", errors.New("reached maxRetries"), err)
				}
				time.Sleep(j.retryTimeout)
				retries++
				goto start
			}
			j.Log.Debugf("Successfully refreshed JWKS cache from %s", j.URL)

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				j.Log.Errorf("%s: failed to refresh JWKS", err.Error())
			}
			resp.Body.Close()

			copy := new(JWKS)
			if err = copy.Unmarshal(body); err != nil {
				j.Log.Errorf("%s: Failed to refresh JWKS", err.Error())
			}

			j.mutex.Lock()
			j.Keys = copy.Keys
			j.mutex.Unlock()

			j.once = sync.Once{}
		}()
	})
}
