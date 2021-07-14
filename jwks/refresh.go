package jwks

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func (j *JWKS) Schedule(rawURL string, refreshTimeout time.Duration) (err error) {

	j.URL, err = url.Parse(rawURL)
	if err != nil {
		return
	}

	go func() {

		// get it once before starting the scheduled job
		if err := j.refresh(j.ctx); err != nil {
			j.Log.Warnf("%s: Failed to refresh JWKS", err)
		}

		for {
			select {
			case <-time.After(refreshTimeout):
				j.Log.Info("Refreshing")
				if err := j.refresh(j.ctx); err != nil {
					j.Log.Warnf("%s: Failed to refresh JWKS", err)
				}

			case <-j.close:
				j.Log.Info("Canceled")
				return
			}
		}
	}()

	return
}

func (j *JWKS) refresh(ctx context.Context) error {
	retries := 0

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL.String(), nil)
	if err != nil {
		return err
	}

start:
	resp, err := j.httpClient.Do(req)
	if err != nil {
		j.Log.Warnf("%s: failed to refresh JWKS", err.Error())
		// retry
		if retries >= j.maxRetries {
			return fmt.Errorf("%s: %s: failed to refresh JWKS", errors.New("reached maxRetries"), err)
		}
		time.Sleep(j.retryTimeout)
		retries++
		goto start
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		j.Log.Warn("Failed to read body of response")
		return fmt.Errorf("%s: failed to refresh JWKS", err.Error())
	}
	resp.Body.Close()

	copy := new(JWKS)
	if err = copy.Unmarshal(body); err != nil {
		return fmt.Errorf("%s: Failed to refresh JWKS", err.Error())
	}

	j.mutex.Lock()
	j.Keys = copy.Keys
	j.mutex.Unlock()
	return nil
}
