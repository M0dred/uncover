package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestSessionRetry(t *testing.T) {
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		time.Sleep(10 * time.Second)
		t.Log("Slept for 10 seconds")
	}))
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)
	engines := []string{"shodan", "publicwww"}
	session, err := NewSession(&Keys{}, 5, 3, 60, engines, time.Second, "")
	require.Nil(t, err)
	t.Cleanup(session.Close)
	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.Nil(t, err)
	resp, err := session.Do(req, engines[0])
	t.Log(resp, err)
	require.ErrorContains(t, err, "giving up after 6 attempts")
	require.Nil(t, resp)
}

func TestSessionRateLimitWaitRespectsRequestContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	session, err := NewSession(&Keys{}, 0, 2, 60, []string{"crt"}, time.Second, "")
	require.NoError(t, err)
	t.Cleanup(session.Close)

	first, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	resp, err := session.Do(first, "crt")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	second, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	started := time.Now()
	resp, err = session.Do(second, "crt")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, resp)
	require.Less(t, time.Since(started), time.Second)
}

func TestSessionHTTPErrorDoesNotExposeQueryCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(ts.Close)

	session, err := NewSession(&Keys{}, 0, 2, 60, []string{"test"}, time.Second, "")
	require.NoError(t, err)
	t.Cleanup(session.Close)

	request, err := retryablehttp.NewRequest(http.MethodGet, ts.URL+"/search?key=super-secret&query=example.com", nil)
	require.NoError(t, err)
	resp, err := session.Do(request, "test")
	require.Error(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Body.Close())
	require.NotContains(t, err.Error(), "super-secret")
	require.NotContains(t, err.Error(), "example.com")
	require.Contains(t, err.Error(), "/search")
}

func TestSessionUsesUnlimitedGlobalDefaultAndProviderCeiling(t *testing.T) {
	session, err := NewSession(&Keys{}, 0, 2, 0, []string{"daydaymap"}, time.Second, "")
	require.NoError(t, err)
	t.Cleanup(session.Close)

	globalLimit, err := session.RateLimits.GetLimit("default")
	require.NoError(t, err)
	require.Greater(t, globalLimit, uint(1_000_000))
	providerLimit, err := session.RateLimits.GetLimit("daydaymap")
	require.NoError(t, err)
	require.Equal(t, uint(1), providerLimit)

	_, err = session.Do(nil, "daydaymap")
	require.ErrorContains(t, err, "request cannot be nil")
}
