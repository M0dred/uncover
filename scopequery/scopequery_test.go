package scopequery

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestScopeAllowsDomainsAndCIDRs(t *testing.T) {
	scope, err := NewScope([]string{"*.example.com", "192.0.2.0/24"})
	require.NoError(t, err)
	require.True(t, scope.Allows(Result{Host: "https://api.example.com/path"}))
	require.True(t, scope.Allows(Result{IP: "192.0.2.10"}))
	require.False(t, scope.Allows(Result{Host: "notexample.com", IP: "198.51.100.2"}))
}

func TestScopeDropsUnrelatedHostnameWhenOnlyIPMatches(t *testing.T) {
	scope, err := NewScope([]string{"192.0.2.0/24"})
	require.NoError(t, err)
	result, ok := scope.Filter(Result{Host: "shared.third-party.test", IP: "192.0.2.10", Port: 443})
	require.True(t, ok)
	require.Empty(t, result.Host)
	require.Equal(t, "192.0.2.10:443", result.Target("hostport"))
}

func TestTargetFormats(t *testing.T) {
	result := Result{IP: "192.0.2.1", Port: 443}
	require.Equal(t, "192.0.2.1:443", result.Target("hostport"))
	require.Equal(t, "https://192.0.2.1:443", result.Target("url"))
	require.Equal(t, "192.0.2.1", result.Target("host"))

	result = Result{Host: "https://app.example.com/login", Port: 8443}
	require.Equal(t, "https://app.example.com:8443", result.Target("url"))
}

func TestFOFAUsesLimitAndParsesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "1", r.URL.Query().Get("size"))
		require.Equal(t, "secret", r.URL.Query().Get("key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"results":[["192.0.2.1","443","app.example.com","https"]]}`))
	}))
	defer server.Close()

	searcher := NewSearcher(time.Second)
	searcher.FOFAURL = server.URL
	results, err := searcher.Search(t.Context(), "fofa", `domain="example.com"`, "secret", 1)
	require.NoError(t, err)
	require.Equal(t, []Result{{Provider: "fofa", IP: "192.0.2.1", Port: 443, Host: "app.example.com", Scheme: "https"}}, results)
}

func TestQuakeUsesLimitAndAuthHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "secret", r.Header.Get("X-QuakeToken"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"Successful.","data":[{"ip":"192.0.2.2","port":80,"hostname":"www.example.com"}]}`))
	}))
	defer server.Close()

	searcher := NewSearcher(time.Second)
	searcher.QuakeURL = server.URL
	results, err := searcher.Search(t.Context(), "quake", "example.com", "secret", 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "www.example.com:80", results[0].Target("hostport"))
}

func TestDriftnetIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
		require.Equal(t, "/ipports", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"other":0,"values":{"192.0.2.3":{"values":{"443":2}}}}`))
	}))
	defer server.Close()

	searcher := NewSearcher(time.Second)
	searcher.DriftnetURL = server.URL
	results, err := searcher.Search(t.Context(), "driftnet", "192.0.2.3", "secret", 1)
	require.NoError(t, err)
	require.Equal(t, "https://192.0.2.3:443", results[0].Target("url"))
}

func TestFOFANetworkErrorDoesNotLeakKey(t *testing.T) {
	searcher := NewSearcher(time.Second)
	searcher.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: request.URL.String(), Err: errors.New("network unavailable")}
	})
	_, err := searcher.Search(t.Context(), "fofa", `domain="example.com"`, "super-secret-key", 1)
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), "super-secret-key"))
	require.False(t, strings.Contains(err.Error(), "fofa.info"))
}
