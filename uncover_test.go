package uncover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources/agent/crt"
	"github.com/stretchr/testify/require"
)

func TestCrtIsRegisteredAsAnonymousAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "example.com", r.URL.Query().Get("apex"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"sub":"api.example.com","first_seen":"2024-01-02T03:04:05Z"}]`))
	}))
	t.Cleanup(server.Close)
	originalURL := crt.URL
	crt.URL = server.URL
	t.Cleanup(func() { crt.URL = originalURL })

	service, err := New(&Options{
		Agents:        []string{"crt"},
		Queries:       []string{"example.com"},
		Limit:         1,
		MaxRetry:      0,
		Timeout:       5,
		RateLimit:     60,
		RateLimitUnit: time.Second,
	})
	require.NoError(t, err)
	require.Len(t, service.Agents, 1)
	require.Equal(t, "crt", service.Agents[0].Name())

	results, err := service.Execute(context.Background())
	require.NoError(t, err)
	result, ok := <-results
	require.True(t, ok)
	require.Equal(t, "api.example.com", result.Host)
	require.Equal(t, "crt", result.Source)
	_, ok = <-results
	require.False(t, ok)
}

func TestCrtIsListedAsAnonymousProvider(t *testing.T) {
	service := &Service{Options: &Options{Agents: []string{"crt"}}}
	require.True(t, service.hasAnyAnonymousProvider())
	require.True(t, isAnonymousAgent("crt"))
	require.False(t, isAnonymousAgent("fofa"))
}
