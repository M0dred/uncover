package uncover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/projectdiscovery/uncover/sources/agent/crt"
	"github.com/stretchr/testify/require"
)

type bufferedAgent struct {
	results chan sources.Result
}

func (agent *bufferedAgent) Name() string { return "crt" }
func (agent *bufferedAgent) Query(context.Context, *sources.Session, *sources.Query) (chan sources.Result, error) {
	return agent.results, nil
}

func TestCrtIsRegisteredAsAnonymousAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "example.com", r.URL.Query().Get("apex"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"sub":"api.example.com","first_seen":"2024-01-02T03:04:05Z"}]`))
	}))
	t.Cleanup(server.Close)

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
	t.Cleanup(service.Close)
	require.Len(t, service.Agents, 1)
	require.Equal(t, "crt", service.Agents[0].Name())
	service.Agents[0].(*crt.Agent).Endpoint = server.URL

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

func TestExecuteRelayRespectsCancellationWhenOutputIsFull(t *testing.T) {
	session, err := sources.NewSession(&sources.Keys{}, 0, 2, 60, []string{"crt"}, time.Second, "")
	require.NoError(t, err)
	t.Cleanup(session.Close)

	upstream := make(chan sources.Result, DefaultChannelBuffSize+8)
	for i := 0; i < cap(upstream); i++ {
		upstream <- sources.Result{Source: "crt", Host: "host.example.com"}
	}
	close(upstream)

	service := &Service{
		Options:  &Options{Agents: []string{"crt"}, Queries: []string{"example.com"}},
		Agents:   []sources.Agent{&bufferedAgent{results: upstream}},
		Session:  session,
		Provider: &sources.Provider{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	results, err := service.Execute(ctx)
	require.NoError(t, err)

	// Let the relay fill its output buffer, then cancel without reading it.
	time.Sleep(50 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not close after cancellation")
	}
}
