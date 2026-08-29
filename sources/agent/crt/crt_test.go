package crt

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func testSession(t *testing.T) *sources.Session {
	t.Helper()
	session, err := sources.NewSession(&sources.Keys{}, 0, 5, 60, []string{"crt"}, time.Second, "")
	require.NoError(t, err)
	t.Cleanup(session.Close)
	return session
}

func TestQueryParsesAndFiltersRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "example.com", r.URL.Query().Get("apex"))
		require.Equal(t, "1", r.URL.Query().Get("dates"))
		require.Equal(t, "json", r.URL.Query().Get("format"))
		require.Equal(t, "application/json", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
{"sub":"API.Example.COM.","first_seen":"2024-01-02T03:04:05Z"},
{"sub":"*.example.com","first_seen":null},
{"sub":"outside.example.net","first_seen":"2024-01-02T03:04:05Z"},
{"sub":"www.example.com","first_seen":null},
{"sub":"WWW.EXAMPLE.COM.","first_seen":"2025-01-01T00:00:00Z"}
]`))
	}))
	t.Cleanup(server.Close)

	ch, err := (&Agent{Endpoint: server.URL}).Query(context.Background(), testSession(t), &sources.Query{Query: "Example.COM.", Limit: 10})
	require.NoError(t, err)

	var results []sources.Result
	for result := range ch {
		require.NoError(t, result.Error)
		results = append(results, result)
	}
	require.Len(t, results, 2)
	require.Equal(t, "api.example.com", results[0].Host)
	require.NotNil(t, results[0].FirstSeen)
	require.Equal(t, "2024-01-02T03:04:05Z", results[0].FirstSeen.UTC().Format(time.RFC3339))
	require.Equal(t, "www.example.com", results[1].Host)
	require.Nil(t, results[1].FirstSeen)
	require.JSONEq(t, `{"sub":"API.Example.COM.","first_seen":"2024-01-02T03:04:05Z"}`, string(results[0].Raw))
}

func TestQueryHonorsLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"sub":"a.example.com"},{"sub":"b.example.com"}]`))
	}))
	t.Cleanup(server.Close)

	ch, err := (&Agent{Endpoint: server.URL}).Query(context.Background(), testSession(t), &sources.Query{Query: "example.com", Limit: 1})
	require.NoError(t, err)
	var results []sources.Result
	for result := range ch {
		results = append(results, result)
	}
	require.Len(t, results, 1)
	require.Equal(t, "a.example.com", results[0].Host)
}

func TestQueryRejectsNonApex(t *testing.T) {
	_, err := (&Agent{}).Query(context.Background(), testSession(t), &sources.Query{Query: "www.example.com"})
	require.ErrorContains(t, err, "eTLD+1 apex")
}

func TestQueryReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	ch, err := (&Agent{Endpoint: server.URL}).Query(context.Background(), testSession(t), &sources.Query{Query: "example.com"})
	require.NoError(t, err)
	result, ok := <-ch
	require.True(t, ok)
	require.Error(t, result.Error)
	require.Contains(t, result.Error.Error(), "unexpected status code 429")
	_, ok = <-ch
	require.False(t, ok)
}

func TestQueryRespectsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("["))
		for i := 0; i < 100; i++ {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			_, _ = fmt.Fprintf(w, `{"sub":"host-%d.example.com"}`, i)
		}
		_, _ = w.Write([]byte("]"))
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := (&Agent{Endpoint: server.URL}).Query(ctx, testSession(t), &sources.Query{Query: "example.com", Limit: 1000})
	require.NoError(t, err)
	select {
	case _, ok := <-ch:
		require.True(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("agent produced no result")
	}
	cancel()

	select {
	case _, ok := <-ch:
		require.False(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("agent channel did not close after cancellation")
	}
}

func TestNormalizeHostRejectsLookalikeDomain(t *testing.T) {
	_, ok := normalizeHost("example.com.attacker.test", "example.com")
	require.False(t, ok)
	_, ok = normalizeHost(strings.ToUpper("api.example.com."), "example.com")
	require.True(t, ok)
}
