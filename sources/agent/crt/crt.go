// Package crt implements the keyless crt.name Certificate Transparency index.
package crt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"golang.org/x/net/publicsuffix"
)

var (
	// URL is the crt.name search endpoint. It is a variable so tests can use a
	// local HTTP server without changing production behavior.
	URL = "https://crt.name/v1/search"
)

const maxResponseBodyBytes = 64 * 1024 * 1024

type record struct {
	Sub       string     `json:"sub"`
	FirstSeen *time.Time `json:"first_seen"`
}

// Agent queries crt.name for subdomains indexed under an eTLD+1 apex.
type Agent struct{}

func (agent *Agent) Name() string { return "crt" }

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session == nil || session.Keys == nil {
		return nil, errors.New("crt provider requires a session")
	}
	if query == nil {
		return nil, errors.New("crt query cannot be nil")
	}

	apex, err := normalizeApex(query.Query)
	if err != nil {
		return nil, err
	}

	results := make(chan sources.Result)
	go func() {
		defer close(results)

		resp, err := agent.fetch(ctx, session, apex)
		if err != nil {
			closeResponse(resp)
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
			return
		}
		defer closeResponse(resp)

		decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes))
		token, err := decoder.Token()
		if err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: fmt.Errorf("decode crt.name response: %w", err)})
			return
		}
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '[' {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: errors.New("crt.name response is not a JSON array")})
			return
		}

		emitted := 0
		for decoder.More() {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: fmt.Errorf("decode crt.name record: %w", err)})
				return
			}

			var item record
			if err := json.Unmarshal(raw, &item); err != nil {
				sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: fmt.Errorf("decode crt.name record: %w", err)})
				return
			}
			host, ok := normalizeHost(item.Sub, apex)
			if !ok {
				continue
			}

			result := sources.Result{Source: agent.Name(), Host: host, Raw: append([]byte(nil), raw...)}
			if item.FirstSeen != nil {
				result.FirstSeen = item.FirstSeen
			}
			if !sources.SendResult(ctx, results, result) {
				return
			}
			emitted++
			if query.Limit > 0 && emitted >= query.Limit {
				return
			}
		}

		if _, err := decoder.Token(); err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: fmt.Errorf("finish crt.name response: %w", err)})
		}
	}()

	return results, nil
}

func (agent *Agent) fetch(ctx context.Context, session *sources.Session, apex string) (*http.Response, error) {
	params := url.Values{
		"apex":   {apex},
		"dates":  {"1"},
		"format": {"json"},
	}
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, URL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if token := session.Keys.CrtToken; token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return session.Do(request, agent.Name())
}

func normalizeApex(value string) (string, error) {
	apex := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if apex == "" {
		return "", errors.New("crt apex cannot be empty")
	}
	if strings.ContainsAny(apex, " /:\\?&#") || strings.HasPrefix(apex, "*.") {
		return "", fmt.Errorf("invalid crt apex %q", value)
	}
	if effective, err := publicsuffix.EffectiveTLDPlusOne(apex); err != nil || effective != apex {
		return "", fmt.Errorf("crt requires an eTLD+1 apex (got %q)", value)
	}
	return apex, nil
}

func normalizeHost(value, apex string) (string, bool) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if host == "" || strings.HasPrefix(host, "*.") {
		return "", false
	}
	if host != apex && !strings.HasSuffix(host, "."+apex) {
		return "", false
	}
	return host, true
}

func closeResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
