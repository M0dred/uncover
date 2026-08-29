package sources

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// DefaultRateLimits contains provider-specific ceilings. Session.Do applies
// these in addition to the user-configured global rate limit.
var DefaultRateLimits = map[string]*ratelimit.Options{
	"shodan":     {Key: "shodan", MaxCount: 1, Duration: time.Second},
	"shodan-idb": {Key: "shodan-idb", MaxCount: 1, Duration: time.Second},
	"fofa":       {Key: "fofa", MaxCount: 1, Duration: time.Second},
	"censys":     {Key: "censys", MaxCount: 1, Duration: 3 * time.Second},
	"quake":      {Key: "quake", MaxCount: 1, Duration: time.Second},
	"hunter":     {Key: "hunter", MaxCount: 15, Duration: time.Second},
	"zoomeye":    {Key: "zoomeye", MaxCount: 1, Duration: time.Second},
	"netlas":     {Key: "netlas", MaxCount: 1, Duration: time.Second},
	"criminalip": {Key: "criminalip", MaxCount: 1, Duration: time.Second},
	"publicwww":  {Key: "publicwww", MaxCount: 1, Duration: time.Minute},
	"hunterhow":  {Key: "hunterhow", MaxCount: 1, Duration: 3 * time.Second},
	"google":     {Key: "google", MaxCount: 1, Duration: 3 * time.Second},
	"odin":       {Key: "odin", MaxCount: 1, Duration: time.Second},
	"binaryedge": {Key: "binaryedge", MaxCount: 1, Duration: time.Second},
	"onyphe":     {Key: "onyphe", MaxCount: 1, Duration: time.Second},
	"driftnet":   {Key: "driftnet", MaxCount: 5, Duration: time.Second},
	"greynoise":  {Key: "greynoise", MaxCount: 1, Duration: time.Second},
	"daydaymap":  {Key: "daydaymap", MaxCount: 1, Duration: time.Second},
	"nerdydata":  {Key: "nerdydata", MaxCount: 1, Duration: time.Second},
	// crt.name documents a 100-request/IP/day free tier. One request every
	// 15 minutes stays below that limit without attempting to bypass it.
	"crt": {Key: "crt", MaxCount: 1, Duration: 15 * time.Minute},
}

// Session handles session agent sessions
type Session struct {
	Keys        *Keys
	Client      *retryablehttp.Client
	RetryMax    int
	RateLimits  *ratelimit.MultiLimiter
	rateLimitMu sync.Mutex
}

func NewSession(keys *Keys, retryMax, timeout, rateLimit int, engines []string, duration time.Duration, proxy string) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxy != "" {
				if proxyURL, err := url.Parse(proxy); err == nil {
					return http.ProxyURL(proxyURL)(req)
				}
			}
			return http.ProxyFromEnvironment(req)
		},
	}

	httpclient := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	options := retryablehttp.Options{RetryMax: retryMax}
	options.RetryWaitMax = time.Duration(timeout) * time.Second
	client := retryablehttp.NewWithHTTPClient(httpclient, options)

	session := &Session{
		Client:   client,
		Keys:     keys,
		RetryMax: retryMax,
	}

	var defaultRatelimit *ratelimit.Options
	switch {
	case rateLimit > 0:
		defaultRatelimit = &ratelimit.Options{Key: "default", MaxCount: uint(rateLimit), Duration: duration}
	default:
		defaultRatelimit = &ratelimit.Options{IsUnlimited: true, Key: "default"}
	}

	var err error
	session.RateLimits, err = ratelimit.NewMultiLimiter(context.Background(), defaultRatelimit)
	if err != nil {
		return nil, err
	}

	// setup ratelimit of all engines
	for _, engine := range engines {
		rateLimitOpts := DefaultRateLimits[engine]
		if rateLimitOpts == nil {
			// The default limiter is taken separately for every request. Unknown
			// engines therefore only need an unlimited source-specific bucket.
			rateLimitOpts = &ratelimit.Options{IsUnlimited: true, Key: engine}
		}
		if err = session.RateLimits.Add(rateLimitOpts); err != nil {
			session.RateLimits.Stop()
			return nil, errorutil.NewWithErr(err).Msgf("failed to setup ratelimit of %v got %v", engine, err)
		}
	}

	return session, nil
}

func (s *Session) Do(request *retryablehttp.Request, source string) (*http.Response, error) {
	if request == nil || request.Request == nil {
		return nil, errors.New("request cannot be nil")
	}
	ctx := request.Context()
	if err := s.takeRateLimit(ctx, "default"); err != nil {
		return nil, err
	}
	if source != "default" {
		if err := s.takeRateLimit(ctx, source); err != nil {
			return nil, err
		}
	}
	// close request connection (does not reuse connections)
	request.Close = true
	resp, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, safeRequestURL(request))
	}
	return resp, nil
}

// takeRateLimit waits for a limiter token while remaining responsive to the
// request context. MultiLimiter.Take itself has no context-aware API, so the
// mutex makes the CanTake/Take pair atomic for requests sharing this Session.
func (s *Session) takeRateLimit(ctx context.Context, key string) error {
	if _, err := s.RateLimits.GetLimit(key); err != nil {
		return err
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		s.rateLimitMu.Lock()
		if s.RateLimits.CanTake(key) {
			err := s.RateLimits.Take(key)
			s.rateLimitMu.Unlock()
			return err
		}
		s.rateLimitMu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Close stops limiter goroutines owned by the session.
func (s *Session) Close() {
	if s == nil {
		return
	}
	if s.RateLimits != nil {
		s.RateLimits.Stop()
	}
	if s.Client != nil {
		if s.Client.HTTPClient != nil {
			s.Client.HTTPClient.CloseIdleConnections()
		}
		if s.Client.HTTPClient2 != nil {
			s.Client.HTTPClient2.CloseIdleConnections()
		}
	}
}

func safeRequestURL(request *retryablehttp.Request) string {
	if request == nil || request.Request == nil || request.Request.URL == nil {
		return "<unknown>"
	}
	redacted := *request.Request.URL
	redacted.RawQuery = ""
	redacted.ForceQuery = false
	redacted.User = nil
	return redacted.String()
}
