package scopequery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxPageSize = 100

// Result is a normalized asset returned by a provider API.
type Result struct {
	Provider string `json:"provider"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Host     string `json:"host,omitempty"`
	Scheme   string `json:"scheme,omitempty"`
}

// Target returns a scanner-friendly endpoint. URL mode infers a scheme when
// the provider does not return one; hostport mode is intended for httpx.
func (r Result) Target(format string) string {
	host, scheme := normalizedHost(r.Host)
	if host == "" {
		host = strings.TrimSpace(r.IP)
	}
	if host == "" {
		return ""
	}
	if scheme == "" {
		scheme = r.Scheme
	}

	switch format {
	case "host":
		return host
	case "url":
		if scheme == "" {
			scheme = inferredScheme(r.Port)
		}
		if r.Port == 0 {
			return scheme + "://" + host
		}
		return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(r.Port))
	default:
		if r.Port == 0 {
			return host
		}
		return net.JoinHostPort(host, strconv.Itoa(r.Port))
	}
}

func inferredScheme(port int) string {
	switch port {
	case 443, 8443, 9443, 10443:
		return "https"
	default:
		return "http"
	}
}

func normalizedHost(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return strings.TrimSuffix(strings.ToLower(parsed.Hostname()), "."), parsed.Scheme
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.TrimSuffix(strings.ToLower(host), "."), ""
	}
	return strings.TrimSuffix(strings.ToLower(value), "."), ""
}

// Scope is an allowlist of exact/subdomains and IP prefixes.
type Scope struct {
	domains  []string
	prefixes []netip.Prefix
}

func NewScope(entries []string) (*Scope, error) {
	s := &Scope{}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if host, _ := normalizedHost(entry); host != "" && strings.Contains(entry, "://") {
			entry = host
		}
		entry = strings.TrimPrefix(strings.ToLower(entry), "*.")
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			s.prefixes = append(s.prefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			s.prefixes = append(s.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		if strings.ContainsAny(entry, "/ ") {
			return nil, fmt.Errorf("invalid scope %q", entry)
		}
		s.domains = append(s.domains, strings.TrimSuffix(entry, "."))
	}
	return s, nil
}

func (s *Scope) Empty() bool { return len(s.domains) == 0 && len(s.prefixes) == 0 }

func (s *Scope) Allows(r Result) bool {
	_, ok := s.Filter(r)
	return ok
}

// Filter returns a safe-to-output result. If only the result IP is in scope,
// an unrelated hostname attached to that IP is removed before output.
func (s *Scope) Filter(r Result) (Result, bool) {
	host, _ := normalizedHost(r.Host)
	hostAllowed := false
	if addr, err := netip.ParseAddr(host); err == nil {
		for _, prefix := range s.prefixes {
			if prefix.Contains(addr) {
				hostAllowed = true
				break
			}
		}
	}
	for _, domain := range s.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			hostAllowed = true
			break
		}
	}
	if hostAllowed {
		return r, true
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(r.IP)); err == nil {
		for _, prefix := range s.prefixes {
			if prefix.Contains(addr) {
				r.Host = ""
				return r, true
			}
		}
	}
	return Result{}, false
}

type Searcher struct {
	Client      *http.Client
	FOFAURL     string
	QuakeURL    string
	DriftnetURL string
}

func NewSearcher(timeout time.Duration) *Searcher {
	return &Searcher{
		Client:      &http.Client{Timeout: timeout},
		FOFAURL:     "https://fofa.info/api/v1/search/all",
		QuakeURL:    "https://quake.360.net/api/v3/search/quake_service",
		DriftnetURL: "https://api.driftnet.io/v1/scan",
	}
}

func (s *Searcher) Search(ctx context.Context, provider, expression, key string, limit int) ([]Result, error) {
	if key == "" {
		return nil, fmt.Errorf("%s API key is empty", provider)
	}
	if limit <= 0 {
		return nil, errors.New("limit must be greater than zero")
	}
	switch strings.ToLower(provider) {
	case "fofa":
		return s.searchFOFA(ctx, expression, key, limit)
	case "quake":
		return s.searchQuake(ctx, expression, key, limit)
	case "driftnet":
		return s.searchDriftnet(ctx, expression, key, limit)
	default:
		return nil, fmt.Errorf("unsupported provider %q", provider)
	}
}

func (s *Searcher) do(req *http.Request, out any) error {
	resp, err := s.Client.Do(req)
	if err != nil {
		op := "request"
		cause := err
		for {
			var urlError *url.Error
			if !errors.As(cause, &urlError) || urlError.Err == nil {
				break
			}
			if urlError.Op != "" {
				op = urlError.Op
			}
			cause = urlError.Err
		}
		message := cause.Error()
		if key := req.URL.Query().Get("key"); key != "" {
			message = strings.ReplaceAll(message, key, "[redacted]")
		}
		return fmt.Errorf("provider request failed during %s: %s", op, message)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		message := strings.TrimSpace(string(body))
		if key := req.URL.Query().Get("key"); key != "" {
			message = strings.ReplaceAll(message, key, "[redacted]")
		}
		return fmt.Errorf("provider returned HTTP %d: %s", resp.StatusCode, message)
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type fofaResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Results [][]string `json:"results"`
}

func (s *Searcher) searchFOFA(ctx context.Context, expression, key string, limit int) ([]Result, error) {
	results := make([]Result, 0, limit)
	for page := 1; len(results) < limit; page++ {
		pageSize := min(limit-len(results), maxPageSize)
		params := url.Values{
			"key":     {key},
			"qbase64": {base64.StdEncoding.EncodeToString([]byte(expression))},
			"fields":  {"ip,port,host,protocol"},
			"page":    {strconv.Itoa(page)},
			"size":    {strconv.Itoa(pageSize)},
			"full":    {"false"},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.FOFAURL+"?"+params.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		var response fofaResponse
		if err := s.do(req, &response); err != nil {
			return nil, err
		}
		if response.Error {
			return nil, errors.New(response.ErrMsg)
		}
		for _, row := range response.Results {
			if len(row) < 3 {
				continue
			}
			port, _ := strconv.Atoi(row[1])
			result := Result{Provider: "fofa", IP: row[0], Port: port, Host: row[2]}
			if len(row) > 3 && (row[3] == "http" || row[3] == "https") {
				result.Scheme = row[3]
			}
			results = append(results, result)
			if len(results) == limit {
				break
			}
		}
		if len(response.Results) < pageSize {
			break
		}
	}
	return results, nil
}

type quakeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Hostname string `json:"hostname"`
	} `json:"data"`
}

func (s *Searcher) searchQuake(ctx context.Context, expression, key string, limit int) ([]Result, error) {
	results := make([]Result, 0, limit)
	for start := 0; len(results) < limit; start = len(results) {
		pageSize := min(limit-len(results), maxPageSize)
		body, err := json.Marshal(map[string]any{
			"query": expression, "start": start, "size": pageSize,
			"ignore_cache": false, "include": []string{"ip", "port", "hostname"},
		})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.QuakeURL, strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-QuakeToken", key)
		var response quakeResponse
		if err := s.do(req, &response); err != nil {
			return nil, err
		}
		if response.Code != 0 {
			return nil, errors.New(response.Message)
		}
		for _, row := range response.Data {
			results = append(results, Result{Provider: "quake", IP: row.IP, Port: row.Port, Host: row.Hostname})
		}
		if len(response.Data) < pageSize {
			break
		}
	}
	return results, nil
}

type driftnetIPResponse struct {
	Values map[string]struct {
		Values map[string]int `json:"values"`
	} `json:"values"`
}

type driftnetSearchResponse struct {
	Results []struct {
		Items []struct {
			Value   string `json:"value"`
			Type    string `json:"type"`
			Context string `json:"context"`
		} `json:"items"`
	} `json:"results"`
}

func (s *Searcher) searchDriftnet(ctx context.Context, expression, key string, limit int) ([]Result, error) {
	if _, err := netip.ParseAddr(expression); err == nil {
		return s.searchDriftnetIP(ctx, expression, key, limit)
	}
	if _, err := netip.ParsePrefix(expression); err == nil {
		return s.searchDriftnetIP(ctx, expression, key, limit)
	}
	params := url.Values{"expression": {expression}, "most_recent": {"true"}}
	return s.searchDriftnetReports(ctx, s.DriftnetURL+"/protocols?"+params.Encode(), key, limit)
}

func (s *Searcher) searchDriftnetIP(ctx context.Context, expression, key string, limit int) ([]Result, error) {
	params := url.Values{"ip": {expression}, "from": {time.Now().AddDate(0, 0, -30).Format(time.DateOnly)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.DriftnetURL+"/ipports?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	var response driftnetIPResponse
	if err := s.do(req, &response); err != nil {
		return nil, err
	}
	results := make([]Result, 0, limit)
	for ip, ports := range response.Values {
		for portValue := range ports.Values {
			port, err := strconv.Atoi(portValue)
			if err != nil {
				continue
			}
			results = append(results, Result{Provider: "driftnet", IP: ip, Port: port})
			if len(results) == limit {
				return results, nil
			}
		}
	}
	return results, nil
}

func (s *Searcher) searchDriftnetReports(ctx context.Context, endpoint, key string, limit int) ([]Result, error) {
	results := make([]Result, 0, limit)
	for page := 0; len(results) < limit; page++ {
		pageURL := endpoint + "&page=" + strconv.Itoa(page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Accept", "application/json")
		var response driftnetSearchResponse
		if err := s.do(req, &response); err != nil {
			return nil, err
		}
		for _, report := range response.Results {
			var result Result
			result.Provider = "driftnet"
			for _, item := range report.Items {
				if item.Context != "" {
					continue
				}
				switch {
				case item.Type == "ip":
					result.IP = item.Value
				case item.Type == "host":
					result.Host = item.Value
				case strings.HasPrefix(item.Type, "port-"):
					result.Port, _ = strconv.Atoi(item.Value)
				}
			}
			if result.IP != "" && result.Port != 0 {
				results = append(results, result)
				if len(results) == limit {
					return results, nil
				}
			}
		}
		if len(response.Results) < maxPageSize {
			break
		}
	}
	return results, nil
}
