package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/uncover/scopequery"
)

type values []string

func (v *values) String() string { return strings.Join(*v, ",") }
func (v *values) Set(value string) error {
	*v = append(*v, value)
	return nil
}

type providerQuery struct{ provider, expression string }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "scopequery:", err)
		os.Exit(1)
	}
}

func run() error {
	var fofaQueries, quakeQueries, driftnetQueries values
	var scopes, scopeFiles values
	var format string
	var limit, timeout int
	var allowAll bool
	flag.Var(&fofaQueries, "fofa-query", "FOFA query (repeatable)")
	flag.Var(&quakeQueries, "quake-query", "360 Quake query (repeatable)")
	flag.Var(&driftnetQueries, "driftnet-query", "Driftnet expression, IP, or CIDR (repeatable)")
	flag.Var(&scopes, "scope", "allowed domain, IP, or CIDR (repeatable)")
	flag.Var(&scopeFiles, "scope-file", "file containing allowed scopes, one per line")
	flag.StringVar(&format, "format", "hostport", "output format: hostport, host, url, or jsonl")
	flag.IntVar(&limit, "limit", 100, "maximum results per query")
	flag.IntVar(&timeout, "timeout", 20, "HTTP timeout in seconds")
	flag.BoolVar(&allowAll, "allow-all", false, "disable scope filtering (use only with explicit authorization)")
	flag.Parse()

	if format != "hostport" && format != "host" && format != "url" && format != "jsonl" {
		return fmt.Errorf("invalid format %q", format)
	}
	if limit <= 0 || timeout <= 0 {
		return errors.New("limit and timeout must be greater than zero")
	}
	for _, path := range scopeFiles {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read scope file: %w", err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if line != "" {
				scopes = append(scopes, line)
			}
		}
	}
	allowlist, err := scopequery.NewScope(scopes)
	if err != nil {
		return err
	}
	if allowlist.Empty() && !allowAll {
		return errors.New("at least one --scope or --scope-file is required (or explicitly use --allow-all)")
	}

	queries := make([]providerQuery, 0, len(fofaQueries)+len(quakeQueries)+len(driftnetQueries))
	for _, query := range fofaQueries {
		queries = append(queries, providerQuery{"fofa", query})
	}
	for _, query := range quakeQueries {
		queries = append(queries, providerQuery{"quake", query})
	}
	for _, query := range driftnetQueries {
		queries = append(queries, providerQuery{"driftnet", query})
	}
	if len(queries) == 0 {
		return errors.New("at least one provider query is required")
	}

	keys := map[string]string{
		"fofa":     firstEnv("FOFA_API_KEY", "FOFA_KEY"),
		"quake":    firstEnv("QUAKE_TOKEN", "QUAKE_API_KEY"),
		"driftnet": os.Getenv("DRIFTNET_API_KEY"),
	}
	searcher := scopequery.NewSearcher(time.Duration(timeout) * time.Second)
	seen := make(map[string]struct{})
	var failures int
	for _, query := range queries {
		results, err := searcher.Search(context.Background(), query.provider, query.expression, keys[query.provider], limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", query.provider, err)
			failures++
			continue
		}
		for _, result := range results {
			if !allowAll {
				var allowed bool
				result, allowed = allowlist.Filter(result)
				if !allowed {
					continue
				}
			}
			target := result.Target("hostport")
			if target == "" {
				continue
			}
			if _, ok := seen[target]; ok {
				continue
			}
			var output string
			if format == "jsonl" {
				payload := struct {
					scopequery.Result
					Target string `json:"target"`
				}{Result: result, Target: target}
				encoded, _ := json.Marshal(payload)
				output = string(encoded)
			} else {
				output = result.Target(format)
			}
			seen[target] = struct{}{}
			fmt.Println(output)
		}
	}
	if failures == len(queries) {
		return errors.New("all provider queries failed")
	}
	return nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}
