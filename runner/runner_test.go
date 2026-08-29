package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRunnerForwardsExecutionControls(t *testing.T) {
	options := &Options{
		Engine:    []string{"crt"},
		Query:     []string{"example.com"},
		Limit:     25,
		Timeout:   17,
		Retries:   3,
		RateLimit: 7,
		Verbose:   true,
	}
	runner, err := NewRunner(options)
	require.NoError(t, err)
	t.Cleanup(runner.Close)

	require.Equal(t, 17, runner.service.Options.Timeout)
	require.Equal(t, 3, runner.service.Options.MaxRetry)
	require.Equal(t, uint(7), runner.service.Options.RateLimit)
	require.Equal(t, time.Second, runner.service.Options.RateLimitUnit)
	require.Equal(t, 3, runner.service.Session.RetryMax)
	require.Equal(t, 17*time.Second, runner.service.Session.Client.HTTPClient.Timeout)
	globalLimit, err := runner.service.Session.RateLimits.GetLimit("default")
	require.NoError(t, err)
	require.Equal(t, uint(7), globalLimit)
	providerLimit, err := runner.service.Session.RateLimits.GetLimit("crt")
	require.NoError(t, err)
	require.Equal(t, uint(1), providerLimit)
}

func TestRunnerRateLimitMinute(t *testing.T) {
	limit, unit, err := runnerRateLimit(&Options{RateLimitMinute: 90})
	require.NoError(t, err)
	require.Equal(t, uint(90), limit)
	require.Equal(t, time.Minute, unit)
}

func TestRunnerRateLimitRejectsConflictingFlags(t *testing.T) {
	_, _, err := runnerRateLimit(&Options{RateLimit: 1, RateLimitMinute: 60})
	require.ErrorContains(t, err, "mutually exclusive")
}

func TestNewRunnerRejectsInvalidExecutionControls(t *testing.T) {
	_, err := NewRunner(nil)
	require.ErrorContains(t, err, "options cannot be nil")
	_, err = NewRunner(&Options{Timeout: 0})
	require.ErrorContains(t, err, "timeout must be greater than zero")
	_, err = NewRunner(&Options{Timeout: 1, Retries: -1})
	require.ErrorContains(t, err, "retry cannot be negative")
	_, err = NewRunner(&Options{Timeout: 1, Limit: -1})
	require.ErrorContains(t, err, "limit cannot be negative")
}

func TestNewRunnerCreatesPrivateOutputFile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "assets.jsonl")
	runner, err := NewRunner(&Options{
		Engine:     []string{"crt"},
		Query:      []string{"example.com"},
		Limit:      1,
		Timeout:    2,
		OutputFile: outputPath,
		Verbose:    true,
	})
	require.NoError(t, err)
	runner.Close()

	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
