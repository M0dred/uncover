package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Runner is an instance of the uncover enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options      *Options
	service      *uncover.Service
	outputWriter *OutputWriter
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	if err := validateExecutionControls(options); err != nil {
		return nil, err
	}
	runner := &Runner{options: options}
	appendAllQueries(options)
	rateLimit, rateLimitUnit, err := runnerRateLimit(options)
	if err != nil {
		return nil, err
	}

	opts := uncover.Options{
		Agents:        options.Engine,
		Queries:       options.Query,
		Limit:         options.Limit,
		MaxRetry:      options.Retries,
		Timeout:       options.Timeout,
		RateLimit:     rateLimit,
		RateLimitUnit: rateLimitUnit,
		Proxy:         options.Proxy,
	}
	service, err := uncover.New(&opts)
	if err != nil {
		return nil, err
	}
	runner.service = service

	runner.outputWriter, err = NewOutputWriter()
	if err != nil {
		return nil, err
	}

	if !options.Verbose {
		runner.outputWriter.AddWriters(os.Stdout)
	}
	if runner.options.OutputFile != "" {
		outputFile, err := os.OpenFile(runner.options.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, errorutil.New("could not create output file %s: %s", options.OutputFile, err)
		}
		runner.outputWriter.AddWriters(outputFile)
	}
	return runner, nil
}

func runnerRateLimit(options *Options) (uint, time.Duration, error) {
	if options == nil {
		return 0, 0, errors.New("options cannot be nil")
	}
	if options.RateLimit < 0 || options.RateLimitMinute < 0 {
		return 0, 0, errors.New("rate limits cannot be negative")
	}
	if options.RateLimit > 0 && options.RateLimitMinute > 0 {
		return 0, 0, errors.New("rate-limit and rate-limit-minute are mutually exclusive")
	}
	if options.RateLimitMinute > 0 {
		return uint(options.RateLimitMinute), time.Minute, nil
	}
	if options.RateLimit > 0 {
		return uint(options.RateLimit), time.Second, nil
	}
	return 0, 0, nil
}

func validateExecutionControls(options *Options) error {
	if options == nil {
		return errors.New("options cannot be nil")
	}
	if options.Timeout <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	if options.Retries < 0 {
		return errors.New("retry cannot be negative")
	}
	if options.Limit < 0 {
		return errors.New("limit cannot be negative")
	}
	_, _, err := runnerRateLimit(options)
	return err
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context) error {
	resultCallback := func(result sources.Result) {
		optionFields := r.options.OutputFields
		switch {
		case result.Error != nil:
			gologger.Warning().Label(result.Source).Msgf("%s\n", result.Error.Error())
		case r.options.JSON:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.JSON())
			r.outputWriter.WriteJsonData(result)
		case r.options.Raw:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.RawData())
			r.outputWriter.WriteString(result.RawData())
		default:
			port := fmt.Sprint(result.Port)
			replacer := strings.NewReplacer(
				"ip", result.IP,
				"host", result.Host,
				"port", port,
				"url", result.Url,
			)
			if (result.IP == "" || port == "0") && stringsutil.ContainsAny(r.options.OutputFields, "ip", "port") {
				optionFields = "host"
			}
			outData := replacer.Replace(optionFields)
			searchFor := []string{result.IP, port}
			if result.Host != "" || r.options.OutputFile != "" {
				searchFor = append(searchFor, result.Host)
			}
			if stringsutil.ContainsAny(outData, searchFor...) && !r.outputWriter.findDuplicate(outData, false) {
				if r.options.Verbose {
					gologger.Info().Label(result.Source).Msg(outData)
				}
				r.outputWriter.WriteString(outData)
			}
		}
	}
	return r.service.ExecuteWithCallback(ctx, resultCallback)
}

// Close closes its resources
func (r *Runner) Close() {
	if r.service != nil {
		r.service.Close()
	}
	if r.outputWriter != nil {
		r.outputWriter.Close()
	}
}
