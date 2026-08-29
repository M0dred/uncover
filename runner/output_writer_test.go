package runner

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestWriteJSONDataPreservesHostOnlyResults(t *testing.T) {
	writer, err := NewOutputWriter()
	require.NoError(t, err)

	var output bytes.Buffer
	writer.AddWriters(&output)
	writer.WriteJsonData(sources.Result{Source: "crt", Host: "api.example.com"})
	writer.WriteJsonData(sources.Result{Source: "crt", Host: "WWW.EXAMPLE.COM."})
	writer.WriteJsonData(sources.Result{Source: "crt", Host: "www.example.com"})

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], `"host":"api.example.com"`)
	require.Contains(t, lines[1], `"host":"WWW.EXAMPLE.COM."`)
}

func TestWriteJSONDataPreservesVirtualHostsOnSameService(t *testing.T) {
	writer, err := NewOutputWriter()
	require.NoError(t, err)

	var output bytes.Buffer
	writer.AddWriters(&output)
	writer.WriteJsonData(sources.Result{Source: "one", IP: "192.0.2.1", Port: 443, Host: "a.example.com"})
	writer.WriteJsonData(sources.Result{Source: "two", IP: "192.0.2.1", Port: 443, Host: "b.example.com"})

	require.Len(t, strings.Split(strings.TrimSpace(output.String()), "\n"), 2)
}

func TestWriteJSONDataPreservesURLOnlyResults(t *testing.T) {
	writer, err := NewOutputWriter()
	require.NoError(t, err)

	var output bytes.Buffer
	writer.AddWriters(&output)
	writer.WriteJsonData(sources.Result{Source: "one", Url: "https://a.example.com/login"})
	writer.WriteJsonData(sources.Result{Source: "two", Url: "https://b.example.com/login"})

	require.Len(t, strings.Split(strings.TrimSpace(output.String()), "\n"), 2)
}

func TestOutputDeduplicationDoesNotExpireForLargeBatches(t *testing.T) {
	writer, err := NewOutputWriter()
	require.NoError(t, err)

	for i := 0; i < 4096; i++ {
		require.False(t, writer.findDuplicate(fmt.Sprintf("host-%d.example.com", i), true))
	}
	require.True(t, writer.findDuplicate("host-0.example.com", true))
}
