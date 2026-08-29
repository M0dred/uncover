package runner

import (
	"crypto/sha1"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/uncover/sources"
)

type OutputWriter struct {
	cache   map[[sha1.Size]byte]struct{}
	writers []io.Writer
	sync.RWMutex
}

func NewOutputWriter() (*OutputWriter, error) {
	return &OutputWriter{cache: make(map[[sha1.Size]byte]struct{})}, nil
}

func (o *OutputWriter) AddWriters(writers ...io.Writer) {
	o.writers = append(o.writers, writers...)
}

// Write writes the data taken as input using only
// the writer(s) with that name.
func (o *OutputWriter) Write(data []byte) {
	o.Lock()
	defer o.Unlock()

	for _, w := range o.writers {
		_, _ = w.Write(data)
		_, _ = w.Write([]byte("\n"))
	}
}

func (o *OutputWriter) findDuplicate(data string, markAsSeen bool) bool {
	o.Lock()
	defer o.Unlock()

	itemHash := sha1.Sum([]byte(data))
	if _, found := o.cache[itemHash]; found {
		return true
	}
	if markAsSeen {
		o.cache[itemHash] = struct{}{}
	}
	return false
}

// WriteString writes the string taken as input using only
func (o *OutputWriter) WriteString(data string) {
	if o.findDuplicate(data, true) {
		return
	}
	o.Write([]byte(data))
}

// WriteJsonData writes the result taken as input in JSON format
func (o *OutputWriter) WriteJsonData(data sources.Result) {
	if o.findDuplicate(resultIdentity(data), true) {
		return
	}
	o.Write([]byte(data.JSON()))
}

// resultIdentity returns the scan target represented by a result. Prefer URL
// and hostname identities over IP:port so virtual hosts on a shared address
// and host-only providers such as crt are not collapsed into one JSONL record.
func resultIdentity(data sources.Result) string {
	if targetURL := strings.TrimSpace(data.Url); targetURL != "" {
		return "url:" + targetURL
	}
	if host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(data.Host)), "."); host != "" {
		if data.Port > 0 {
			return "hostport:" + net.JoinHostPort(host, strconv.Itoa(data.Port))
		}
		return "host:" + host
	}
	if ip := strings.TrimSpace(data.IP); ip != "" {
		if data.Port > 0 {
			return "ipport:" + net.JoinHostPort(ip, strconv.Itoa(data.Port))
		}
		return "ip:" + ip
	}
	if len(data.Raw) > 0 {
		return "raw:" + string(data.Raw)
	}
	return "result:" + data.JSON()
}

// Close closes the output writers
func (o *OutputWriter) Close() {
	// Iterate over the writers and close the file writers
	for _, writer := range o.writers {
		if fileWriter, ok := writer.(*os.File); ok {
			if fileWriter == os.Stdout || fileWriter == os.Stderr {
				continue
			}
			_ = fileWriter.Close()
		}
	}
}
