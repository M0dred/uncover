package sources

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type Result struct {
	Timestamp int64      `json:"timestamp"`
	Source    string     `json:"source"`
	IP        string     `json:"ip"`
	Port      int        `json:"port"`
	Host      string     `json:"host"`
	Url       string     `json:"url"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	Raw       []byte     `json:"-"`
	Error     error      `json:"-"`
}

func (result *Result) IpPort() string {
	return net.JoinHostPort(result.IP, fmt.Sprint(result.Port))
}

func (result *Result) HostPort() string {
	return net.JoinHostPort(result.Host, fmt.Sprint(result.Port))
}

func (result *Result) RawData() string {
	return string(result.Raw)
}

func (result *Result) JSON() string {
	data, _ := json.Marshal(result)
	return string(data)
}
