package sources

import (
	"encoding/json"
	"fmt"
	"net"
)

type Result struct {
	Timestamp int64  `json:"timestamp" csv:"timestamp"`
	Source    string `json:"source" csv:"source"`
	IP        string `json:"ip" csv:"IP"`
	Port      int    `json:"port" csv:"port"`
	Host      string `json:"host" csv:"host"`
	Url       string `json:"url" csv:"url"`
	Raw       []byte `json:"-" csv:"-"`
	Error     error  `json:"-" csv:"-"`
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
