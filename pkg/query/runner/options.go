package runner

import "time"

type Options struct {
	Engine  []string      `json:"engine"`
	Limit   int           `json:"limit,omitempty"`
	Delay   int           `json:"delay,omitempty"`
	Domains []string      `json:"domains,omitempty"`
	Proxy   string        `json:"proxy,omitempty"`
	Auth    string        `json:"auth,omitempty"`
	Retries int           `json:"retries"`
	Timeout time.Duration `json:"timeout"`
}
