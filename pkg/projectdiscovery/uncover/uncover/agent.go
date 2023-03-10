package uncover

import "github.com/projectdiscovery/ratelimit"

type AgentOptions struct {
	RateLimiter *ratelimit.Limiter
}

type Query struct {
	Query string
	Limit int
}

type Agent interface {
	Query(*Session, *Query) (chan Result, error)
	Name() string
}
