package runner

import (
	"fmt"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"github.com/wjlin0/uncover"
)

const (
	defaultThread         = 50
	defaultHTTPTimeout    = 15
	defaultRateLimit      = -1
	defaultRetries        = 0
	defaultUncoverLimit   = 100
	defaultSubdomainLimit = 1000
)

func DefaultOptions(options *types.Options) {
	if options.Thread <= 0 {
		options.Thread = defaultThread
	}
	if options.MatchPath == "" {
		options.MatchPath = DefaultMatchDir

	}
	if options.Method == nil || len(options.Method) == 0 {
		options.Method = []string{"GET"}
	}
	if options.HttpTimeout <= 0 {
		options.HttpTimeout = defaultHTTPTimeout
	}
	if options.RateLimit <= 0 {
		options.RateLimit = defaultRateLimit
	}
	if options.RetryMax < 0 {
		options.RetryMax = defaultRetries
	}
	if options.UncoverLimit == 0 {
		options.UncoverLimit = defaultUncoverLimit
	}
	if options.SubdomainLimit == 0 {
		options.SubdomainLimit = defaultSubdomainLimit
	}

	if options.GetHash && options.SkipHashMethod == "" {
		options.SkipHashMethod = "sha256"
	}

	if options.SkipHash != "" && options.SkipHashMethod == "" {
		options.SkipHashMethod = "sha256"
	}
	// uncover
	if len(options.UncoverEngine) == 0 && len(options.UncoverQuery) > 0 {
		options.UncoverEngine = []string{"quake"}
	}

	if len(options.UncoverEngine) > 0 && len(options.UncoverQuery) > 0 {
		options.Uncover = true
	}
	if options.Uncover && options.IsPathEmpty() {
		options.Path = []string{"/"}
	}

	// subdomain
	if len(options.SubdomainEngine) == 0 && len(options.SubdomainQuery) > 0 {
		options.SubdomainEngine = uncover.AllAgents()
	}
	if len(options.SubdomainEngine) > 0 && len(options.SubdomainQuery) > 0 {
		options.Subdomain = true
	}
	if options.Subdomain && options.IsPathEmpty() {
		options.Path = []string{"/"}
	}

	if options.Subdomain {
		options.FindOtherDomain = true
	}

	uncover.DefaultCallback = func(query string, agent string) string {
		if !util.IsValidDomain(query) {
			return query
		}
		switch agent {
		case "fofa":
			return fmt.Sprintf(`domain="%s"`, query)
		case "hunter":
			return fmt.Sprintf(`domain.suffix="%s"`, query)
		case "quake":
			return fmt.Sprintf(`domain:"%s"`, query)
		case "zoomeye":
			return fmt.Sprintf(`site:%s`, query)
		case "netlas":
			return fmt.Sprintf(`domain:%s`, query)
		case "daydaymap":
			return fmt.Sprintf(`domain="%s"`, query)
		case "fofa-spider":
			return fmt.Sprintf(`domain="%s"`, query)
		case "zoomeye-spider":
			return fmt.Sprintf(`site:%s`, query)
		default:
			return query
		}
	}
}
