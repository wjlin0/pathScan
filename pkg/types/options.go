package types

import (
	"github.com/projectdiscovery/goflags"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/pathScan/v2/pkg/input"
	"github.com/wjlin0/pathScan/v2/pkg/output"
)

type Options struct {
	URL                 goflags.StringSlice             `json:"url"`
	List                goflags.StringSlice             `json:"list"`
	Path                goflags.StringSlice             `json:"path"`
	PathList            goflags.StringSlice             `json:"path-list"`
	Subdomain           bool                            `json:"subdomain"`
	Output              string                          `json:"output"`
	RateLimit           int                             `json:"rate-http"`
	Thread              int                             `json:"thread"`
	RetryMax            int                             `json:"retries"`
	Proxy               goflags.StringSlice             `json:"proxy"`
	NoColor             bool                            `json:"no-color"`
	Verbose             bool                            `json:"verbose"`
	Silent              bool                            `json:"silent"`
	SkipURL             goflags.StringSlice             `json:"skip-url"`
	SkipCode            goflags.StringSlice             `json:"skip-code"`
	SkipHash            string                          `json:"skip-hash"`
	SkipBodyLen         goflags.StringSlice             `json:"skip-body-len"`
	SkipHashMethod      string                          `json:"skip-hash-method"`
	ErrUseLastResponse  bool                            `json:"err-use-last-response"`
	CSV                 bool                            `json:"csv,omitempty"`
	HTML                bool                            `json:"html,omitempty"`
	Version             bool                            `json:"version"`
	Uncover             bool                            `json:"uncover"`
	UncoverQuery        goflags.StringSlice             `json:"uncover-query"`
	UncoverEngine       goflags.StringSlice             `json:"uncover-engine"`
	UncoverDelay        int                             `json:"uncover-delay"`
	UncoverLimit        int                             `json:"uncover-limit"`
	UncoverField        string                          `json:"uncover-field"`
	UncoverOutput       string                          `json:"uncover-output"`
	Update              bool                            `json:"update"`
	UserAgent           goflags.StringSlice             `json:"user-agent"`
	Cookie              string                          `json:"cookie"`
	Authorization       string                          `json:"authorization"`
	Header              goflags.StringSlice             `json:"header"`
	HttpTimeout         int                             `json:"http-timeout"`
	UpdateMatch         bool                            `json:"update-match-version"`
	Method              goflags.StringSlice             `json:"method"`
	MatchPath           string                          `json:"match-path"`
	GetHash             bool                            `json:"get-hash"`
	FindOtherDomainList goflags.StringSlice             `json:"find-other-domain-list"`
	ResultEventCallback func(result output.ResultEvent) `json:"-"`
	Body                string                          `json:"body"`
	FindOtherDomain     bool                            `json:"find-other-domain"`
	DisableStdin        bool                            `json:"disable-stdin"`
	DisableUpdateCheck  bool                            `json:"disable-update-check"`
	DisableScanMatch    bool                            `json:"disable-scan-match"`
	SubdomainLimit      int                             `json:"subdomain-limit"`
	SubdomainQuery      goflags.StringSlice             `json:"subdomain-query"`
	SubdomainEngine     goflags.StringSlice             `json:"subdomain-engine"`
	SubdomainOutput     string                          `json:"subdomain-output"`
	Resolvers           goflags.StringSlice             `json:"resolvers"`
	SkipBodyRegex       goflags.StringSlice             `json:"skip-body-regex"`
	LoadDefaultDict     bool                            `json:"load-default-dict"`
	LoadAPIDict         bool                            `json:"load-api-dict"`
	Debug               bool                            `json:"debug"`
	Validate            bool                            `json:"validate"`
	Stdin               bool                            `json:"stdin"`
	URLs                []*input.Target
	DisableAliveCheck   bool `json:"skip-alive-check"`
}

var DefaultOptions = &Options{
	RateLimit:      100,
	Thread:         30,
	HttpTimeout:    15,
	RetryMax:       0,
	UncoverLimit:   100,
	SubdomainLimit: 1000,
	Method:         []string{"GET"},
	Stdin:          fileutil.HasStdin(),
	Path:           []string{"/"},
}

func (o *Options) CountURL() int {
	return len(o.URL) + len(o.List)
}

func (o *Options) SkipOutputIsEmpty() bool {
	return len(o.SkipCode) == 0 && len(o.SkipBodyRegex) == 0 && len(o.SkipBodyLen) == 0 && len(o.SkipHash) == 0
}

func (o *Options) OutputType() string {
	if o.CSV {
		return "csv"
	}

	return "txt"

}

func (o *Options) IsPathEmpty() bool {
	return len(o.Path) == 0 && len(o.PathList) == 0 && !o.LoadDefaultDict && !o.LoadAPIDict
}
