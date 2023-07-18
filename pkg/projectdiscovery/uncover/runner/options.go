package runner

import (
	"time"

	"github.com/projectdiscovery/goflags"
)

// Options contains the configuration options for tuning the enumeration process.
type Options struct {
	Query        goflags.StringSlice
	Engine       goflags.StringSlice
	ConfigFile   string
	ProviderFile string
	OutputFile   string
	OutputFields string
	JSON         bool
	Raw          bool
	Limit        int
	Silent       bool
	Version      bool
	Verbose      bool
	NoColor      bool
	Timeout      int
	Delay        int
	delay        time.Duration
	Provider     *Provider
	Retries      int
	Shodan       goflags.StringSlice
	ShodanIdb    goflags.StringSlice
	Fofa         goflags.StringSlice
	Censys       goflags.StringSlice
	Quake        goflags.StringSlice
	Netlas       goflags.StringSlice
	Hunter       goflags.StringSlice
	ZoomEye      goflags.StringSlice
	CriminalIP   goflags.StringSlice
}
