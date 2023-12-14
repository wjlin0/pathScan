package runner

import (
	"github.com/projectdiscovery/gologger"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/wjlin0/pathScan/pkg/util"
	"path/filepath"
)

const (
	banner = `
               __   __    ____               
   ___  ___ _ / /_ / /   / __/____ ___ _ ___ 
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.5.1
/_/
`
	Version               = `1.5.1`
	defaultResumeFileName = `resume.cfg`
	userName              = "wjlin0"
	repoName              = "pathScan-match"
)
const (
	// HTTP defines the plain http scheme
	HTTP = "http"
	// HTTPS defines the secure http scheme
	HTTPS = "https"
	// HTTPorHTTPS defines both http and https scheme in mutual exclusion
	HTTPorHTTPS = "http|https"
	// HTTPandHTTPS defines both http and https scheme
	HTTPandHTTPS = "http&https"
)

var (
	defaultPathScanDir            = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan")
	defaultMatchDir               = filepath.Join(defaultPathScanDir, "match-config")
	defaultPathDict               = filepath.Join(defaultPathScanDir, "dict")
	defaultResume                 = filepath.Join(defaultPathScanDir, "resume")
	defaultProviderConfigLocation = filepath.Join(defaultPathScanDir, "provider-config.yaml")
	PathScanMatchVersion, _       = util.GetMatchVersion(defaultMatchDir)
)

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\t\twjlin0.com\n\n")
	gologger.Print().Msgf("慎用。你要为自己的行为负责\n")
	gologger.Print().Msgf("开发者不承担任何责任，也不对任何误用或损坏负责.\n")
}
