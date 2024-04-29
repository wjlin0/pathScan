package runner

import (
	"github.com/projectdiscovery/gologger"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"path/filepath"
)

const (
	banner = `
               __   __    ____               
   ___  ___ _ / /_ / /   / __/____ ___ _ ___ 
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/
/_/
`
	Version               = `2.1.0`
	userName              = "wjlin0"
	pathScanMatchRepoName = "pathScan-match"
	pathScanRepoName      = "pathScan"
	toolName              = "pathScan"
)

var (
	DefaultPathScanDir            = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan")
	DefaultMatchDir               = filepath.Join(DefaultPathScanDir, "match-config")
	DefaultProviderConfigLocation = filepath.Join(DefaultPathScanDir, "provider-config.yaml")
	DefaultPathScanConfig         = filepath.Join(DefaultPathScanDir, "config.yaml")
	PathScanMatchVersion, _       = util.GetMatchVersion(DefaultMatchDir)
)

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\t\twjlin0.com\n\n")
	gologger.Print().Msgf("慎用。你要为自己的行为负责\n")
	gologger.Print().Msgf("开发者不承担任何责任，也不对任何误用或损坏负责.\n")
}
