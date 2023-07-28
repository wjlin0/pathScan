package runner

import (
	"github.com/projectdiscovery/gologger"
	folderutil "github.com/projectdiscovery/utils/folder"
	"path/filepath"
)

const (
	banner = `
               __   __    ____               
   ___  ___ _ / /_ / /   / __/____ ___ _ ___ 
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.3.0
/_/
`
	Version               = `1.3.0`
	defaultResumeFileName = `resume.cfg`
	userName              = "wjlin0"
	repoName              = "pathScan-match"
)

var (
	defaultPathScanDir            = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan")
	defaultMatchDir               = filepath.Join(defaultPathScanDir, "match-config")
	defaultJsDir                  = filepath.Join(defaultPathScanDir, "js")
	defaultPathDict               = filepath.Join(defaultPathScanDir, "dict")
	defaultProviderConfigLocation = filepath.Join(defaultPathScanDir, "provider-config.yaml")
	defaultRecursiveRunFile       = filepath.Join(defaultPathDict, "dir.txt")
	PathScanMatchVersion          = ""
)

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\t\twjlin0.com\n\n")
	gologger.Print().Msgf("慎用。你要为自己的行为负责\n")
	gologger.Print().Msgf("开发者不承担任何责任，也不对任何误用或损坏负责.\n")
}
