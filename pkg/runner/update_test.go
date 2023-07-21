package runner

import (
	"fmt"
	folderutil "github.com/projectdiscovery/utils/folder"
	"golang.org/x/net/context"
	"path/filepath"
	"testing"
)

func TestGetLatestReleaseFromGithub(t *testing.T) {
	fmt.Println(getLatestReleaseFromGithub())
}
func TestDownloadReleaseAndUnzip(t *testing.T) {
	defaultMatchConfigDir := filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan", "match-config")
	err := downloadReleaseAndUnzip(context.Background(), defaultMatchConfigDir, "https://github.com/wjlin0/pathScan/releases/download/v1.1.4/dict.zip")
	if err != nil {
		t.Errorf("%s", err)
	}

}
