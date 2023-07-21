package runner

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
	"github.com/wjlin0/pathScan/pkg/util"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// downloadReleaseAndUnzip downloads and unzips the release in a directory
func downloadReleaseAndUnzip(ctx context.Context, path, downloadURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request to %s: %w", downloadURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download a release file from %s: %w", downloadURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download a release file from %s: Not successful status %d", downloadURL, res.StatusCode)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to create buffer for zip file: %w", err)
	}

	reader := bytes.NewReader(buf)
	_ = os.RemoveAll(path)
	zipReader, err := zip.NewReader(reader, reader.Size())
	err = util.Nunzip(path, zipReader)
	if err != nil {
		return fmt.Errorf("解压出错: %s\n", err.Error())
	}

	return nil
}

func getLatestReleaseFromGithub() (*github.RepositoryRelease, error) {
	var (
		gitHubClient *github.Client
		retried      bool
	)
	gitHubClient = getGHClientIncognito()
getRelease:
	release, _, err := gitHubClient.Repositories.GetLatestRelease(context.Background(), userName, repoName)
	if err != nil {
		// retry with authentication
		if gitHubClient = getGHClientWithToken(); gitHubClient != nil && !retried {
			retried = true
			goto getRelease
		}
		return nil, err
	}
	if release == nil {
		return nil, errors.New("no version found for the templates")
	}
	return release, nil
}
func getGHClientWithToken() *github.Client {
	if token, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		oauthClient := oauth2.NewClient(ctx, ts)
		return github.NewClient(oauthClient)
	}
	return nil
}
func getGHClientIncognito() *github.Client {
	var tc *http.Client
	return github.NewClient(tc)
}

func UpdateMatch() (bool, error) {
	fromGithub, err := getLatestReleaseFromGithub()
	if err != nil {
		return false, err
	}
	err = downloadReleaseAndUnzip(context.Background(), defaultMatchDir, *fromGithub.ZipballURL)
	if err != nil {
		return false, err
	}
	return true, nil
}
func UpdateVersion() (bool, error) {
	var command string
	switch runtime.GOOS {
	case "windows":
		command = "pathScan.exe"
	default:
		command = "pathScan"
	}
	m := &update.Manager{
		Command: command,
		Store: &githubUpdateStore.Store{
			Owner:   "wjlin0",
			Repo:    "pathScan",
			Version: Version,
		},
	}
	releases, err := m.LatestReleases()
	if err != nil {
		return false, errors.Wrap(err, "无法获取最新版本")
	}
	if len(releases) == 0 {
		gologger.Info().Msgf("已经为最新版本%v", Version)
		return true, nil
	}
	latest := releases[0]
	var currentOS string
	currentOS = strings.ToLower(runtime.GOOS[:1]) + runtime.GOOS[1:]
	currentArch := runtime.GOARCH
	final := latest.FindZip(currentOS, currentArch)
	if final == nil {
		return false, fmt.Errorf("no compatible binary found for %s/%s", currentOS, runtime.GOARCH)
	}
	tarball, err := final.DownloadProxy(progress.Reader)
	if err != nil {
		return false, errors.Wrap(err, "could not download latest release")
	}
	if err := m.Install(tarball); err != nil {
		return false, errors.Wrap(err, "could not install latest release")
	}
	gologger.Info().Msgf("Successfully updated to pathScan %s\n", latest.Version)
	return true, nil
}
