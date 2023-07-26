package runner

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"github.com/google/go-github/github"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	retryableHttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
	"github.com/wjlin0/pathScan/pkg/util"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
func DownloadDict() error {
	home, err := os.UserHomeDir()
	if err != nil {

		return fmt.Errorf("打开主目录时出错：%s\n", err.Error())
	}
	path := filepath.Join(home, ".config", "pathScan", "dict")
	if fileutil.FileExists(filepath.Join(path, ".check")) {
		gologger.Info().Msgf("远程字典下载成功->%s", path)
		return nil
	}
	gologger.Info().Msg("本地不存在字典,正在下载...")
	err = fileutil.CreateFolder(path)
	if err != nil {

		return fmt.Errorf("打开 %s 出错:%s\n", path, err.Error())
	}

	dictUrl := "https://raw.githubusercontent.com/wjlin0/pathScan/main/config/dict.zip"

	client := retryableHttp.DefaultClient()
	resp, err := client.Get(dictUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, resp.Body)
	if err != nil {

		return fmt.Errorf("下载 %s 文件出错: %s\n", dictUrl, err.Error())
	}
	reader := bytes.NewReader(buffer.Bytes())
	err = util.Unzip(path, reader)
	if err != nil {
		return fmt.Errorf("解压出错: %s\n", err.Error())
	}
	gologger.Info().Msgf("远程字典下载成功->%s", path)
	return nil
}
func CheckVersion() error {
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
		return err
	}
	if len(releases) != 0 {
		gologger.Error().Label("OUT").Msgf("你的版本( v%s )较低. 最新为 %s", Version, releases[0].Version)
	} else {
		gologger.Info().Msgf("Current pathScan version: %s %s", Version, fmt.Sprintf("(%s)", aurora.Colorize("latest", aurora.GreenFg|aurora.BrightFg).String()))

	}
	return nil

}
func CheckMatchVersion() error {
	var command string
	switch runtime.GOOS {
	case "windows":
		command = "pathScan.exe"
	default:
		command = "pathScan"
	}
	open, err := os.Open(filepath.Join(defaultMatchDir, ".version"))
	if err != nil {
		return err
	}
	defer open.Close()
	scanner := bufio.NewScanner(open)
	var version string
	if scanner.Scan() {
		// 获取第一行的内容
		version = scanner.Text()
	} else {
		return nil
	}
	m := &update.Manager{
		Command: command,
		Store: &githubUpdateStore.Store{
			Owner:   "wjlin0",
			Repo:    "pathScan-match",
			Version: version,
		},
	}
	releases, err := m.LatestReleases()
	if err != nil {
		return err
	}
	if len(releases) != 0 {
		gologger.Error().Label("OUT").Msgf("pathScan-match 版本( %s )较低. 最新为 %s", version, releases[0].Version)
	} else {
		gologger.Info().Msgf("Current pathScan-match version: %s %s", version, fmt.Sprintf("(%s)", aurora.Colorize("latest", aurora.GreenFg|aurora.BrightFg).String()))
	}
	return nil

}
