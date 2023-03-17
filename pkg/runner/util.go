package runner

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func (o *Options) DownloadDict() error {
	home, err := os.UserHomeDir()
	if err != nil {

		return fmt.Errorf("打开主目录时出错：%s\n", err.Error())
	}
	path := filepath.Join(home, ".config", "pathScan", "dict", "v"+Version)
	if fileutil.FileExists(filepath.Join(path, ".check")) {
		gologger.Info().Msgf("远程字典下载成功->%s", path)
		return nil
	}
	gologger.Info().Msg("本地不存在字典,正在下载...")
	err = fileutil.CreateFolder(path)
	if err != nil {

		return fmt.Errorf("打开 %s 出错:%s\n", path, err.Error())
	}

	dictUrl := "https://github.com/wjlin0/pathScan/releases/download/v" + Version + "/dict.zip"

	client := newClient(o, false)
	resp, err := client.Get(dictUrl)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)

	if err != nil {

		return fmt.Errorf("下载 %s 文件出错: %s\n", dictUrl, err.Error())
	}
	defer resp.Body.Close()
	reader := bytes.NewReader(body)
	err = util.Unzip(path, reader)
	if err != nil {
		return fmt.Errorf("解压出错: %s\n", err.Error())
	}
	gologger.Info().Msgf("远程字典下载成功->%s", path)
	time.Sleep(time.Second * 5)
	return nil
}

func (o *Options) UpdateVersion() (bool, error) {
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
	currentOS = strings.ToUpper(runtime.GOOS[:1]) + runtime.GOOS[1:]
	var currentArch string
	switch runtime.GOARCH {
	case "amd64":
		currentArch = "x86_64"
	default:
		currentArch = runtime.GOARCH
	}
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
	gologger.Info().Msgf("Successfully updated to Nuclei %s\n", latest.Version)
	return true, nil
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
		gologger.Info().Msgf("使用 pathScan v%s", Version)
	}
	return nil

}
