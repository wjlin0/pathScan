package runner

import (
	"bytes"
	"fmt"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	http "github.com/projectdiscovery/retryablehttp-go"
	"github.com/tj/go-update"
	githubUpdateStore "github.com/tj/go-update/stores/github"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

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

	client := http.DefaultClient()
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
		gologger.Info().Msgf("使用 pathScan v%s", Version)
	}
	return nil

}

func (o *Options) DownloadFile(mathConfigPath, url string) error {
	err := fileutil.CreateFolder(filepath.Dir(mathConfigPath))
	if err != nil {
		return fmt.Errorf("新建 %s 出错:%s\n", filepath.Dir(mathConfigPath), err.Error())
	}
	client := newClient(o, false)
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(mathConfigPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	gologger.Info().Msgf("远程文件下载成功-> %s", mathConfigPath)
	return nil
}
