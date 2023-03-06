package runner

import (
	"bytes"
	"fmt"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (r *Runner) DownloadDict() error {
	home, err := os.UserHomeDir()
	if err != nil {

		return fmt.Errorf("打开主目录时出错：%s\n", err.Error())
	}
	path := filepath.Join(home, ".config", "pathScan", "dict", "v"+Version)
	if fileutil.FileExists(filepath.Join(path, ".check")) {
		return nil
	}
	gologger.Info().Msg("本地不存在字典,正在下载...")
	err = fileutil.CreateFolder(path)
	if err != nil {

		return fmt.Errorf("打开 %s 出错:%s\n", path, err.Error())
	}

	url := "https://github.com/wjlin0/pathScan/releases/download/v" + Version + "/dict.zip"
	request, err := http.NewRequest("GET", url, nil)
	r.client.CheckRedirect = nil
	resp, err := r.client.Do(request)
	if !r.Cfg.Options.ErrUseLastResponse {
		r.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	if err != nil {
		return fmt.Errorf("下载文件出错: %s\n", err.Error())
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {

		return fmt.Errorf("下载 %s 文件出错: %s\n", url, err.Error())
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
func randShuffle(slice []string) []string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
	return slice
}

func DataRoot(elem ...string) string {
	home, _ := os.UserHomeDir()
	var e []string
	home = filepath.Join(home, ".config", "pathScan")
	e = append(e, home)
	e = append(e, elem...)
	return filepath.Join(e...)
}
