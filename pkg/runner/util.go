package runner

import (
	"bytes"
	"fmt"
	"github.com/projectdiscovery/fileutil"
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
	err = fileutil.CreateFolder(path)
	if err != nil {

		return fmt.Errorf("打开 %s 出错:%s\n", path, err.Error())
	}

	url := "https://github.com/wjlin0/pathScan/releases/download/v" + Version + "/dict.zip"
	resp, err := http.Get(url)

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

	return nil
}
func randShuffle(slice []string) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
}
