package runner

import (
	"encoding/json"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const defaultResumeFileName = `resume.cfg`

type ResumeCfg struct {
	Rwm     *sync.RWMutex
	Options *Options       `json:"options"`
	Results *result.Result `json:"results"`
}

func ParserResumeCfg(filename string) (*ResumeCfg, error) {
	cfg := &ResumeCfg{
		Rwm: &sync.RWMutex{},
	}

	if fileutil.FileExists(filename) {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("打开 %s 文件错误", filename))
		}
		err = json.Unmarshal(data, cfg)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("json格式错误 %s", filename))
		}
	} else {
		return nil, errors.New(fmt.Sprintf("文件 %s 不存在", filename))
	}

	return cfg, nil
}
func (cfg *ResumeCfg) MarshalResume(filename string) error {
	cfg.Rwm.Lock()
	defer cfg.Rwm.Unlock()
	//data, err := json.Marshal(cfg)
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	resumeFolderPath := DefaultResumeFolderPath()
	if !fileutil.FolderExists(resumeFolderPath) {
		_ = os.MkdirAll(DefaultResumeFolderPath(), 0644)
	}
	return os.WriteFile(DefaultResumeFilePath(filename), data, 0644)
}

func DefaultResumeFolderPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultResumeFileName
	}
	return filepath.Join(home, ".config", "pathScan", "resume")
}
func DefaultResumeFilePath(filename string) string {
	return filepath.Join(DefaultResumeFolderPath(), filename)
}
func (cfg *ResumeCfg) CleanupResumeConfig() {
	if fileutil.FileExists(cfg.Options.ResumeCfg) {

		_ = os.Remove(cfg.Options.ResumeCfg)
	}
}

func (cfg *ResumeCfg) ClearResume() {
	resumePath := util.DataRoot("resume")
	dir, err := os.ReadDir(resumePath)
	if err != nil {
		return
	}
	var t int64

	size := func() chan int64 {
		out := make(chan int64)
		go func() {
			defer close(out)
			for _, d := range dir {
				if d.IsDir() {
					continue
				}
				info, err := d.Info()
				if err != nil {
					continue
				}
				out <- info.Size()
			}
		}()
		return out
	}()

	for s := range size {
		t += s
	}
	// t > 50MB
	if t >= 52428800 {
		//_ = os.RemoveAll(DefaultResumeFolderPath())
		builder := strings.Builder{}
		if !cfg.Options.NoColor {
			builder.WriteString(aurora.Yellow(fmt.Sprintf("%s", DefaultResumeFolderPath())).String())
		} else {
			builder.WriteString(DefaultResumeFolderPath())
		}
		gologger.Info().Msg(builder.String() + " 已经大于100MB, 请使用 -clear 清理")
	}
}
