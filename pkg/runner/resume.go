package runner

import (
	"encoding/json"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type ResumeCfg struct {
	Rwm           *sync.RWMutex
	Options       *Options `json:"options"`
	ResultsCached *Cached  `json:"results-cached"`
	OutputCached  *Cached  `json:"output-cached"`
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
		_ = os.MkdirAll(DefaultResumeFolderPath(), os.ModePerm)
	}
	return os.WriteFile(DefaultResumeFilePath(filename), data, os.ModePerm)
}
func (cfg *ResumeCfg) CleanupResumeConfig() {
	if fileutil.FileExists(cfg.Options.ResumeCfg) {

		_ = os.Remove(cfg.Options.ResumeCfg)
	}
}
func (cfg *ResumeCfg) ClearResume() {
	_ = os.Remove(cfg.Options.ResumeCfg)
	dir, err := os.ReadDir(defaultResume)
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
	// t > 5MB
	if t >= 5242880 {
		builder := strings.Builder{}
		if !cfg.Options.NoColor {
			builder.WriteString(aurora.Yellow("WRN").String())
		} else {
			builder.WriteString("WRN")
		}
		gologger.Info().Label(builder.String()).Msgf("%s is already greater than 5MB, please use - clear to clean", defaultResume)
	}
}
