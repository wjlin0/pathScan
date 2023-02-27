package runner

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/wjlin0/pathScan/pkg/result"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
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
	data, err := json.Marshal(cfg)
	//data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	resumeFolderPath := DefaultResumeFolderPath()
	if !fileutil.FolderExists(resumeFolderPath) {
		_ = os.MkdirAll(DefaultResumeFolderPath(), 0644)
	}
	return os.WriteFile(DefaultResumeFilePath(filename), data, 0644)
}
func RandFileName(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
	for i := 0; i < length; i++ {
		result = append(result, bytes[rand.Intn(len(bytes))])
	}
	return string(result)
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
