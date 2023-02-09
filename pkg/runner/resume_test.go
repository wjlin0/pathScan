package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestResumeCfg_MarshalResume(t *testing.T) {
	os.Args = []string{os.Args[0], "-u", "https://wjlin0.com/", "-uf", "url_text.txt", "-ps", "/api/user", "-pf", "dict_text.txt"}
	options := ParserOptions()
	cfg := &ResumeCfg{
		Rwm:     &sync.RWMutex{},
		Options: options,
	}
	filename := RandFileName(30) + ".cfg"
	fmt.Println(filepath.Join(DefaultResumeFolderPath(), filename))
	err := cfg.MarshalResume(filename)
	if err != nil {
		return
	}
}

func TestParserResumeCfg(t *testing.T) {
	cfg, err := ParserResumeCfg("C:\\Users\\wjl\\.config\\path-scan-go\\wtV20KhKfI9aqXP3ZgKcuVdFsVIA7S.cfg")
	if err != nil {
		return
	}
	fmt.Println(cfg)
}
