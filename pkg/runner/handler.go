package runner

import (
	"bufio"
	_ "embed"
	"fmt"
	"github.com/corpix/uarand"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/sources"
	"github.com/wjlin0/pathScan/pkg/util"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	HeaderKeyUserAgent     = "User-Agent"
	HeaderKeyCookie        = "Cookie"
	HeaderKeyAuthorization = "Authorization"
)

func (r *Runner) handlerHeader() map[string]interface{} {
	headerMap := make(map[string]interface{})

	if len(r.Cfg.Options.UserAgent) > 0 {
		headerMap[HeaderKeyUserAgent] = []string(r.Cfg.Options.UserAgent)
	}
	if r.Cfg.Options.Cookie != "" {
		headerMap[HeaderKeyCookie] = r.Cfg.Options.Cookie
	}
	if r.Cfg.Options.Authorization != "" {
		headerMap[HeaderKeyAuthorization] = r.Cfg.Options.Authorization
	}

	for _, header := range append(r.Cfg.Options.Header, r.Cfg.Options.HeaderFile...) {
		split := strings.SplitN(header, ":", 2)
		if len(split) == 2 {
			headerMap[strings.TrimSpace(split[0])] = strings.TrimSpace(split[1])
		}
	}

	if userAgent, ok := headerMap[HeaderKeyUserAgent]; !ok || len(userAgent.([]string)) == 0 {
		headerMap[HeaderKeyUserAgent] = uarand.UserAgents
	}
	headerMap["Accept-Charset"] = "utf-8"
	return headerMap
}

//go:embed dict/main.txt
var mainTxt string

//go:embed dict/api.txt
var apiTxt string

func (r *Runner) handlerGetTargetPath() ([]string, error) {
	opt := r.Cfg.Options
	var paths []string

	// 处理 Path 和 PathFile
	for _, path := range append(opt.Path, opt.PathFile...) {
		paths = append(paths, path)
	}
	// 处理 PathRemote
	if opt.PathRemote != "" {
		resp, err := r.client.Get(opt.PathRemote)
		if err != nil {
			return nil, fmt.Errorf("从远程加载字典失败: %s", err)
		}
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			path := strings.TrimSpace(scanner.Text())
			if path != "" {
				paths = append(paths, path)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read response body：%s", err)
		}
		gologger.Debug().Msg("Completing remote loading of URL list")

	}
	if opt.LoadAPIDict {
		for _, path := range strings.Split(apiTxt, "\n") {
			paths = append(paths, path)
		}
	}

	if opt.LoadDefaultDict {
		for _, path := range strings.Split(mainTxt, "\n") {
			paths = append(paths, path)
		}
	}

	// 如果未指定路径，则处理默认文件名
	if len(paths) == 0 && len(r.targets_) == 1 && opt.Path == nil && opt.PathFile == nil {
		for _, path := range strings.Split(mainTxt, "\n") {
			paths = append(paths, path)
		}
	}

	// 如果没有添加任何路径，则将根目录添加到结果中
	if len(paths) == 0 {
		paths = append(paths, "/")
	}
	return util.RemoveDuplicateAndEmptyStrings(paths), nil
}

func (r *Runner) handlerGetTargets() ([]string, error) {
	var targets []string
	// 处理 Url 和 UrlFile
	for _, url := range append(r.Cfg.Options.Url, r.Cfg.Options.UrlFile...) {
		targets = append(targets, url)
	}

	// 处理 UrlRemote
	if r.Cfg.Options.UrlRemote != "" {
		resp, err := http.Get(r.Cfg.Options.UrlRemote)
		if err != nil {
			return nil, fmt.Errorf("从远程加载 URL 列表失败：%s", err)
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" {
				targets = append(targets, url)

			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read response body：%s", err)
		}
		gologger.Info().Msg("Completing remote loading of URL list")
	}

	// 处理从标准输入读取的 URL
	if r.Cfg.Options.UrlChannel && fileutil.HasStdin() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			u := strings.TrimSpace(s.Text())
			if u != "" {
				targets = append(targets, u)
			}

		}
		os.Stdin.Close()
	}
	targets = util.RemoveDuplicateStrings(targets)
	for i, _ := range targets {
		if !strings.HasSuffix(targets[i], "/") {
			targets[i] = fmt.Sprintf("%s/", targets[i])
		}

	}
	return targets, nil
}
func InitPathScan() error {
	if fileutil.FileExists(filepath.Join(defaultPathScanDir, ".check")) {
		return nil
	}
	gologger.Info().Msg("Initializing in progress.")
	var err error
	err = InitConfig()
	if err != nil {
		return err
	}
	err = InitMatch()
	if err != nil {
		return err
	}
	_, err = os.Create(filepath.Join(defaultPathScanDir, ".check"))
	if err != nil {
		return err
	}
	gologger.Info().Msg("Initialization completed.")
	return nil
}

func InitMatch() error {
	if fileutil.FileExists(filepath.Join(defaultMatchDir, ".check")) {
		return nil
	}
	_, err := UpdateMatch()
	if err != nil {
		return err
	}
	_, err = os.Create(filepath.Join(defaultMatchDir, ".check"))
	if err != nil {
		return err
	}
	return nil
}
func InitConfig() error {
	// create default provider file if it doesn't exist
	if !fileutil.FileExists(defaultProviderConfigLocation) {
		if err := fileutil.Marshal(fileutil.YAML, []byte(defaultProviderConfigLocation), sources.Provider{}); err != nil {
			return err
		}
	}
	return nil
}
