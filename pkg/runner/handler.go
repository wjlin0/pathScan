package runner

import (
	"bufio"
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
	"sync"
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
func (r *Runner) handlerGetTargetPath() (map[string]struct{}, error) {
	at := make(map[string]struct{})
	protocol := "path"
	// 处理 Path 和 PathFile
	for _, path := range append(r.Cfg.Options.Path, r.Cfg.Options.PathFile...) {
		util.AddStrToMap(path, at, protocol)
	}
	// 处理 PathRemote
	if r.Cfg.Options.PathRemote != "" {
		resp, err := r.client.Get(r.Cfg.Options.PathRemote)
		if err != nil {
			return nil, fmt.Errorf("从远程加载字典失败: %s", err)
		}
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			path := strings.TrimSpace(scanner.Text())
			if path != "" {
				util.AddStrToMap(path, at, protocol)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read response body：%s", err)
		}
		gologger.Debug().Msg("Completing remote loading of URL list")

	}

	// 如果未指定路径，则处理默认文件名
	if len(at) == 0 && len(r.targets_) == 1 && r.Cfg.Options.Path == nil && r.Cfg.Options.PathFile == nil {
		out, err := fileutil.ReadFile(filepath.Join(defaultPathDict, "main.txt"))
		if err != nil {
			return nil, err
		}
		for path := range out {
			util.AddStrToMap(path, at, protocol)
		}
	}
	// 如果没有添加任何路径，则将根目录添加到结果中
	if len(at) == 0 {
		at["/"] = struct{}{}
	}

	return at, nil
}

func (r *Runner) handlerGetTargets() (map[string]struct{}, error) {
	at := make(map[string]struct{})
	protocol := "url"
	// 处理 Url 和 UrlFile
	for _, url := range append(r.Cfg.Options.Url, r.Cfg.Options.UrlFile...) {
		util.AddStrToMap(url, at, protocol)
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
				util.AddStrToMap(url, at, protocol)
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
				util.AddStrToMap(u, at, protocol)
			}

		}
		os.Stdin.Close()
	}

	// 从结果中删除 SkipUrl 指定的 URL
	for _, skip := range r.Cfg.Options.SkipUrl {
		delete(at, skip)
	}
	return at, nil
}
func InitPathScan() error {
	if fileutil.FileExists(filepath.Join(defaultPathScanDir, ".check")) {
		return nil
	}
	gologger.Info().Msg("Initializing in progress.")
	var err error
	err = InitJs()
	if err != nil {
		return err
	}
	err = InitConfig()
	if err != nil {
		return err
	}
	err = InitMatch()
	if err != nil {
		return err
	}
	err = InitPathDict()
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
func InitJs() error {
	if fileutil.FileExists(filepath.Join(defaultJsDir, ".check")) {
		return nil
	}
	if !fileutil.FolderExists(defaultJsDir) {
		err := fileutil.CreateFolders(defaultJsDir)
		if err != nil {
			return err
		}
	}
	MapDownloadPath := map[string][]string{
		"template": {
			filepath.Join(defaultJsDir, "template.html"), "https://raw.githubusercontent.com/wjlin0/pathScan/main/config/template.html",
		},
		"antdCss": {
			filepath.Join(defaultJsDir, "antd.min.css"), "https://unpkg.com/ant-design-vue@1.7.8/dist/antd.min.css",
		},
		"andJs": {
			filepath.Join(defaultJsDir, "antd.min.js"), "https://unpkg.com/ant-design-vue@1.7.8/dist/antd.min.js",
		},
		"vueJs": {
			filepath.Join(defaultJsDir, "vue.min.js"), "https://unpkg.com/vue@2.7.14/dist/vue.min.js",
		},
	}
	errChan := make(chan error)
	var wg sync.WaitGroup
	for _, v := range MapDownloadPath {
		wg.Add(1)
		go func(path, httppath string) {
			defer wg.Done()
			err := fileutil.DownloadFile(path, httppath)
			if err != nil {
				errChan <- err
			}
		}(v[0], v[1])
	}
	go func() {
		wg.Wait()
		close(errChan)
	}()
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	_, err := os.Create(filepath.Join(defaultJsDir, ".check"))
	if err != nil {
		return err
	}
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
func InitPathDict() error {
	if fileutil.FileExists(filepath.Join(defaultPathDict, ".check")) {
		return nil
	}
	err := DownloadDict()
	if err != nil {
		return err
	}
	_, err = os.Create(filepath.Join(defaultPathDict, ".check"))
	if err != nil {
		return err
	}
	return nil
}
