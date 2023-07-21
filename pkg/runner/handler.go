package runner

import (
	"bufio"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/pathScan/pkg/common/uncover"
	ucRunner "github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/runner"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
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

var defaultUserAgents = []string{
	"Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
	"Mozilla/5.0 (Linux;u;Android 4.2.2;zh-cn;) AppleWebKit/534.46 (KHTML,like Gecko)Version/5.1 Mobile Safari/10600.6.3 (compatible; Baiduspider/2.0;+http://www.baidu.com/search/spider.html)",
	"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	"Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)",
	"Mozilla/5.0 (iPhone;CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko)Version/9.0 Mobile/13B143 Safari/601.1 (compatible; Baiduspider-render/2.0;Smartapp; +http://www.baidu.com/search/spider.html)",
}

func (r *Runner) handlerHeader() map[string]interface{} {
	headerMap := make(map[string]interface{})

	if len(r.Cfg.Options.UserAgent) > 0 {
		headerMap[HeaderKeyUserAgent] = r.Cfg.Options.UserAgent
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
		headerMap[HeaderKeyUserAgent] = defaultUserAgents
	}

	return headerMap
}

func (r *Runner) handlerGetTargetPath() map[string]struct{} {
	at := make(map[string]struct{})

	// 处理 Path 和 PathFile
	addPathsToSet(r.Cfg.Options.Path, at)
	addPathsToSet(r.Cfg.Options.PathFile, at)
	// 处理 PathRemote
	if r.Cfg.Options.PathRemote != "" {
		resp, err := r.client.Get(r.Cfg.Options.PathRemote)
		if err != nil {
			gologger.Warning().Msgf("从远程加载字典失败: %s", err)
		} else {
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					gologger.Warning().Msgf("关闭响应体失败: %s", err)
				}
			}(resp.Body)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				gologger.Warning().Msgf("读取响应体失败：%s", err)
			} else {
				for _, p := range strings.Split(string(body), "\n") {
					p = strings.TrimSpace(p)
					if p == "" {
						continue
					}
					at[p] = struct{}{}
				}
				gologger.Debug().Msg("从远程加载字典完成")
			}
		}
	}

	// 如果未指定路径，则处理默认文件名
	if len(at) == 0 && len(r.targets) == 1 && r.Cfg.Options.Path == nil && r.Cfg.Options.PathFile == nil {
		u := r.handlerGetFilePath("main.txt")
		if u != nil {
			addPathsToSet(u, at)
		}
	}
	// 如果没有添加任何路径，则将根目录添加到结果中
	if len(at) == 0 {
		at["/"] = struct{}{}
	}

	return at
}

// 辅助函数：将路径列表添加到集合中
func addPathsToSet(pathList []string, pathSet map[string]struct{}) {
	for _, p := range pathList {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// 统一 path 前有 /
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		pathSet[p] = struct{}{}

	}
}

func (r *Runner) handlerGetFilePath(filename string) []string {

	path := util.DataRoot("dict", filename)
	out, err := fileutil.ReadFile(path)
	if err != nil {
		return nil
	}
	var str []string
	for o := range out {
		str = append(str, o)
	}
	return str
}

func (r *Runner) handlerGetTargets() map[string]struct{} {
	at := make(map[string]struct{})
	// 处理 Url 和 UrlFile
	r.addUrlsToSet(r.Cfg.Options.Url, at)
	r.addUrlsToSet(r.Cfg.Options.UrlFile, at)

	// 处理 UrlRemote
	if r.Cfg.Options.UrlRemote != "" {
		resp, err := http.Get(r.Cfg.Options.UrlRemote)
		if err != nil {
			gologger.Warning().Msgf("从远程加载 URL 列表失败：%s", err)
		} else {
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					gologger.Warning().Msgf("关闭响应体失败: %s", err)
				}
			}(resp.Body)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				gologger.Warning().Msgf("读取响应体失败：%s", err)
			} else {
				for _, u := range strings.Split(string(body), "\n") {
					u = strings.TrimSpace(u)
					if u == "" {
						continue
					}
					r.addUrlToSet(u, at)
				}
				gologger.Debug().Msg("从远程加载 URL 列表完成")
			}
		}
	}

	// 处理从标准输入读取的 URL
	if r.Cfg.Options.Silent && fileutil.HasStdin() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			u := strings.TrimSpace(s.Text())
			if u == "" {
				continue
			}
			r.addUrlToSet(u, at)
		}
		os.Stdin.Close()
	}

	// 处理 Uncover 引擎查找到的 URL
	if r.Cfg.Options.Uncover && r.Cfg.Options.UncoverQuery != nil {
		if r.Cfg.Options.UncoverEngine == nil {
			r.Cfg.Options.UncoverEngine = []string{"quake", "fofa"}
		}
		gologger.Info().Msgf("正在运行: %s", strings.Join(r.Cfg.Options.UncoverEngine, ","))
		ch, err := uncover.GetTargetsFromUncover(r.Cfg.Options.UncoverDelay, r.Cfg.Options.UncoverLimit, r.Cfg.Options.UncoverField, r.Cfg.Options.UncoverOutput, r.Cfg.Options.Csv, r.Cfg.Options.UncoverEngine, r.Cfg.Options.UncoverQuery, r.Cfg.Options.Proxy, r.Cfg.Options.ProxyAuth)
		if err != nil {
			gologger.Error().Label("WRN").Msg(err.Error())
		} else {
			for c := range ch {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				r.addUrlToSet(c, at)
			}
		}
	}
	// 从结果中删除 SkipUrl 指定的 URL
	for _, skip := range r.Cfg.Options.SkipUrl {
		delete(at, skip)
	}

	return at
}

// 辅助函数：将 URL 列表添加到集合中
func (r *Runner) addUrlsToSet(urlList []string, urlSet map[string]struct{}) {
	for _, u := range urlList {
		u = strings.TrimSpace(u)
		if u != "" {
			r.addUrlToSet(u, urlSet)
		}
	}
}
func (r *Runner) addUrlToSet(u string, urlSet map[string]struct{}) {
	u = strings.TrimSpace(u)
	if !((strings.HasPrefix(u, "http") && !strings.HasSuffix(u, "https")) || (strings.HasPrefix(u, "https") && !strings.HasSuffix(u, "http"))) {
		u1 := "http://" + u
		u2 := "https://" + u
		r.addUrlToSet(u1, urlSet)
		r.addUrlToSet(u2, urlSet)
	} else {
		// 统一后缀无 /
		if strings.HasSuffix(u, "/") {
			u = strings.TrimRight(u, "/")
		}
		urlSet[u] = struct{}{}
	}

}

func InitPathScan() error {
	if fileutil.FileExists(filepath.Join(defaultPathScanDir, ".check")) {
		return nil
	}
	gologger.Info().Msg("正在进行初始化....")
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
	gologger.Info().Msg("初始化完成....")
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
		if err := fileutil.Marshal(fileutil.YAML, []byte(defaultProviderConfigLocation), ucRunner.Provider{}); err != nil {
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
