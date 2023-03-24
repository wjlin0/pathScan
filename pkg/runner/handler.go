package runner

import (
	"bufio"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/pathScan/pkg/common/uncover"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
		if p != "" {
			pathSet[p] = struct{}{}
		}
	}
}

func (r *Runner) handlerGetFilePath(filename string) []string {

	path := util.DataRoot("dict", "v"+Version, filename)
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
	addPathsToSet(r.Cfg.Options.Url, at)
	addPathsToSet(r.Cfg.Options.UrlFile, at)

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
		ch, err := uncover.GetTargetsFromUncover(r.Cfg.Options.UncoverDelay, r.Cfg.Options.UncoverLimit, r.Cfg.Options.UncoverField, r.Cfg.Options.UncoverOutput, r.Cfg.Options.Csv, r.Cfg.Options.UncoverEngine, r.Cfg.Options.UncoverQuery)
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
	if !strings.HasPrefix(u, "http") {
		u1 := "http://" + u
		u2 := "https://" + u
		r.addUrlToSet(u1, urlSet)
		r.addUrlToSet(u2, urlSet)
	} else {
		if !strings.HasSuffix(u, "/") {
			u, _ = url.JoinPath(u, "/")
		}
		urlSet[u] = struct{}{}
	}
}
