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

func (r *Runner) handlerHeader() map[string]interface{} {
	headerMap := make(map[string]interface{})
	if r.Cfg.Options.UserAgent != nil {
		headerMap["User-Agent"] = r.Cfg.Options.UserAgent
	}
	if r.Cfg.Options.Cookie != "" {
		headerMap["Cookie"] = r.Cfg.Options.Cookie
	}
	if r.Cfg.Options.Authorization != "" {
		headerMap["Authorization"] = r.Cfg.Options.Authorization
	}
	if r.Cfg.Options.Header != nil {
		for _, v := range r.Cfg.Options.Header {

			split := strings.Split(v, ":")
			if len(split) == 2 {
				headerMap[split[0]] = split[1]
			}
		}
	}
	if r.Cfg.Options.HeaderFile != nil {

		for _, v := range r.Cfg.Options.HeaderFile {
			split := strings.Split(v, ":")
			if len(split) == 2 {
				headerMap[split[0]] = split[1]
			}
		}
	}
	_, ok := headerMap["User-Agent"]
	if !ok {
		headerMap["User-Agent"] = []string{"Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5", "Mozilla/5.0 (Linux;u;Android 4.2.2;zh-cn;) AppleWebKit/534.46 (KHTML,like Gecko)Version/5.1 Mobile Safari/10600.6.3 (compatible; Baiduspider/2.0;+http://www.baidu.com/search/spider.html)", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)", "Mozilla/5.0 (iPhone;CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko)Version/9.0 Mobile/13B143 Safari/601.1 (compatible; Baiduspider-render/2.0;Smartapp; +http://www.baidu.com/search/spider.html)"}
	}

	return headerMap
}
func (r *Runner) handlerGetTargetPath() map[string]struct{} {
	at := make(map[string]struct{})
	var resp *http.Response
	var err error

	if r.Cfg.Options.Path != nil {
		for _, p := range r.Cfg.Options.Path {
			if _, ok := at[p]; !ok {
				p = strings.TrimSpace(p)
				at[p] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.PathFile != nil {
		for _, p := range r.Cfg.Options.PathFile {
			if _, ok := at[p]; !ok {
				p = strings.TrimSpace(p)
				at[p] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.PathRemote != "" {
		request, _ := http.NewRequest("GET", r.Cfg.Options.PathRemote, nil)
		resp, err = r.client.Do(request)
		if err == nil {
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {

				}
			}(resp.Body)
			body, _ := io.ReadAll(resp.Body)
			for _, p := range strings.Split(string(body), "\n") {
				p = strings.Trim(p, "\r")
				p = strings.Trim(p, "\n")
				if p == "" {
					continue
				}
				if _, ok := at[p]; !ok {
					at[p] = struct{}{}
				}

			}
		}
		gologger.Debug().Msg("从远程加载字典 完成...")
	}

	if len(r.targets) == 1 && r.Cfg.Options.Path == nil && r.Cfg.Options.PathFile == nil && r.Cfg.Options.PathRemote == "" {
		u := r.handlerGetFilePath("main.txt")
		if u != nil {
			for _, s := range u {
				at[s] = struct{}{}
			}
		}
	}
	if len(at) == 0 {
		at["/"] = struct{}{}
	}
	return at
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
	var resp *http.Response
	var err error
	if r.Cfg.Options.Url != nil {
		for _, u := range r.Cfg.Options.Url {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasSuffix(u, "/") {
				u, _ = url.JoinPath(u, "/")
			}
			if !strings.HasPrefix(u, "http") {
				u1 := "http://" + u
				u2 := "https://" + u
				at[u1] = struct{}{}
				at[u2] = struct{}{}
			} else {
				at[u] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.UrlFile != nil {
		for _, u := range r.Cfg.Options.UrlFile {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasSuffix(u, "/") {
				u, _ = url.JoinPath(u, "/")
			}
			if !strings.HasPrefix(u, "http") {
				u1 := "http://" + u
				u2 := "https://" + u
				at[u1] = struct{}{}
				at[u2] = struct{}{}
			} else {
				at[u] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.UrlRemote != "" {
		resp, err = http.Get(r.Cfg.Options.UrlRemote)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			for _, u := range strings.Split(string(body), "\n") {
				u = strings.Trim(u, "\r")
				u = strings.Trim(u, "\n")
				if !strings.HasSuffix(u, "/") {
					u, _ = url.JoinPath(u, "/")
				}
				if !strings.HasPrefix(u, "http") {
					u1 := "http://" + u
					u2 := "https://" + u
					at[u1] = struct{}{}
					at[u2] = struct{}{}
				} else {
					at[u] = struct{}{}
				}
			}
		}
	}
	if r.Cfg.Options.Silent && fileutil.HasStdin() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			u := strings.TrimSpace(s.Text())
			if u == "" {
				continue
			}
			if !strings.HasSuffix(u, "/") {
				u, _ = url.JoinPath(u, "/")
			}
			if !strings.HasPrefix(u, "http") {
				u1 := "http://" + u
				u2 := "https://" + u
				at[u1] = struct{}{}
				at[u2] = struct{}{}
			} else {
				at[u] = struct{}{}
			}
		}
		os.Stdin.Close()
	}
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
				c = strings.Trim(c, "\r")
				c = strings.Trim(c, "\n")
				if c == "" {
					continue
				}
				if !strings.HasPrefix(c, "http") {
					c1 := "http://" + c
					c = "https://" + c
					if !strings.HasSuffix(c1, "/") {
						c1, _ = url.JoinPath(c1, "/")
					}
					at[c1] = struct{}{}
				}
				if !strings.HasSuffix(c, "/") {
					c, _ = url.JoinPath(c, "/")
				}
				at[c] = struct{}{}
			}
		}

	}
	for _, skip := range r.Cfg.Options.SkipUrl {
		delete(at, skip)
	}

	return at
}
