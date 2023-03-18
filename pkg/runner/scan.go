package runner

import (
	"crypto/tls"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/result"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func (r *Runner) CustomHeader(req *http.Request) {
	for k, v := range r.headers {
		switch v.(type) {
		case string:
			req.Header.Set(k, v.(string))
		case []string:
			rand.Seed(time.Now().Unix())
			i := v.([]string)
			req.Header.Set(k, i[rand.Intn(len(i))])
		}
	}
}

func (r *Runner) GoTargetPath(target, path string) (*result.TargetResult, error) {
	reg := regexp.MustCompile(`<title.*>(.*?)</title>`)
	_url, err := url.JoinPath(target, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		return nil, err
	}
	r.CustomHeader(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	server := resp.Header.Get("Server")

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t := reg.FindAllStringSubmatch(string(body), -1)
	title := ""
	if len(t) == 0 {
	} else if len(t[0]) <= 1 {
	} else if len(t[0]) == 2 {
		title = t[0][1]
	}

	re := &result.TargetResult{
		Target:  target,
		Path:    path,
		Title:   title,
		Status:  resp.StatusCode,
		BodyLen: len(string(body)),
		Server:  server,
	}
	return re, nil
}

func newClient(options *Options, errUseLastResponse bool) *http.Client {
	transport := &http.Transport{
		Proxy:           getProxyFunc(options),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
	}
	if options.TimeoutTCP > 0 {
		dial := &net.Dialer{
			Timeout:   options.TimeoutTCP,
			KeepAlive: 30 * time.Second,
		}
		transport.DialContext = dial.DialContext
	}

	client := &http.Client{
		Timeout:       options.TimeoutTCP,
		CheckRedirect: getCheckRedirectFunc(errUseLastResponse),
		Transport:     transport,
	}
	return client
}

// 辅助函数：获取代理设置函数
func getProxyFunc(options *Options) func(*http.Request) (*url.URL, error) {
	if options.Proxy == "" {
		return nil
	}
	proxyURL, err := url.Parse(options.Proxy)
	if err != nil {
		gologger.Error().Msgf("解析代理 URL 失败：%s", err)
		return nil
	}
	if options.ProxyAuth != "" {
		username, password, ok := parseProxyAuth(options.ProxyAuth)
		if !ok {
			gologger.Error().Msgf("解析代理授权信息失败：%s", options.ProxyAuth)
			return nil
		}
		proxyURL.User = url.UserPassword(username, password)
	}
	return http.ProxyURL(proxyURL)
}

// 辅助函数：获取 CheckRedirect 函数
func getCheckRedirectFunc(errUseLastResponse bool) func(req *http.Request, via []*http.Request) error {
	if errUseLastResponse {
		return func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		return nil
	}
}

// 辅助函数：解析代理授权信息（格式为“username:password”）
func parseProxyAuth(auth string) (string, string, bool) {
	parts := strings.SplitN(auth, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
