package runner

import (
	"bytes"
	"crypto/tls"
	"github.com/projectdiscovery/gologger"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"pathScan/pkg/result"
	"regexp"
	"strings"
	"time"
)

var reg = regexp.MustCompile(`<title.*>(.*?)</title>`)

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

//func (r *Runner) GoTargetPath(target, path string) (*result.TargetResult, error) {
//	_url, err := url.JoinPath(target, path)
//	if err != nil {
//		return nil, err
//	}
//	req, err := http.NewRequest("GET", _url, nil)
//	if err != nil {
//		return nil, err
//	}
//	r.CustomHeader(req)
//	resp, err := r.client.Do(req)
//	if err != nil {
//		return nil, err
//	}
//	defer resp.Body.Close()
//	headerBuffer := bytes.Buffer{}
//	err = resp.Header.Write(&headerBuffer)
//	if err != nil {
//		return nil, err
//	}
//
//	bodyBuffer := bytes.Buffer{}
//	_, err = io.Copy(&bodyBuffer, resp.Body)
//	if err != nil {
//		return nil, err
//	}
//	bodyBytes := bodyBuffer.Bytes()
//	// tech
//	parse := r.regOptions.Parse([][]byte{headerBuffer.Bytes(), bodyBytes})
//	fmt.Println(parse)
//	// title
//	title := ""
//	if t := reg.FindStringSubmatch(string(bodyBytes)); len(t) >= 3 {
//		title = t[1]
//	}
//	// server
//	server := resp.Header.Get("Server")
//	re := &result.TargetResult{
//		Target:  target,
//		Path:    path,
//		Title:   title,
//		Status:  resp.StatusCode,
//		BodyLen: len(bodyBytes),
//		Server:  server,
//	}
//	return re, nil
//}

func (r *Runner) createRequest(target, path string) (*http.Request, error) {
	_url, err := url.JoinPath(target, path)
	if err != nil {
		return nil, err
	}
	method := "GET"
	if r.Cfg.Options.Method != "" {
		method = r.Cfg.Options.Method
	}
	req, err := http.NewRequest(method, _url, nil)
	if err != nil {
		return nil, err
	}
	r.CustomHeader(req)
	return req, nil
}
func (r *Runner) readHeader(resp *http.Response) ([]byte, error) {
	buffer := bytes.Buffer{}
	err := resp.Header.Write(&buffer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func (r *Runner) readBody(resp *http.Response) ([]byte, error) {
	buffer := bytes.Buffer{}
	_, err := io.Copy(&buffer, resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return buffer.Bytes(), nil
}

func (r *Runner) extractTitle(body []byte) string {
	t := reg.FindStringSubmatch(string(body))
	if len(t) >= 2 {
		return t[1]
	}
	return ""
}
func (r *Runner) processResponse(target, path string, resp *http.Response) (*result.TargetResult, error) {
	headerBytes, err := r.readHeader(resp)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := r.readBody(resp)
	if err != nil {
		return nil, err
	}

	title := r.extractTitle(bodyBytes)
	server := resp.Header.Get("Server")
	tech := r.Parse(map[string]interface {
	}{
		"all_headers": headerBytes,
		"body":        bodyBytes,
	})
	re := &result.TargetResult{
		Target:     target,
		Path:       path,
		Title:      title,
		Status:     resp.StatusCode,
		BodyLen:    len(bodyBytes),
		Server:     server,
		Technology: tech,
	}
	return re, nil
}

func (r *Runner) GoTargetPath(target, path string) (*result.TargetResult, error) {
	req, err := r.createRequest(target, path)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	re, err := r.processResponse(target, path, resp)
	if err != nil {
		return nil, err
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
