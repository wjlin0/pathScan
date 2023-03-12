package runner

import (
	"crypto/tls"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/result"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

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
	req.Header.Set("User-Agent", r.GetUserAgent())
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

func newClient(options *Options, ErrUseLastResponse bool) *http.Client {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: newTransport(options),
	}
	if ErrUseLastResponse {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func newTransport(options *Options) *http.Transport {
	t := &http.Transport{
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}
	if options.Proxy != "" {
		proxyUrl, err := url.Parse(options.Proxy)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if options.ProxyAuth != "" {
			proxyUrl.User = url.UserPassword(strings.Split(options.ProxyAuth, ":")[0], strings.Split(options.ProxyAuth, ":")[1])
		}
		t.Proxy = http.ProxyURL(proxyUrl)
	}
	return t
}
