package runner

import (
	"crypto/tls"
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	http "github.com/projectdiscovery/retryablehttp-go"
	httputil "github.com/projectdiscovery/utils/http"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"golang.org/x/net/context"
	"math/rand"
	"net"
	defaultHttp "net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var regByRetry = regexp.MustCompile(`<title.*>(.*?)</title>`)

func (r *Runner) CheckSkip(status int, contentLength int, body []byte) bool {
	if _, ok := r.skipCode[strconv.Itoa(status)]; ok {
		return true
	}
	if r.Cfg.Options.SkipHash != "" {
		bodyHash, _ := util.GetHash(body, r.Cfg.Options.SkipHashMethod)
		if r.Cfg.Options.SkipHash == string(bodyHash) {
			return true
		}
	}
	if r.Cfg.Options.SkipBodyLen == contentLength {
		return true
	}

	return false

}
func (r *Runner) NewRequest(method string, url string, body interface{}) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.headers {
		switch v.(type) {
		case string:
			request.Header.Set(k, v.(string))
		case []string:
			rand.Seed(time.Now().Unix())
			request.Header.Set(k, v.([]string)[rand.Intn(len(v.([]string)))])
		}
	}
	return request, nil

}
func (r *Runner) Do(target, path string, method string) (map[string]interface{}, error) {
	var gzipRetry bool
	// 创建 request
	_url, err := url.JoinPath(target, path)
	if err != nil {
		return nil, err
	}

	request, err := r.NewRequest(method, _url, []byte(r.Cfg.Options.Body))
	if err != nil {
		return nil, err
	}
	requestRaw := util.GetRequestPackage(request)
	gologger.Debug().Msg(requestRaw)
	if r.Cfg.ResultsCached.HasInCached(fmt.Sprintf("%s%s%s", target, path, method)) {
		return nil, errors.New(fmt.Sprintf("in cached %s %s%s", method, target, path))
	}
	r.Cfg.ResultsCached.Set(fmt.Sprintf("%s%s%s", target, path, method))
getResponse:
	r.limiter.Take()
	resp, err := r.retryable.Do(request)
	if err != nil {
		return nil, err
	}

	var ip string

	parse, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	// hp.Dialer.GetDialedIP would return only the last dialed one
	ip = r.dialer.GetDialedIP(parse.Host)
	if ip == "" {
		if onlyHost, _, err := net.SplitHostPort(parse.Host); err == nil {
			ip = r.dialer.GetDialedIP(onlyHost)
		}
	}
	ips, cname, _ := r.GetDNSData(parse.Host)
	if len(ips) > 1 && ip == "" {
		ip = ips[0]
	}
	host := util.JoinPath(target, path)
	parse, err = url.Parse(host)
	if err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	var shouldIgnoreErrors, shouldIgnoreBodyErrors bool
	headerBytes, bodyBytes, err := httputil.DumpResponseHeadersAndRaw(resp)
	if err != nil {
		if stringsutil.ContainsAny(err.Error(), "tls: user canceled") {
			shouldIgnoreErrors = true
			shouldIgnoreBodyErrors = true
		}
		if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
			gzipRetry = true
			request.Header.Set("Accept-Encoding", "identity")
			goto getResponse
		}
		if !shouldIgnoreErrors {
			return nil, err
		}
	}
	closeErr := resp.Body.Close()
	if closeErr != nil && !shouldIgnoreBodyErrors {
		return nil, closeErr
	}
	// Title
	var title string
	if t := regByRetry.FindStringSubmatch(string(bodyBytes)); len(t) >= 2 {
		title = t[1]
	}

	server := resp.Header.Get("Server")
	target = util.GetTrueUrl(parse)
	targetResult := &result.Result{
		TimeStamp:     time.Now(),
		URL:           target,
		Path:          parse.Path,
		Method:        method,
		Title:         title,
		Host:          ip,
		Status:        resp.StatusCode,
		CNAME:         cname,
		A:             ips,
		ContentLength: int64(len(bodyBytes)),
		Server:        server,
	}
	m["result"] = targetResult
	// 跳过
	m["check"] = r.CheckSkip(resp.StatusCode, len(bodyBytes), bodyBytes)
	if m["check"].(bool) {
		return m, nil
	}
	byte_ := map[string]interface {
	}{
		"all_headers": headerBytes,
		"body":        bodyBytes,
	}
	gologger.Debug().Msg(string(bodyBytes))
	targetResult.Technology = r.parseTechnology(byte_)
	if r.Cfg.Options.FindOtherDomain {
		targetResult.Links = r.parseOtherUrl(parse.Hostname(), r.Cfg.Options.FindOtherDomainList, headerBytes, bodyBytes)
	}
	targetResult.RequestBody = requestRaw
	targetResult.ResponseBody = util.GetResponsePackage(resp, bodyBytes, true)
	return m, err
}
func (r *Runner) GetDNSData(hostname string) (ips, cnames []string, err error) {
	dnsData, err := r.dialer.GetDNSData(hostname)
	if err != nil {
		return nil, nil, err
	}
	ips = make([]string, 0, len(dnsData.A)+len(dnsData.AAAA))
	ips = append(ips, dnsData.A...)
	ips = append(ips, dnsData.AAAA...)
	cnames = dnsData.CNAME
	return
}
func (r *Runner) NewRetryableClient() *http.Client {
	return http.NewClient(http.Options{
		Timeout:      time.Second * time.Duration(r.Cfg.Options.Timeout),
		RetryMax:     r.Cfg.Options.Retries,
		RetryWaitMax: time.Second * time.Duration(r.Cfg.Options.Timeout),
		HttpClient:   r.NewClient(),
	})
}
func (r *Runner) NewClient() *defaultHttp.Client {
	transport := &defaultHttp.Transport{
		DialContext: r.dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return r.dialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConnsPerHost: -1,
		Proxy:               util.GetProxyFunc(r.Cfg.Options.Proxy, r.Cfg.Options.ProxyAuth),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
	}

	client := &defaultHttp.Client{
		Timeout:       time.Second * time.Duration(r.Cfg.Options.Timeout),
		CheckRedirect: util.GetCheckRedirectFunc(r.Cfg.Options.ErrUseLastResponse),
		Transport:     transport,
	}
	return client
}
