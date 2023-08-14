package runner

import (
	"bytes"
	"crypto/tls"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	http "github.com/projectdiscovery/retryablehttp-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/runner"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"golang.org/x/net/context"
	"io"
	"math/rand"
	"net"
	defaultHttp "net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var regByRetry = regexp.MustCompile(`<title.*>(.*?)</title>`)

func (r *Runner) customRetryableHeader(req *http.Request) {
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

func (r *Runner) createRetryableRequest(target, path string) (*http.Request, error) {
	_url, err := url.JoinPath(target, path)
	if err != nil {
		return nil, err
	}
	method := "GET"
	if r.Cfg.Options.Method != "" {
		method = r.Cfg.Options.Method
	}
	var body []byte
	if r.Cfg.Options.Body != "" {
		body = []byte(r.Cfg.Options.Body)
	}
	req, err := http.NewRequest(method, _url, body)
	if err != nil {
		return nil, err
	}
	r.customRetryableHeader(req)
	return req, nil
}
func (r *Runner) readRetryableHeader(resp *defaultHttp.Response) ([]byte, error) {
	buffer := bytes.Buffer{}
	err := resp.Header.Write(&buffer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func (r *Runner) readRetryableBody(resp *defaultHttp.Response) ([]byte, error) {
	buffer := bytes.Buffer{}
	_, err := io.Copy(&buffer, resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(buffer.Bytes()))

	return buffer.Bytes(), nil
}

func (r *Runner) extractRetryableTitle(body []byte) string {
	t := regByRetry.FindStringSubmatch(string(body))
	if len(t) >= 2 {
		return t[1]
	}
	return ""
}

func (r *Runner) checkSkip(re *result.TargetResult, head []byte, body []byte) bool {
	option := r.Cfg.Options
	if _, ok := r.skipCode[strconv.Itoa(re.Status)]; ok {
		return true
	}
	if option.SkipHash != "" {
		bodyHash, _ := util.GetHash(body, option.SkipHashMethod)
		if option.SkipHash == string(bodyHash) {
			return true
		}
	}
	if option.SkipBodyLen == int(re.ContentLength) {
		return true
	}

	return false

}

func (r *Runner) GoTargetPathByRetryable(target, path string) (map[string]interface{}, error) {
	req, err := r.createRetryableRequest(target, path)
	if err != nil {
		return nil, err
	}
	r.limiter.Take()
	resp, err := r.retryable.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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
	r.limiter.Take()
	ips, cname, _ := r.getDNSData(parse.Host)
	if len(ips) > 1 && ip == "" {
		ip = ips[0]
	}
	host := util.JoinPath(target, path)
	parse, err = url.Parse(host)
	if err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	headerBytes, err := r.readRetryableHeader(resp)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := r.readRetryableBody(resp)
	if err != nil {
		return nil, err
	}

	title := r.extractRetryableTitle(bodyBytes)
	server := resp.Header.Get("Server")
	target = util.GetTrueUrl(parse)
	re := &result.TargetResult{
		TimeStamp:     time.Now(),
		URL:           target,
		Path:          parse.Path,
		Title:         title,
		Host:          ip,
		Status:        resp.StatusCode,
		CNAME:         cname,
		A:             ips,
		ContentLength: int64(len(bodyBytes)),
		Server:        server,
	}
	m["re"] = re
	// 跳过
	m["check"] = r.checkSkip(re, headerBytes, bodyBytes)
	if m["check"].(bool) {
		return m, nil
	}
	byte_ := map[string]interface {
	}{
		"all_headers": headerBytes,
		"body":        bodyBytes,
	}

	tech := r.ParseTechnology(byte_)
	if r.Cfg.Options.FindOtherLink || r.Cfg.Options.FindOtherDomain {
		links := r.ParseOtherUrl(host, byte_)
		m["links"] = links
	}
	re.Technology = tech
	m["request"] = util.GetRequestPackage(req)
	if len(bodyBytes) > 1000 {
		m["response"] = util.GetResponsePackage(resp, false)
	} else {
		m["response"] = util.GetResponsePackage(resp, true)
	}

	return m, err
}
func (r *Runner) getDNSData(hostname string) (ips, cnames []string, err error) {
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

func newRetryableClient(options *Options, errUseLastResponse bool, dialer *fastdialer.Dialer) *http.Client {

	httpOptions := http.Options{
		Timeout:      options.TimeoutHttp,
		RetryMax:     options.Retries,
		RetryWaitMax: options.TimeoutHttp,
		HttpClient:   newClient(options, errUseLastResponse, dialer),
	}
	return http.NewClient(httpOptions)
}
func newClient(options *Options, errUseLastResponse bool, dialer *fastdialer.Dialer) *defaultHttp.Client {

	transport := &defaultHttp.Transport{
		DialContext: dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConnsPerHost: -1,
		Proxy:               util.GetProxyFunc(options.Proxy, options.ProxyAuth),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
	}
	if options.TimeoutHttp > 0 {
		dial := &net.Dialer{
			Timeout:   options.TimeoutHttp,
			KeepAlive: options.TimeoutHttp,
		}
		transport.DialContext = dial.DialContext
	}

	client := &defaultHttp.Client{
		Timeout:       options.TimeoutHttp,
		CheckRedirect: util.GetCheckRedirectFunc(errUseLastResponse),
		Transport:     transport,
	}
	return client
}
func (r *Runner) GoOtherLink(outputOtherWriter *runner.OutputWriter, ctx context.Context, wg *sizedwaitgroup.SizedWaitGroup) {
	defer func() {
		wg.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case target := <-r.otherLinkChan:
			parse, err := url.Parse(target)
			if err != nil {
				continue
			}
			target = util.GetTrueUrl(parse)
			path := parse.Path
			r.wg.Add()
			go r.GoHandler(target, path, outputOtherWriter, ctx, nil, nil, r.wg)
		}
	}

}
