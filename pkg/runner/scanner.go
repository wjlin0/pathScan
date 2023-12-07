package runner

import (
	"crypto/tls"
	"fmt"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	http "github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/generic"
	httputil "github.com/projectdiscovery/utils/http"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
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
	// 跳过长度逻辑处理
	for _, l := range r.Cfg.Options.SkipBodyLen {
		switch strings.Count(l, "-") {
		case 1:
			split := strings.Split(l, "-")
			if len(split) != 2 {
				continue
			}
			min, err := strconv.Atoi(split[0])
			if err != nil {
				continue
			}
			max, err := strconv.Atoi(split[1])
			if err != nil {
				continue
			}
			if contentLength >= min && contentLength <= max {
				return true
			}
		case 0:
			atoi, err := strconv.Atoi(l)
			if err != nil {
				continue
			}
			if atoi == contentLength {
				return true
			}
		default:
			continue
		}

	}
	for _, l := range r.Cfg.Options.skipBodyRegex {
		// 匹配body
		if l.Match(body) {
			return true
		}
	}
	return false

}
func (r *Runner) NewRequest(ctx context.Context, method string, url string, body interface{}) (*http.Request, error) {
	urlx, err := urlutil.ParseURL(url, true)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestFromURLWithContext(ctx, method, urlx, body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.headers {
		switch v.(type) {
		case string:
			request.Header.Set(k, v.(string))
		case []string:

			rand.Seed(time.Now().Unix())
			//request.Header.Set(k, uarand.GetRandom())
			request.Header.Set(k, v.([]string)[rand.Intn(len(v.([]string)))])

		}

	}
	return request, nil

}

type Response struct {
	Response      *defaultHttp.Response
	Raw           string
	RawData       []byte
	RawHeaders    string
	Headers       map[string][]string
	StatusCode    int
	ContentLength int
	Data          []byte
}

func (r *Runner) do(req *http.Request) (*Response, error) {
	var (
		gzipRetry bool
	)
getResponse:
	httpresp, err := r.retryable.Do(req)
	if httpresp == nil && err != nil {
		return nil, err
	}
	var (
		shouldIgnoreErrors     bool
		shouldIgnoreBodyErrors bool
	)
	var resp Response
	resp.Headers = httpresp.Header.Clone()
	headers, rawResp, err := httputil.DumpResponseHeadersAndRaw(httpresp)
	if err != nil {
		if stringsutil.ContainsAny(err.Error(), "tls: user canceled") {
			shouldIgnoreErrors = true
			shouldIgnoreBodyErrors = true
		}

		// Edge case - some servers respond with gzip encoding header but uncompressed body, in this case the standard library configures the reader as gzip, triggering an error when read.
		// The bytes slice is not accessible because of abstraction, therefore we need to perform the request again tampering the Accept-Encoding header
		if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
			gzipRetry = true
			req.Header.Set("Accept-Encoding", "identity")
			goto getResponse
		}
		if !shouldIgnoreErrors {
			return nil, err
		}
	}

	resp.Raw = string(rawResp)
	resp.RawHeaders = string(headers)
	var respbody []byte
	if !generic.EqualsAny(httpresp.StatusCode, defaultHttp.StatusSwitchingProtocols, defaultHttp.StatusNotModified) {
		var err error
		respbody, err = io.ReadAll(httpresp.Body)
		if err != nil && !shouldIgnoreBodyErrors {
			return nil, err
		}
	}
	closeErr := httpresp.Body.Close()
	if closeErr != nil && !shouldIgnoreBodyErrors {
		return nil, closeErr
	}
	resp.RawData = make([]byte, len(respbody))
	copy(resp.RawData, respbody)
	respbody, err = DecodeData(respbody, httpresp.Header)
	if err != nil && !shouldIgnoreBodyErrors {
		return nil, closeErr
	}
	// if content length is not defined
	if resp.ContentLength <= 0 {
		// check if it's in the header and convert to int
		if contentLength, ok := resp.Headers["Content-Length"]; ok && len(contentLength) > 0 {
			contentLengthInt, _ := strconv.Atoi(contentLength[0])
			resp.ContentLength = contentLengthInt
		}

		// if we have a body, then use the number of bytes in the body if the length is still zero
		if resp.ContentLength <= 0 && len(respbody) > 0 {
			resp.ContentLength = len(respbody)
		}
	}
	resp.Data = respbody
	// fill metrics
	resp.StatusCode = httpresp.StatusCode
	resp.Response = httpresp
	return &resp, nil
}

// returns all the targets_ within a cidr range or the single target
func (r *Runner) targets(target string) chan result.Target {
	results := make(chan result.Target)
	go func() {
		defer close(results)

		target = strings.TrimSpace(target)

		switch {
		case stringsutil.HasPrefixAny(target, "*", "."):
			// A valid target does not contain:
			// trim * and/or . (prefix) from the target to return the domain instead of wilcard
			target = stringsutil.TrimPrefixAny(target, "*", ".")
			results <- result.Target{Host: target}
		case asn.IsASN(target):
			cidrIps, err := asn.GetIPAddressesAsStream(target)
			if err != nil {
				return
			}
			for ip := range cidrIps {
				results <- result.Target{Host: ip}
			}
		case iputil.IsCIDR(target):
			cidrIps, err := mapcidr.IPAddressesAsStream(target)
			if err != nil {
				return
			}
			for ip := range cidrIps {
				results <- result.Target{Host: ip}
			}
		case !stringsutil.HasPrefixAny(target, "http://", "https://") && stringsutil.ContainsAny(target, ","):
			idxComma := strings.Index(target, ",")
			results <- result.Target{Host: target[idxComma+1:], CustomHost: target[:idxComma]}
		default:
			results <- result.Target{Host: target}
		}
	}()
	return results
}
func GetDNSData(dialer *fastdialer.Dialer, hostname string) (ips, cnames []string, err error) {
	dnsData, err := dialer.GetDNSData(hostname)
	if err != nil {
		return nil, nil, err
	}
	ips = make([]string, 0, len(dnsData.A)+len(dnsData.AAAA))
	ips = append(ips, dnsData.A...)
	ips = append(ips, dnsData.AAAA...)
	cnames = dnsData.CNAME
	return
}
func (r *Runner) analyze(protocol string, t result.Target, path, method string) (m map[string]interface{}, err error) {
	m = make(map[string]interface{})
	originProtocol := protocol
	if protocol == HTTPorHTTPS {
		protocol = HTTPS
	}
	retried := false
	target := t.Host
retry:

	proTarget := fmt.Sprintf("%s://%s", protocol, target)
	// 创建 request
	_url, err := url.JoinPath(proTarget, path)
	if err != nil {
		return nil, err
	}
	if r.Cfg.Options.SkipUrl != nil {
		for _, h := range r.Cfg.Options.SkipUrl {
			parse, err := url.Parse(_url)
			if err != nil {
				return nil, err
			}
			switch {
			case strings.HasPrefix(h, "*."):
				if parse.Hostname() == h[2:] || strings.HasSuffix(parse.Hostname(), h[1:]) {
					gologger.Warning().Msgf("skip %s ", _url)
					return nil, nil
				}
			default:
				if parse.Hostname() == h {
					gologger.Warning().Msgf("skip %s ", _url)
					return nil, nil
				}
			}

		}
	}
	request, err := r.NewRequest(context.Background(), method, _url, []byte(r.Cfg.Options.Body))
	if err != nil {
		return nil, err
	}
	requestRaw := util.GetRequestPackage(request)
	if r.Cfg.Options.Verbose && requestRaw != "" {
		gologger.Print().Msg(requestRaw)
	}
	if r.Cfg.ResultsCached.HasInCached(fmt.Sprintf("%s-%s", _url, method)) {
		gologger.Warning().Msgf("in cached %s %s", method, _url)
		return nil, nil
	}
	r.Cfg.ResultsCached.Set(fmt.Sprintf("%s-%s", _url, method))
	r.limiter.Take()
	resp, err := r.do(request)
	if err != nil {
		if !retried && originProtocol == HTTPorHTTPS {
			if protocol == HTTPS {
				protocol = HTTP
			} else {
				protocol = HTTPS
			}
			retried = true
			goto retry
		}
		return nil, err
	}

	var ip string

	parse, err := url.Parse(proTarget)
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
	var ips, cname []string
	// 解决请求目标为ip时过慢
	if parse.Hostname() != ip {
		ips, cname, _ = GetDNSData(r.dialer, parse.Host)
		if len(ips) > 0 && ip == "" {
			ip = ips[0]
		}
	} else {
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	host := util.JoinPath(proTarget, path)
	parse, err = url.Parse(host)
	if err != nil {
		return nil, err
	}

	// Title
	var title string
	if t := regByRetry.FindStringSubmatch(string(resp.RawData)); len(t) >= 2 {
		title = strings.Join(t[1:], " ")
	}

	server := strings.Join(resp.Headers["Server"], " ")
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
		ContentLength: resp.ContentLength,
		Server:        server,
		Header:        resp.Headers,
		HTTPurl:       parse,
	}
	m["result"] = targetResult
	// 跳过
	m["check"] = r.CheckSkip(resp.StatusCode, resp.ContentLength, resp.Data)
	if m["check"].(bool) {
		return m, nil
	}
	byte_ := map[string]interface {
	}{
		"all_headers": resp.RawHeaders,
		"body":        resp.RawData,
	}
	targetResult.Technology = r.parseTechnology(byte_)
	if r.Cfg.Options.FindOtherDomain {
		targetResult.Links = r.parseOtherUrl(parse.Hostname(), r.Cfg.Options.FindOtherDomainList, []byte(resp.RawHeaders), resp.Data)
	}
	targetResult.RequestBody = requestRaw
	targetResult.ResponseBody = util.GetResponsePackage(resp.Response, resp.Data, true)
	if r.Cfg.Options.Verbose && targetResult.ResponseBody != "" {
		gologger.Print().Msg(targetResult.ResponseBody)
	}
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
	var retryablehttpOptions = http.DefaultOptionsSpraying
	retryablehttpOptions.Timeout = time.Second * time.Duration(r.Cfg.Options.Timeout)
	retryablehttpOptions.RetryMax = r.Cfg.Options.Retries
	return http.NewClient(http.Options{
		Timeout:      time.Second * time.Duration(r.Cfg.Options.Timeout),
		RetryMax:     r.Cfg.Options.Retries,
		RetryWaitMax: time.Second * time.Duration(r.Cfg.Options.Timeout),
		HttpClient:   r.NewClient(),
	})
}
func (r *Runner) NewClient() *defaultHttp.Client {
	errUseLastResponse := r.Cfg.Options.ErrUseLastResponse
	checkRedirect := func(req *defaultHttp.Request, via []*defaultHttp.Request) error {
		if !errUseLastResponse {
			return defaultHttp.ErrUseLastResponse
		} else {
			return nil
		}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	transport := &defaultHttp.Transport{
		DialContext:         r.dialer.Dial,
		DialTLSContext:      r.dialer.DialTLS,
		MaxIdleConnsPerHost: -1,
		Proxy:               util.GetProxyFunc(r.Cfg.Options.Proxy, r.Cfg.Options.ProxyAuth),
		TLSClientConfig:     tlsConfig,
	}

	client := &defaultHttp.Client{
		Timeout:       time.Second * time.Duration(r.Cfg.Options.Timeout),
		CheckRedirect: checkRedirect,
		Transport:     transport,
	}
	return client
}
