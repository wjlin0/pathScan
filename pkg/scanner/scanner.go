package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/corpix/uarand"
	lru "github.com/hashicorp/golang-lru"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/generic"
	httputil "github.com/projectdiscovery/utils/http"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/v2/pkg/identification"
	"github.com/wjlin0/pathScan/v2/pkg/input"
	"github.com/wjlin0/pathScan/v2/pkg/output"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"github.com/wjlin0/uncover"
	proxyutils "github.com/wjlin0/utils/proxy"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	client        *retryablehttp.Client
	rateLimiter   *ratelimit.Limiter
	options       *types.Options
	dialer        *fastdialer.Dialer
	operators     []*identification.Operators
	skipBodyRegex []*regexp.Regexp
	cache         *lru.Cache
	uncover       *uncover.Service

	sync.RWMutex
}

func NewScanner(options *types.Options) (*Scanner, error) {
	var (
		err           error
		limiter       *ratelimit.Limiter
		dialer        *fastdialer.Dialer
		client        *retryablehttp.Client
		operators     []*identification.Operators
		clientOptions retryablehttp.Options
		httpClient    *http.Client
	)
	scanner := &Scanner{options: options}
	if options.RateLimit < 0 {
		limiter = ratelimit.NewUnlimited(context.Background())
	} else {
		limiter = ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	}
	fastOptons := fastdialer.DefaultOptions
	fastOptons.WithDialerHistory = true
	fastOptons.EnableFallback = true
	if len(options.Resolvers) > 0 {
		fastOptons.BaseResolvers = options.Resolvers
	}
	if dialer, err = fastdialer.NewDialer(fastOptons); err != nil {
		return nil, err
	}

	if options.CountURL() == 1 {
		clientOptions = retryablehttp.DefaultOptionsSingle
	} else {
		clientOptions = retryablehttp.DefaultOptionsSpraying
	}
	clientOptions.Timeout = time.Second * time.Duration(options.HttpTimeout)
	clientOptions.RetryMax = options.RetryMax
	errUseLastResponse := options.ErrUseLastResponse
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !errUseLastResponse {
			return http.ErrUseLastResponse
		} else {
			return nil
		}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	proxyFunc, _ := proxyutils.GetProxyFunc(types.ProxyURL)
	if proxyFunc == nil {
		proxyFunc = http.ProxyFromEnvironment
	}

	transport := &http.Transport{
		DialContext:         dialer.Dial,
		DialTLSContext:      dialer.DialTLS,
		MaxIdleConnsPerHost: -1,
		Proxy:               proxyFunc,
		TLSClientConfig:     tlsConfig,
	}

	httpClient = &http.Client{
		Timeout:       time.Second * time.Duration(options.HttpTimeout),
		CheckRedirect: checkRedirect,
		Transport:     transport,
	}

	clientOptions.HttpClient = httpClient

	client = retryablehttp.NewClient(clientOptions)

	operators, _ = identification.NewOptions(options.MatchPath)

	for _, skip := range options.SkipBodyRegex {
		regex, err := regexp.Compile(skip)
		if err != nil {
			return nil, err
		}
		scanner.skipBodyRegex = append(scanner.skipBodyRegex, regex)
	}
	cache, err := lru.New(2048)
	if err != nil {
		return nil, err
	}
	var (
		service *uncover.Service
	)

	if options.Uncover {
		opts := &uncover.Options{
			Agents:   scanner.options.UncoverEngine,
			Queries:  scanner.options.UncoverQuery,
			Limit:    scanner.options.UncoverLimit,
			MaxRetry: 2,
			Timeout:  scanner.options.HttpTimeout,
		}
		if service, err = uncover.New(opts); err != nil {
			return nil, err
		}
		service.Session.Client = client
		scanner.uncover = service
	} else if options.Subdomain {
		opts := &uncover.Options{
			Agents:   scanner.options.SubdomainEngine,
			Queries:  scanner.options.SubdomainQuery,
			Limit:    scanner.options.SubdomainLimit,
			MaxRetry: 2,
			Timeout:  scanner.options.HttpTimeout,
		}
		if service, err = uncover.New(opts); err != nil {
			return nil, err
		}

		service.Session.Client = client
		scanner.uncover = service
	}

	scanner.rebaseUncover()

	scanner.cache = cache
	scanner.operators = operators
	scanner.dialer = dialer
	scanner.client = client
	scanner.rateLimiter = limiter
	return scanner, nil
}

func (scanner *Scanner) CountOperators() int {
	return len(scanner.operators)
}

func (scanner *Scanner) Close() {
	scanner.dialer.Close()
	scanner.rateLimiter.Stop()
}

func (scanner *Scanner) Scan(target *input.Target, writer func(event output.ResultEvent)) {
	var (
		Schemes []string
		wg      = sizedwaitgroup.New(-1)
	)
	if target.Scheme == input.HTTPandHTTPS {
		Schemes = []string{"https", "http"}
	} else {
		Schemes = []string{target.Scheme}
	}
	for _, scheme := range Schemes {
		for _, method := range target.Methods {
			for _, path := range target.Paths {
				wg.Add()
				go func(target *input.Target, scheme, method, path string) {
					defer wg.Done()
					event, err := scanner.scanURL(target, scheme, method, path, writer)
					if err != nil {
						gologger.Debug().Msgf("Could not scan %s %s://%s%s: %s", method, scheme, target.Host, path, err)
						return
					}

					if scanner.checkEventSkip(event) {
						return
					}
					writer(event)
					if !scanner.options.FindOtherDomain {
						return
					}

					for _, link := range event.Links {
						if scanner.IsSkipURL(link) || scanner.findDuplicate(method+link) {
							continue
						}
						scheme, host := util.GetProtocolAndHost(link)
						target = &input.Target{
							Host:    host,
							Scheme:  scheme,
							Methods: []string{method},
							Paths:   []string{"/"},
							Body:    "",
						}
						wg.Add()
						go func() {
							wg.Done()
							scanner.Scan(target, writer)
						}()

					}
				}(target, scheme, method, path)
			}
		}
	}

	wg.Wait()
}

func (scanner *Scanner) scanURL(target *input.Target, scheme, method, path string, callback func(event output.ResultEvent)) (event output.ResultEvent, err error) {

	originProtocol := scheme
	if scheme == input.HTTPorHTTPS {
		scheme = input.HTTPS
	}
	retried := false
retry:
	var (
		request *retryablehttp.Request
	)
	URL := scheme + "://" + target.Host + path
	if scanner.IsSkipURL(URL) {
		gologger.Debug().Msgf("skipping %s", URL)
		return
	}
	if scanner.findDuplicate(method + "|" + URL) {
		return
	}
	if request, err = target.NewRequest(method, URL); err != nil {
		return output.ResultEvent{}, err
	}

	scanner.rateLimiter.Take()

	resp, err := scanner.do(request)

	if err != nil {
		if !retried && originProtocol == input.HTTPorHTTPS {
			if scheme == input.HTTPS {
				scheme = input.HTTP
			} else {
				scheme = input.HTTPS
			}
			retried = true
			goto retry
		}
		return output.ResultEvent{}, err
	}

	event, err = scanner.getEvent(request, resp)
	if err != nil {
		return output.ResultEvent{}, err
	}
	var tech []string

	if path == "/" && !scanner.options.DisableScanMatch {
		tech = append(tech, scanner.scanByOperators(request, resp, callback)...)
	}

	event.Technology = sliceutil.Dedupe(tech)

	return event, nil

}

type Response struct {
	Response      *http.Response
	Raw           string
	RawData       []byte
	RawHeaders    string
	Headers       map[string][]string
	StatusCode    int
	ContentLength int
	Data          []byte
}

func (scanner *Scanner) do(request *retryablehttp.Request) (resp *Response, err error) {
	var (
		gzipRetry bool
	)
	if request != nil && scanner.options.Debug {
		if dump, _ := request.Dump(); dump != nil {
			gologger.Print().Msg(string(dump))
		}
	}
	defer func() {
		if resp != nil && scanner.options.Debug {
			gologger.Print().Msg(resp.Raw)
		}
	}()
	resp = &Response{}
getResponse:
	httpresp, err := scanner.client.Do(request)
	if httpresp == nil && err != nil {
		return nil, err
	}
	var (
		shouldIgnoreErrors     bool
		shouldIgnoreBodyErrors bool
	)
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
			request.Header.Set("Accept-Encoding", "identity")
			goto getResponse
		}
		if !shouldIgnoreErrors {
			return nil, err
		}
	}

	resp.Raw = string(rawResp)
	resp.RawHeaders = string(headers)
	var respbody []byte
	if !generic.EqualsAny(httpresp.StatusCode, http.StatusSwitchingProtocols, http.StatusNotModified) {
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
	return resp, nil
}

func (scanner *Scanner) scanByOperators(requestOrigin *retryablehttp.Request, responseOrigin *Response, callback func(event output.ResultEvent)) []string {
	var (
		wg        = sizedwaitgroup.New(-1)
		requests  = make(map[string]*retryablehttp.Request)
		responses = make(map[string]*Response)
		result    []string
	)
	URL := strings.TrimSuffix(requestOrigin.String(), "/")
	for _, operator := range scanner.operators {
		for _, req := range operator.Request {
			for _, path := range req.Path {
				h := fmt.Sprintf("%s-%s-%s-%s", URL+path, req.Method, req.Header, req.Body)
				if _, ok := requests[h]; ok {
					continue
				}
				requests[h], _ = retryablehttp.NewRequest(req.Method, URL+path, req.Body)
				for k, v := range req.Header {
					requests[h].Header.Set(k, v.(string))
				}
				if ok := requests[h].Header.Get("User-Agent"); ok == "" {
					requests[h].Header.Set("User-Agent", uarand.GetRandom())
				}
			}
		}

	}
	for _, operator := range scanner.operators {
		wg.Add()
		go func(operator *identification.Operators) {
			defer wg.Done()
			for _, req := range operator.Request {
				for _, path := range req.Path {
					var (
						err     error
						request *retryablehttp.Request
						resp    *Response
					)
					h := fmt.Sprintf("%s-%s-%s-%s", URL+path, req.Method, req.Header, req.Body)
					if request = requests[h]; request == nil {
						return
					}
					if req.Method == "GET" && req.Header == nil && (len(req.Path) == 1 && req.Path[0] == "/") && req.Body == "" {
						resp = responseOrigin
					}
					if resp == nil {
						if resp = responses[h]; resp == nil {
							if resp, err = scanner.do(request); err != nil {
								return
							}
							scanner.Lock()
							responses[h] = resp
							scanner.Unlock()
						}
					}

					data := make(map[string]interface{})
					data["all_headers"] = resp.RawHeaders
					data["body"] = resp.RawData
					data["status_code"] = resp.StatusCode
					data["header"] = resp.RawHeaders
					data["response"] = resp.Raw
					data["raw"] = resp.Raw
					execute, b := operator.Execute(data, match)
					if b && !(len(execute) == 1 && execute[0] == "") {
						scanner.Lock()
						result = append(result, execute...)
						scanner.Unlock()

						ok := path == "/" && req.Method == "GET" && len(req.Header) == 0 && len(req.Body) == 0

						if event, _ := scanner.getEvent(request, resp); event.URL != "" && !ok {
							event.Technology = execute
							callback(event)
						}

						if operator.StopAtFirstMatch {
							return
						}
					}
				}
			}

		}(operator)
	}
	wg.Wait()

	return result
}

func (scanner *Scanner) CountOperatorsRequest() int {
	count := 0
	cache := make(map[string]struct{})
	for _, operator := range scanner.operators {
		for _, req := range operator.Request {
			for _, path := range req.Path {
				h := fmt.Sprintf("%s-%s-%s-%s", path, req.Method, req.Header, req.Body)
				if _, ok := cache[h]; ok {
					continue
				}
				cache[h] = struct{}{}
				count++
			}
		}

	}
	return count
}

func (scanner *Scanner) Alive(target *input.Target) *input.Target {
	var (
		Schemes     []string
		aliveTarget = target.Clone()
	)
	if target.Scheme == input.HTTPandHTTPS {
		Schemes = []string{"https", "http"}
	} else {
		Schemes = []string{target.Scheme}
	}
	for _, scheme := range Schemes {

		originProtocol := scheme
		if scheme == input.HTTPorHTTPS {
			scheme = input.HTTPS
		}
		retried := false
	retry:
		var (
			err     error
			request *retryablehttp.Request
		)
		URL := scheme + "://" + target.Host + "/"
		if request, err = target.NewRequest("HEAD", URL); err != nil {
			gologger.Debug().Msgf("Could not create request for %s: %s", URL, err)
			continue
		}
		if err != nil {
			continue
		}

		scanner.rateLimiter.Take()
		_, err = scanner.do(request)
		if err != nil {
			if !retried && originProtocol == input.HTTPorHTTPS {
				if scheme == input.HTTPS {
					scheme = input.HTTP
				} else {
					scheme = input.HTTPS
				}
				retried = true
				goto retry
			}
			gologger.Debug().Msgf("Could not make request for %s: %s", URL, err)
			continue
		}
		aliveTarget.Scheme = scheme
		return aliveTarget
	}
	return nil
}

func (scanner *Scanner) checkEventSkip(event output.ResultEvent) bool {
	if event.URL == "" {
		return true
	}
	if scanner.options.SkipOutputIsEmpty() {
		return false
	}
	if sliceutil.Contains(scanner.options.SkipCode, strconv.Itoa(event.Status)) {
		return true
	}

	// 循环递归跳过 状态码 例如 5xx 4xx 3xx 500-599 400-499 300-399
	for _, status := range scanner.options.SkipCode {

		if strings.Contains(status, "-") && !strings.Contains(status, "xx") {
			split := strings.Split(status, "-")
			if len(split) != 2 {
				continue
			}
			minStatus, err := strconv.Atoi(split[0])
			if err != nil {
				continue
			}
			maxStatus, err := strconv.Atoi(split[1])
			if err != nil {
				continue
			}
			if event.Status >= minStatus && event.Status <= maxStatus {
				return true
			}
		}
		if strings.Contains(status, "xx") {
			if strings.HasPrefix(status, strconv.Itoa(event.Status)[:1]) {
				return true
			}
		}

	}

	if scanner.options.SkipHash != "" {
		bodyHash, _ := util.GetHash([]byte(event.RequestBody), scanner.options.SkipHashMethod)
		if scanner.options.SkipHash == string(bodyHash) {
			return true
		}
	}
	// 跳过长度逻辑处理
	for _, l := range scanner.options.SkipBodyLen {
		switch strings.Count(l, "-") {
		case 1:
			split := strings.Split(l, "-")
			if len(split) != 2 {
				continue
			}
			minLength, err := strconv.Atoi(split[0])
			if err != nil {
				continue
			}
			maxLength, err := strconv.Atoi(split[1])
			if err != nil {
				continue
			}
			if event.ContentLength >= minLength && event.ContentLength <= maxLength {
				return true
			}
		case 0:
			atoi, err := strconv.Atoi(l)
			if err != nil {
				continue
			}
			if atoi == event.ContentLength {
				return true
			}
		default:
			continue
		}

	}

	for _, l := range scanner.skipBodyRegex {
		// 匹配body
		if l.Match([]byte(event.ResponseBody)) {
			return true
		}
	}

	return false
}
