package web

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/projectdiscovery/retryablehttp-go"
	log "github.com/sirupsen/logrus"
	"github.com/wjlin0/pathScan/pkg/common/identification"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup

type WebAddon struct {
	proxy.BaseAddon
	client    *retryablehttp.Client
	cached    map[string]struct{}
	connsMu   sync.RWMutex
	regexOpts []*identification.Options
	output    chan *result.Result
}

var regexTitile = regexp.MustCompile(`<title.*>(.*?)</title>`)
var allows []string

func NewWebAddon(proxyAddr string, hosts []string, regexpOpts []*identification.Options, output chan *result.Result) *WebAddon {
	web := new(WebAddon)
	switch {
	case strings.HasPrefix(proxyAddr, ":"):
		proxyAddr = fmt.Sprintf("http://127.0.0.1%v", proxyAddr)
	case !strings.HasPrefix(proxyAddr, "http") && !strings.HasPrefix(proxyAddr, ":"):
		proxyAddr = fmt.Sprintf("http://%s", proxyAddr)

	}
	allows = hosts
	log.SetLevel(0)
	parse, err := url.Parse(proxyAddr)
	if err != nil {
		panic(err)
	}

	// 配置 retryableclient
	var retryablehttpOptions = retryablehttp.Options{}
	retryablehttpOptions.RetryMax = 1
	transport := &http.Transport{
		MaxIdleConnsPerHost: -1,
		Proxy:               http.ProxyURL(parse),
		ForceAttemptHTTP2:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	retryablehttpOptions.HttpClient = &http.Client{}
	retryablehttpOptions.HttpClient.Transport = transport
	retryablehttpOptions.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 禁止自动重定向
		return http.ErrUseLastResponse
	}
	web.client = retryablehttp.NewClient(retryablehttpOptions)
	web.cached = make(map[string]struct{})
	web.output = output
	web.regexOpts = regexpOpts
	return web
}

func (web *WebAddon) Response(f *proxy.Flow) {
	if f.Request.Method == http.MethodConnect {
		return
	}
	// Title
	var title string
	if t := regexTitile.FindStringSubmatch(string(f.Response.Body)); len(t) >= 2 {
		title = strings.Join(t[1:], " ")
	}
	// request body header
	requestBodyBuffer := bytes.Buffer{}
	requestHeaderBuffer := bytes.Buffer{}
	for k, values := range f.Request.Header {
		requestHeaderBuffer.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(values, ";")))
	}
	requestBodyBuffer.Write(f.Request.Body)
	// response body header
	responseBodyBuffer := bytes.Buffer{}
	responseHeaderBuffer := bytes.Buffer{}
	for k, values := range f.Response.Header {
		responseHeaderBuffer.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(values, ";")))
	}
	body, err := f.Response.DecodedBody()
	if err != nil {
		body = f.Response.Body
	}
	responseBodyBuffer.Write(body)
	// server
	server := strings.Join(f.Response.Header["Server"], " ")
	re := &result.Result{
		TimeStamp:     time.Now(),
		URL:           util.GetTrueUrl(f.Request.URL),
		Path:          f.Request.URL.Path,
		Method:        f.Request.Method,
		Title:         title,
		Host:          "",
		A:             nil,
		CNAME:         nil,
		Status:        f.Response.StatusCode,
		ContentLength: len(f.Response.Body),
		Server:        server,
		Technology: parseTechnology(web.regexOpts, match, map[string]interface{}{
			"all_headers": responseHeaderBuffer.Bytes(),
			"body":        responseBodyBuffer.Bytes(),
		}),
		ResponseBody: fmt.Sprintf("%s\r\n%s", responseHeaderBuffer.String(), responseBodyBuffer.String()),
		RequestBody:  fmt.Sprintf("%s\r\n%s", requestBodyBuffer.String(), requestHeaderBuffer.String()),
		Links:        nil,
		Header:       nil,
	}
	web.output <- re
	hosts := append(allows, f.Request.URL.Hostname())
	go web.requestHosts(parseHosts(util.RemoveDuplicateStrings(hosts), responseHeaderBuffer.Bytes(), responseBodyBuffer.Bytes()))
}

func (web *WebAddon) requestHosts(hosts []string) {
	for _, host := range hosts {
		web.connsMu.Lock()
		if _, ok := web.cached[host]; ok {
			web.connsMu.Unlock()
			continue
		}
		web.cached[host] = struct{}{}
		web.connsMu.Unlock()
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			_, _ = web.client.Get(host)

		}(host)
	}
	wg.Wait()
}
func parseTechnology(regexOpts []*identification.Options, match identification.MatchFunc, data map[string]interface{}) []string {
	var tag []string
	for _, options := range regexOpts {
		for _, sub := range options.SubMatch {
			execute, b := sub.Execute(data, match)
			if b && !(len(execute) == 1 && execute[0] == "") {
				tag = append(tag, execute...)
			}
		}
	}

	return tag
}
func match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := util.GetPartString(matcher.Part, data)
	if !ok {
		return false, []string{}
	}

	switch matcher.GetType() {
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(item, data))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(item))
	case matchers.HashMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchHash(item))
	}
	return false, []string{}
}
