package scanner

import (
	"bytes"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/wjlin0/pathScan/v2/pkg/identification/matchers"
	"github.com/wjlin0/pathScan/v2/pkg/output"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"github.com/wjlin0/uncover/sources"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func (scanner *Scanner) getDialedIP(host string) (ip string) {
	URL, err := url.Parse(host)
	if err != nil {
		return
	}
	ip = scanner.dialer.GetDialedIP(URL.Host)
	if ip == "" {
		if onlyHost, _, err := net.SplitHostPort(URL.Host); err == nil {
			ip = scanner.dialer.GetDialedIP(onlyHost)
		}
	}
	return

}
func (scanner *Scanner) getDNSData(hostname string) (ips, cnames []string, err error) {
	dnsData, err := scanner.dialer.GetDNSData(hostname)
	if err != nil {
		return nil, nil, err
	}
	ips = make([]string, 0, len(dnsData.A)+len(dnsData.AAAA))
	ips = append(ips, dnsData.A...)
	ips = append(ips, dnsData.AAAA...)
	cnames = dnsData.CNAME
	return
}

var titleRegex = regexp.MustCompile(`<title.*>(.*?)</title>`)

func (scanner *Scanner) getTitle(body string) (title string) {

	if titles := titleRegex.FindStringSubmatch(body); len(titles) > 1 {
		title = strings.Join(titles[1:], " ")
	}

	return
}

func (scanner *Scanner) getTechnology(data map[string]interface{}) []string {
	var tag []string

	for _, sub := range scanner.operators {

		execute, b := sub.Execute(data, match)
		if b && !(len(execute) == 1 && execute[0] == "") {
			tag = append(tag, execute...)
		}
	}

	return tag
}

func (scanner *Scanner) getLinkURLs(oldUrl string, domains []string, data ...[]byte) []string {
	var buffer bytes.Buffer
	for _, v := range data {
		buffer.Write(v)
	}
	// 提取响应包的 body 数据
	body := buffer.String()
	if domains != nil {
		matchDomains := make(map[string]struct{})
		Topdomains := make(map[string]struct{})
		if net.ParseIP(oldUrl) == nil {
			Topdomains[util.GetMainDomain(oldUrl)] = struct{}{}
		}
		for _, d := range domains {
			Topdomains[util.GetMainDomain(d)] = struct{}{}
		}
		for k, _ := range Topdomains {
			for _, d1 := range sources.MatchSubdomains(k, body, false) {
				matchDomains[d1] = struct{}{}
			}
		}
		domains = []string{}
		for k, _ := range matchDomains {
			domains = append(domains, k)
		}
		return domains
	}
	domain := oldUrl
	if net.ParseIP(oldUrl) == nil {
		domain = util.GetMainDomain(oldUrl)
	}

	return sources.MatchSubdomains(domain, body, false)

}

func match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := util.GetPartString(matcher.Part, data)
	if !ok {
		return false, []string{}
	}
	switch matcher.GetType() {
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(types.ToString(item), data))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(types.ToString(item)))
	case matchers.HashMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchHash(types.ToString(item)))
	case matchers.StatusMatcher:
		statusCode, ok := getStatusCode(data)
		if !ok {
			return false, []string{}
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode)), []string{}

	}
	return false, []string{}
}
func getStatusCode(data map[string]interface{}) (int, bool) {
	statusCodeValue, ok := data["status_code"]
	if !ok {
		return 0, false
	}
	statusCode, ok := statusCodeValue.(int)
	if !ok {
		return 0, false
	}
	return statusCode, true
}
func (scanner *Scanner) getEvent(request *retryablehttp.Request, resp *Response) (event output.ResultEvent, err error) {
	parseURL := request.URL
	requestRaw, _ := request.Dump()

	ip := scanner.getDialedIP(parseURL.String())
	var ips, cnames []string
	if parseURL.Hostname() != ip {
		ips, cnames, _ = scanner.getDNSData(parseURL.Hostname())
		if len(ips) > 0 && ip == "" {
			ip = ips[0]
		}
	} else {
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	title := scanner.getTitle(string(resp.Data))

	event = output.ResultEvent{
		TimeStamp:     time.Now(),
		URL:           parseURL.Scheme + "://" + parseURL.Host,
		Path:          parseURL.GetRelativePath(),
		Method:        request.Method,
		Title:         title,
		Host:          ip,
		A:             ips,
		CNAME:         cnames,
		Status:        resp.StatusCode,
		ContentLength: resp.ContentLength,
		Server:        strings.Join(resp.Headers["server"], ","),
		ResponseBody:  string(resp.Data),
		RequestBody:   string(requestRaw),
		Header:        resp.Headers,
	}
	return
}
