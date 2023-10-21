package runner

import (
	"bytes"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/sources"
	"github.com/wjlin0/pathScan/pkg/util"
	"net"
)

func Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
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

func (r *Runner) parseTechnology(data map[string]interface{}) []string {
	var tag []string
	for _, options := range r.regOptions {
		for _, sub := range options.SubMatch {
			execute, b := sub.Execute(data, Match)
			if b && !(len(execute) == 1 && execute[0] == "") {
				tag = append(tag, execute...)
			}
		}
	}

	return tag
}
func (r *Runner) parseOtherUrl(oldUrl string, domains []string, data ...[]byte) []string {
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
