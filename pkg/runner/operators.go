package runner

import (
	"bytes"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
	"github.com/wjlin0/pathScan/pkg/query/utils"
	"github.com/wjlin0/pathScan/pkg/util"
	"net"
	"strings"
)

func Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := getMatchPart(matcher.Part, data)
	if !ok {
		return false, []string{}
	}
	switch matcher.GetType() {
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(item, data))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(item))
	}
	return false, []string{}
}

func (r *Runner) ParseTechnology(data map[string]interface{}) []string {
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
func (r *Runner) ParseOtherUrl(oldUrl string, domains []string, data ...[]byte) []string {
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
			for _, d1 := range utils.MatchSubdomains(k, body, false) {
				matchDomains[d1] = struct{}{}
			}
		}
		domains = []string{}
		for k, _ := range matchDomains {
			domains = append(domains, k)
		}
		return domains
	}
	if net.ParseIP(oldUrl) != nil {
		return nil
	}
	domain := util.GetMainDomain(oldUrl)
	return utils.MatchSubdomains(domain, body, false)

}

func getMatchPart(part string, data map[string]interface{}) (string, bool) {
	if part == "" {
		part = "body"
	}
	if part == "header" {
		part = "all_headers"
	}
	var itemStr string

	if part == "all" {
		builder := &strings.Builder{}
		builder.WriteString(types.ToString(data["body"]))
		builder.WriteString(types.ToString(data["all_headers"]))
		itemStr = builder.String()
	} else {
		item, ok := data[part]
		if !ok {
			return "", false
		}
		itemStr = types.ToString(item)
	}
	return itemStr, true
}
