package runner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
	"github.com/wjlin0/pathScan/pkg/util"
	"net/url"
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
func (r *Runner) ParseOtherUrl(oldUrl string, data map[string]interface{}) []string {
	var all []string
	// 提取响应包的 body 数据
	body, ok := data["body"].([]byte)
	if !ok {
		return nil
	}
	all = util.ExtractURLs(string(body))
	var urls []string
	// 过滤不属于子域名或基本URL的链接

	for _, link := range all {
		if link == "" {
			continue
		}
		var links []string
		if !strings.HasPrefix(link, "http") {
			links = append(links, "http://"+link)
			links = append(links, "https://"+link)
		} else {
			links = append(links, link)
		}
		for _, link := range links {
			if _, err := url.Parse(link); err != nil {
				continue
			}
			switch {
			case r.Cfg.Options.FindOtherDomain:
				parse, _ := url.Parse(link)
				urls = append(urls, util.GetTrueUrl(parse))
			case r.Cfg.Options.FindOtherLink:
				if !util.IsSubdomainOrSameDomain(oldUrl, link) {
					continue
				}

				if util.IsBlackPath(link) {
					continue
				}
				urls = append(urls, link)
			}
		}

	}

	return urls
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
