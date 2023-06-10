package runner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
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

func (r *Runner) Parse(data map[string]interface{}) []string {
	var tag []string
	for _, sub := range r.regOptions.SubMatch {
		execute, b := sub.Execute(data, Match)
		if b && !(len(execute) == 1 && execute[0] == "") {
			tag = append(tag, execute...)
		}
	}
	return tag
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
