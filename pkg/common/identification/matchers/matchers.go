package matchers

import "regexp"

// ConditionType is the type of condition for matcher
type ConditionType int

const (
	// ANDCondition matches responses with AND condition in arguments.
	ANDCondition ConditionType = iota + 1
	// ORCondition matches responses with AND condition in arguments.
	ORCondition
)

// ConditionTypes is a table for conversion of condition type from string.
var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}

type Matcher struct {
	// description: |
	//   Type is the type of the matcher.
	Type MatcherTypeHolder `yaml:"type" jsonschema:"title=type of matcher,description=Type of the matcher,enum=status,enum=size,enum=word,enum=regex,enum=binary,enum=dsl"`
	// description: |
	//   Condition is the optional condition between two matcher variables. By default,
	//   the condition is assumed to be OR.
	// values:
	//   - "and"
	//   - "or"
	Condition string `yaml:"condition,omitempty" jsonschema:"title=condition between matcher variables,description=Condition between the matcher variables,enum=and,enum=or"`

	// description: |
	//   Part is the part of the request response to match data from.
	//
	//   Each protocol exposes a lot of different parts which are well
	//   documented in docs for each request type.
	// examples:
	//   - value: "\"body\""
	//   - value: "\"raw\""
	Part string `yaml:"part,omitempty" jsonschema:"title=part of response to match,description=Part of response to match data from"`

	// description: |
	//   Name of the matcher. Name should be lowercase and must not contain
	//   spaces or underscores (_).
	// examples:
	//   - value: "\"cookie-matcher\""
	Name string `yaml:"name,omitempty" jsonschema:"title=name of the matcher,description=Name of the matcher"`
	// description: |
	//   Words contains word patterns required to be present in the response part.
	// examples:
	//   - name: Match for Outlook mail protection domain
	//     value: >
	//       []string{"mail.protection.outlook.com"}
	//   - name: Match for application/json in response headers
	//     value: >
	//       []string{"application/json"}
	Words []string `yaml:"words,omitempty" jsonschema:"title=words to match in response,description= Words contains word patterns required to be present in the response part"`
	// description: |
	//   Regex contains Regular Expression patterns required to be present in the response part.
	// examples:
	//   - name: Match for Linkerd Service via Regex
	//     value: >
	//       []string{`(?mi)^Via\\s*?:.*?linkerd.*$`}
	//   - name: Match for Open Redirect via Location header
	//     value: >
	//       []string{`(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)example\\.com.*$`}
	Regex []string `yaml:"regex,omitempty" jsonschema:"title=regex to match in response,description=Regex contains regex patterns required to be present in the response part"`
	// description: |
	//   DSL are the dsl expressions that will be evaluated as part of nuclei matching rules.
	//   A list of these helper functions are available [here](https://nuclei.projectdiscovery.io/templating-guide/helper-functions/).
	// examples:
	//   - name: DSL Matcher for package.json file
	//     value: >
	//       []string{"contains(body, 'packages') && contains(tolower(all_headers), 'application/octet-stream') && status_code == 200"}
	//   - name: DSL Matcher for missing strict transport security header
	//     value: >
	//       []string{"!contains(tolower(all_headers), ''strict-transport-security'')"}
	MatchAll bool `yaml:"match-all,omitempty" jsonschema:"title=match all values,description=match all matcher values ignoring condition"`
	Group    int  `yaml:"group,omitempty"`
	// cached data for the compiled matcher
	condition     ConditionType
	matcherType   MatcherType
	regexCompiled []*regexp.Regexp
}

// ResultWithMatchedSnippet returns true and the matched snippet, or false and an empty string
func (matcher *Matcher) ResultWithMatchedSnippet(data bool, matchedSnippet []string) (bool, []string) {
	return data, matchedSnippet
}
