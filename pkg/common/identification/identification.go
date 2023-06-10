package identification

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
	"path/filepath"
)

type Options struct {
	Version  string       `yaml:"version"`
	SubMatch []*Operators `yaml:"rules"`
}

type Operators struct {
	Name              string              `yaml:"name"`
	Matchers          []*matchers.Matcher `yaml:"matchers"`
	MatchersCondition string              `yaml:"matchers-condition"`
	matchersCondition matchers.ConditionType
}
type MatchFunc func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)

func (operators *Operators) Compile() error {
	if operators.MatchersCondition != "" {
		operators.matchersCondition = matchers.ConditionTypes[operators.MatchersCondition]
	} else {
		operators.matchersCondition = matchers.ORCondition
	}

	for _, matcher := range operators.Matchers {
		if err := matcher.CompileMatchers(); err != nil {
			return errors.Wrap(err, "could not compile matcher")
		}
	}
	return nil
}
func (operators *Operators) Execute(data map[string]interface{}, match MatchFunc) ([]string, bool) {
	var matches bool
	Name := make(map[string][]string)
	matcherCondition := operators.GetMatchersCondition()
	for _, matcher := range operators.Matchers {
		if isMatch, matched := match(data, matcher); isMatch { // if it's a "named" matcher with OR condition, then display it
			if matcherCondition == matchers.ORCondition {
				if matcher.Name != "" {
					Name[matcher.Name] = matched
				} else {
					Name[operators.Name] = []string{operators.Name}
				}
			}
			matches = true
		} else if matcherCondition == matchers.ANDCondition {
			return nil, false
		}
	}
	if len(operators.Matchers) > 0 && !matches {
		return nil, false
	}
	if matches && matcherCondition == matchers.ANDCondition {
		Name[operators.Name] = []string{operators.Name}
	}
	if len(Name) > 0 || matches {
		return func(m map[string][]string) []string {
			var s []string
			for _, v := range m {

				s = append(s, v...)
			}
			return s
		}(Name), true
	}
	return nil, false
}

// GetMatchersCondition returns the condition for the matchers
func (operators *Operators) GetMatchersCondition() matchers.ConditionType {
	return operators.matchersCondition
}

var defaultMatchConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan", "match-config.yaml")

func ParsesDefaultOptions(u string) (*Options, error) {
	options := &Options{}
	var err error
	if u != "" {
		err = options.loadConfigFrom(u)
		if err != nil {
			return nil, err
		}
	} else {
		err = options.loadConfigFrom(defaultMatchConfigLocation)
	}
	if err != nil {
		gologger.Debug().Msg(err.Error())
	}
	for _, sub := range options.SubMatch {
		err := sub.Compile()
		if err != nil {
			return nil, err
		}
	}
	return options, nil

}
func (o *Options) loadConfigFrom(location string) error {
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), o)
}
