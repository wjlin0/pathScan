package identification

import (
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
	"github.com/wjlin0/pathScan/pkg/util"
)

type Options struct {
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

func (o *Options) loadConfigFrom(location string) error {
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), o)
}

func parserOptionsByDir(dir string) ([]*Options, error) {
	var options []*Options
	var sumErr error
	extension, err := util.ListFilesWithExtension(dir, ".yaml")
	if err != nil {
		return nil, err
	}
	for _, ext := range extension {
		o := &Options{}
		e := o.loadConfigFrom(ext)
		if e != nil {
			sumErr = e
			continue
		}
		var errorIndices []int
		for j, sub := range o.SubMatch {
			err = sub.Compile()
			if e != nil {
				sumErr = e
				errorIndices = append(errorIndices, j)
			}
		}
		// 根据错误项的索引，删除 SubMatch 切片中对应的项
		for k := len(errorIndices) - 1; k >= 0; k-- {
			index := errorIndices[k]
			o.SubMatch = append(o.SubMatch[:index], o.SubMatch[index+1:]...)
		}
		options = append(options, o)
	}

	return options, sumErr
}

func ParserHandler(path string) ([]*Options, error) {
	return parserOptionsByDir(path)
}
