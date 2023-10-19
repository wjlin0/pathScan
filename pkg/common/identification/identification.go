package identification

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/wjlin0/pathScan/pkg/common/identification/matchers"
	"github.com/wjlin0/pathScan/pkg/util"
	"path/filepath"
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

var defaultMatchConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan", "match-config.yaml")

func parsesOptions(u string) (*Options, error) {
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

func parserOptionsByDir(dir string) ([]*Options, error) {
	var options []*Options
	extension, err := util.ListFilesWithExtension(dir, ".yaml")
	if err != nil {
		return nil, err
	}
	for _, ext := range extension {
		o := &Options{}
		err := o.loadConfigFrom(ext)
		if err != nil {
			gologger.Warning().Msg(err.Error())
			continue
		}
		options = append(options, o)
	}
	for i, o := range options {
		var errorIndices []int
		for j, sub := range o.SubMatch {
			err := sub.Compile()
			if err != nil {
				gologger.Warning().Msg(err.Error())
				errorIndices = append(errorIndices, j)
			}
		}
		// 根据错误项的索引，删除 SubMatch 切片中对应的项
		for k := len(errorIndices) - 1; k >= 0; k-- {
			index := errorIndices[k]
			o.SubMatch = append(o.SubMatch[:index], o.SubMatch[index+1:]...)
		}
		// 更新 options 中对应项的 SubMatch 切片
		options[i] = o
	}

	return options, nil
}

func ParserHandler(path string) ([]*Options, error) {
	var options []*Options
	var err error
	switch {
	case fileutil.FolderExists(path):
		options, err = parserOptionsByDir(path)
		if err != nil {
			return nil, err
		}
	case fileutil.FileExists(path):
		option, err := parsesOptions(path)
		if err != nil {
			return nil, err
		}
		options = append(options, option)
	default:
	}
	return options, nil
}
