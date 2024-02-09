package identification

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	httputil "github.com/projectdiscovery/utils/http"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/wjlin0/pathScan/v2/pkg/identification/matchers"
	"github.com/wjlin0/pathScan/v2/pkg/identification/request"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"strings"
)

type Operators struct {
	Name              string                 `yaml:"name"`
	Matchers          []*matchers.Matcher    `yaml:"matchers"`
	MatchersCondition string                 `yaml:"matchers-condition"`
	Request           []*request.Request     `yaml:"request"`
	StopAtFirstMatch  bool                   `yaml:"stop-at-first-match"`
	matchersCondition matchers.ConditionType `yaml:"-"`
}
type MatchFunc func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)

func (operators *Operators) Compile() error {
	if operators.Name == "" {
		return errors.New("name is required")
	}
	if operators.Matchers == nil {
		return errors.New("matchers are required")
	}

	if operators.Request == nil || len(operators.Request) == 0 {
		return errors.New("request is required")
	}

	for _, req := range operators.Request {
		for i, path := range req.Path {
			if !strings.HasPrefix(path, "/") {
				req.Path[i] = "/" + path
			}
		}
	}

	for _, req := range operators.Request {
		if req.Method == "" {
			req.Method = "GET"
		}
		if !sliceutil.Contains(httputil.AllHTTPMethods(), strings.ToUpper(req.Method)) {
			return errors.New("method is not supported")
		}
		req.Method = strings.ToUpper(req.Method)
	}

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

func (operators *Operators) LoadConfigFrom(location string) error {
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), operators)
}

func NewOptions(path string) ([]*Operators, error) {
	var (
		options []*Operators
	)
	if fileutil.FileExists(path) {
		oper := &Operators{}
		if e := oper.LoadConfigFrom(path); e != nil {
			return nil, e
		}
		if e := oper.Compile(); e != nil {
			return nil, e
		}
		options = append(options, oper)
		return options, nil
	}

	extension, err := util.ListFilesWithExtension(path, ".yaml", ".yml")
	if err != nil {
		return nil, err
	}
	for _, ext := range extension {
		oper := &Operators{}
		if e := oper.LoadConfigFrom(ext); e != nil {
			gologger.Debug().Msgf("Could not load options from %s: %s\n", ext, e)
			continue
		}
		if e := oper.Compile(); e != nil {
			gologger.Debug().Msgf("Could not load options from %s: %s\n", ext, e)
			continue
		}

		options = append(options, oper)
	}

	return options, nil
}
