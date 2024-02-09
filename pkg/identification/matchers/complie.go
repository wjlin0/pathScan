package matchers

import (
	"fmt"
	"regexp"
)

func (matcher *Matcher) CompileMatchers() error {
	var ok bool

	computedType, err := toMatcherTypes(matcher.GetType().String())
	if err != nil {
		return fmt.Errorf("没有匹配规则: %s", matcher.Type)
	}
	matcher.matcherType = computedType
	if err := matcher.Validate(); err != nil {
		return err
	}
	if matcher.Part == "" {
		matcher.Part = "body"
	}
	for _, regex := range matcher.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		matcher.regexCompiled = append(matcher.regexCompiled, compiled)
	}
	// Set up the condition type, if any.
	if matcher.Condition != "" {
		matcher.condition, ok = ConditionTypes[matcher.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", matcher.Condition)
		}
	} else {
		matcher.condition = ORCondition
	}
	return nil
}
