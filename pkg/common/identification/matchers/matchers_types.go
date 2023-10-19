package matchers

import (
	"encoding/json"
	"errors"
	"strings"
)

// MatcherType is the type of the matcher specified
type MatcherType int

// name:MatcherType
const (
	// name:word
	WordsMatcher MatcherType = iota + 1
	// name:regex
	RegexMatcher
	HashMatcher
)

// MatcherTypes is a table for conversion of matcher type from string.
var MatcherTypes = map[MatcherType]string{
	WordsMatcher: "word",
	RegexMatcher: "regex",
	HashMatcher:  "hash",
}

// GetType returns the type of the matcher
func (matcher *Matcher) GetType() MatcherType {
	return matcher.Type.MatcherType
}

func toMatcherTypes(valueToMap string) (MatcherType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range MatcherTypes {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid matcher type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (t MatcherType) String() string {
	return MatcherTypes[t]
}

// MatcherTypeHolder is used to hold internal type of the matcher
type MatcherTypeHolder struct {
	MatcherType MatcherType `mapping:"true"`
}

func (t MatcherTypeHolder) String() string {
	return t.MatcherType.String()
}

func (holder *MatcherTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toMatcherTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.MatcherType = computedType
	return nil
}

func (holder MatcherTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.MatcherType.String())
}

func (holder MatcherTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.MatcherType.String(), nil
}
