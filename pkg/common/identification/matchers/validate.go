package matchers

import (
	"fmt"
	"github.com/pkg/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"gopkg.in/yaml.v3"
	"reflect"
	"strings"
)

var commonExpectedFields = []string{"Type", "Condition", "Name", "MatchAll", "Group"}

// Validate perform initial validation on the matcher structure
func (matcher *Matcher) Validate() error {
	// uses yaml marshaling to convert the struct to map[string]interface to have same field names
	matcherMap := make(map[string]interface{})
	marshaledMatcher, err := yaml.Marshal(matcher)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(marshaledMatcher, &matcherMap); err != nil {
		return err
	}

	var expectedFields []string
	switch matcher.matcherType {
	case WordsMatcher:
		expectedFields = append(commonExpectedFields, "Words", "Part")
	case RegexMatcher:
		expectedFields = append(commonExpectedFields, "Regex", "Part")
	}
	return checkFields(matcher, matcherMap, expectedFields...)
}

func checkFields(m *Matcher, matcherMap map[string]interface{}, expectedFields ...string) error {
	var foundUnexpectedFields []string
	for marshaledFieldName := range matcherMap {
		// revert back the marshaled name to the original field
		structFieldName, err := getFieldNameFromYamlTag(marshaledFieldName, *m)
		if err != nil {
			return err
		}
		if !sliceutil.Contains(expectedFields, structFieldName) {
			foundUnexpectedFields = append(foundUnexpectedFields, structFieldName)
		}
	}
	if len(foundUnexpectedFields) > 0 {
		return fmt.Errorf("matcher %s has unexpected fields: %s", m.matcherType, strings.Join(foundUnexpectedFields, ","))
	}
	return nil
}

func getFieldNameFromYamlTag(tagName string, object interface{}) (string, error) {
	reflectType := reflect.TypeOf(object)
	if reflectType.Kind() != reflect.Struct {
		return "", errors.New("the object must be a struct")
	}
	for idx := 0; idx < reflectType.NumField(); idx++ {
		field := reflectType.Field(idx)
		tagParts := strings.Split(field.Tag.Get("yaml"), ",")
		if len(tagParts) > 0 && tagParts[0] == tagName {
			return field.Name, nil
		}
	}
	return "", fmt.Errorf("field %s not found", tagName)
}
