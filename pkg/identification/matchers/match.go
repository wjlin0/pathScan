package matchers

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"strings"
)

func (matcher *Matcher) MatchWords(corpus string, data map[string]interface{}) (bool, []string) {

	var matchedWords []string
	// Iterate over all the words accepted as valid
	for i, word := range matcher.Words {
		if data == nil {
			data = make(map[string]interface{})
		}

		var err error
		word, err = expressions.Evaluate(word, data)
		if err != nil {
			gologger.Warning().Msgf("Error while evaluating word matcher: %q", word)
			if matcher.condition == ANDCondition {
				return false, []string{}
			}
		}
		// Continue if the word doesn't match
		if !strings.Contains(corpus, word) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, []string{word}
		}
		matchedWords = append(matchedWords, word)

		// If we are at the end of the words, return with true
		if len(matcher.Words)-1 == i && !matcher.MatchAll {
			return true, matchedWords
		}
	}
	if len(matchedWords) > 0 && matcher.MatchAll {
		return true, matchedWords
	}
	return false, []string{}
}

// MatchRegex matches a regex check against a corpus
func (matcher *Matcher) MatchRegex(corpus string) (bool, []string) {
	var matchedRegexes []string
	// Iterate over all the regexes accepted as valid
	for i, regex := range matcher.regexCompiled {
		// Continue if the regex doesn't match
		if !regex.MatchString(corpus) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}
		currentMatches := regex.FindStringSubmatch(corpus)
		if !(matcher.Group <= 0) && (len(currentMatches)-1 >= matcher.Group) {

			if matcher.Alias {
				if currentMatches[matcher.Group] != "" {
					currentMatches = []string{fmt.Sprintf("%s:%s", matcher.Name, currentMatches[matcher.Group])}
				} else {
					currentMatches = []string{fmt.Sprintf("%s", matcher.Name)}
				}
			} else {
				currentMatches = []string{currentMatches[matcher.Group]}
			}
		}
		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, currentMatches
		}
		matchedRegexes = append(matchedRegexes, currentMatches...)
		// If we are at the end of the regex, return with true
		if len(matcher.regexCompiled)-1 == i && !matcher.MatchAll {
			return true, matchedRegexes
		}
	}
	if len(matchedRegexes) > 0 && matcher.MatchAll {
		return true, matchedRegexes
	}
	return false, []string{}
}

// MatchHash returns true if the corpus matches the favicon
func (matcher *Matcher) MatchHash(corpus string) (bool, []string) {
	hashMethod := "sha256"
	if matcher.HashMethod != "" {
		hashMethod = matcher.HashMethod
	}
	hash, err := util.GetHash([]byte(corpus), hashMethod)
	if err != nil {
		return false, nil
	}
	for _, fav := range matcher.Hash {
		if string(hash) == (fav) {
			return true, []string{matcher.Name}
		}
	}
	return false, nil
}

// MatchStatusCode matches a status code check against a corpus
func (matcher *Matcher) MatchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	//
	// Status codes don't support AND conditions.
	for _, status := range matcher.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}
