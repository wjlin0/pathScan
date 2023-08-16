package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

func MatchSubdomains(domain string, html string, fuzzy bool) []string {
	if !fuzzy {
		reg := regexp.MustCompile(fmt.Sprintf(`(?i)(?:\>|\"|\'|\=|\,)(?:http\:\/\/|https\:\/\/)+(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}%s`, domain))
		submatch := reg.FindAllString(html, -1)
		if len(submatch) == 0 {
			return submatch
		}
		var processed []string
		for _, s := range submatch {
			parse, err := url.Parse(s[1:])
			if err != nil {
				continue
			}
			processed = append(processed, parse.Hostname())
		}
		return func(processed []string) (newSubMatch []string) {
			// 去重
			s := make(map[string]struct{})
			for i := 0; i < len(processed); i++ {
				s[strings.ToLower(processed[i])] = struct{}{}
			}
			for k, _ := range s {
				newSubMatch = append(newSubMatch, k)
			}
			return
		}(processed)
	}
	reg := regexp.MustCompile(fmt.Sprintf(`(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}%s`, domain))
	submatch := reg.FindAllString(html, -1)
	return func(submatch []string) (newSubMatch []string) {
		s := make(map[string]struct{})
		for i := 0; i < len(submatch); i++ {
			s[strings.ToLower(submatch[i])] = struct{}{}
		}
		for k, _ := range s {
			newSubMatch = append(newSubMatch, k)
		}
		return
	}(submatch)
}
