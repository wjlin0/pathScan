package sources

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

func NewHTTPRequest(method, url string, body io.Reader) (*retryablehttp.Request, error) {
	request, err := retryablehttp.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "PathScan - FOSS Project (github.com/wjlin0/pathScan)")
	return request, nil
}

func GetHostname(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	return parsedURL.Hostname(), nil
}

var ifDomainReg = regexp.MustCompile("(?i)[a-z0-9][-a-z0-9]{0,62}(\\.[a-z0-9][-a-z0-9]{0,62})+$")

func DefaultQuery(query string, engine string) string {
	if !ifDomainReg.MatchString(query) {
		return query
	}
	switch engine {
	case "fofa":
		return fmt.Sprintf("domain=\"%s\"", query)
	case "quake":
		return fmt.Sprintf("domain:\"%s\"", query)
	case "zoomeye":
		return fmt.Sprintf("site:%s", query)
	case "hunter":
		return fmt.Sprintf("domain=\"%s\"", query)
	case "shodan":
		return fmt.Sprintf("hostname:%s", query)
	default:
		return query
	}
}
func MatchSubdomains(domain string, html string, fuzzy bool) []string {
	domain = regexp.QuoteMeta(domain)
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
