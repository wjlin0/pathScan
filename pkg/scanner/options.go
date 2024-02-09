package scanner

import (
	sliceutil "github.com/projectdiscovery/utils/slice"
	"net/url"
	"strings"
)

func (scanner *Scanner) IsSkipURL(URL string) bool {
	var (
		parseURL *url.URL
		err      error
	)
	if len(scanner.options.SkipURL) == 0 {
		return false
	}
	if sliceutil.Contains(scanner.options.SkipURL, URL) {
		return true
	}
	if parseURL, err = url.Parse(URL); err != nil {
		return true
	}

	for _, skip := range scanner.options.SkipURL {
		switch {
		case strings.HasPrefix(skip, "*."):
			if parseURL.Hostname() == skip[2:] || strings.HasSuffix(parseURL.Hostname(), skip[1:]) {
				return true
			}
		default:
			if parseURL.Hostname() == skip {
				return true
			}
		}
	}

	return false
}
