package input

import (
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/retryablehttp-go"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"strings"
)

const (
	// HTTP defines the plain http scheme
	HTTP = "http"
	// HTTPS defines the secure http scheme
	HTTPS = "https"
	// HTTPorHTTPS defines both http and https scheme in mutual exclusion
	HTTPorHTTPS = "http|https"
	// HTTPandHTTPS defines both http and https scheme
	HTTPandHTTPS = "http&https"
)

type Target struct {
	// Host is the host input on which match was found.
	Host string `json:"host,omitempty"`
	// Scheme is the scheme of the host input on which match was found (if applicable).
	Scheme string `json:"scheme,omitempty"`
	// Methods is the method of the host input on which match was found (if applicable).
	Methods []string `json:"methods,omitempty"`

	// Headers is the headers of the host input on which match was found (if applicable).
	Headers map[string]interface{} `json:"headers,omitempty"`

	// paths is the paths of the host input on which match was found (if applicable).
	Paths []string `json:"paths,omitempty"`
	// Body is the body of the host input on which match was found (if applicable).
	Body string `json:"body,omitempty"`
	// BasePath is the base path of the host input on which match was found (if applicable).
	BasePath string `json:"base-path"`
}

func NewTarget(target string, methods []string, headers map[string]interface{}, paths []string, body string) *Target {
	var (
		host   string
		scheme string
	)

	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	if strings.Contains(target, "://") {
		hostAndScheme := strings.Split(target, "://")
		switch hostAndScheme[0] {
		case HTTP:
			scheme = HTTP
		case HTTPS:
			scheme = HTTPS
		case HTTPandHTTPS:
			scheme = HTTPandHTTPS
		default:
			scheme = HTTPorHTTPS
		}
		host = hostAndScheme[1]

	} else {
		host = target
		scheme = HTTPorHTTPS
	}
	host = strings.TrimSuffix(host, "/")
	magicPath := ""
	// 如果 此时依旧存在 / 说明存在路径
	if strings.Contains(host, "/") {
		index := strings.Index(host, "/")
		magicPath = host[index:]
		host = host[:index]
	}
	// 如果 host中有 端口号 且不是ipv6
	if strings.Contains(host, ":") && !strings.Contains(host, "]") {
		port := strings.Split(host, ":")[1]
		if port == "80" && scheme == HTTP {
			host = strings.Split(host, ":")[0]
		}
		if port == "443" && scheme == HTTPS {
			host = strings.Split(host, ":")[0]
		}
	}

	// 处理 每个path 的正确性,并去重
	var newPaths []string
	for _, path := range paths {

		if magicPath != "" && path != "/" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			path = magicPath + path
		} else if magicPath != "" && path == "/" {
			path = magicPath
		}

		if path == "/" {
			if !sliceutil.Contains(newPaths, path) {
				newPaths = append(newPaths, path)
			}
			continue
		}

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if !sliceutil.Contains(newPaths, path) {
			newPaths = append(newPaths, path)
		}
	}

	// 如果 path 为空，设置默认值
	if len(paths) == 0 && magicPath != "" {
		newPaths = append(newPaths, magicPath)
	}

	return &Target{
		Host:     host,
		Scheme:   scheme,
		Methods:  methods,
		BasePath: magicPath,
		Headers:  headers,
		Paths:    newPaths,
		Body:     body,
	}

}

func DecomposeHost(targets []string, methods []string, headers map[string]interface{}, paths []string, body string) chan *Target {
	results := make(chan *Target)
	go func() {
		defer close(results)
		for _, target := range targets {
			target = strings.TrimSpace(target)

			switch {
			case stringsutil.HasPrefixAny(target, "*", "."):
				// A valid target does not contain:
				// trim * and/or . (prefix) from the target to return the domain instead of wilcard
				target = stringsutil.TrimPrefixAny(target, "*", ".")

				results <- NewTarget(target, methods, headers, paths, body)

			case asn.IsASN(target):
				cidrIps, err := asn.GetIPAddressesAsStream(target)
				if err != nil {
					return
				}
				for ip := range cidrIps {
					results <- NewTarget(ip, methods, headers, paths, body)
				}
			case iputil.IsCIDR(target):
				cidrIps, err := mapcidr.IPAddressesAsStream(target)
				if err != nil {
					return
				}
				for ip := range cidrIps {
					results <- NewTarget(ip, methods, headers, paths, body)
				}
			case !stringsutil.HasPrefixAny(target, "http://", "https://") && stringsutil.ContainsAny(target, ","):
				idxComma := strings.Index(target, ",")
				results <- NewTarget(target[:idxComma], methods, headers, paths, body)
			default:
				results <- NewTarget(target, methods, headers, paths, body)
			}
		}
	}()
	return results
}

func (target *Target) NewRequest(method, URL string) (*retryablehttp.Request, error) {
	request, err := retryablehttp.NewRequest(method, URL, target.Body)
	if err != nil {
		return nil, err
	}
	for k, v := range target.Headers {
		request.Header.Set(k, v.(string))
	}
	return request, nil
}
func (target *Target) Clone() *Target {
	return &Target{
		Host:    target.Host,
		Scheme:  target.Scheme,
		Methods: target.Methods,
		Headers: target.Headers,
		Paths:   target.Paths,
		Body:    target.Body,
	}
}

// IsDuplicate 判断target是否是重复的
func (target *Target) IsDuplicate(target2 *Target) bool {

	if target.Host != target2.Host {
		return false
	}
	if target.Scheme != target2.Scheme {
		return false
	}
	if !sliceutil.Equal(target.Methods, target2.Methods) {
		return false
	}
	if !sliceutil.Equal(target.Paths, target2.Paths) {
		return false
	}
	if target.Body != target2.Body {
		return false
	}
	return true
}
