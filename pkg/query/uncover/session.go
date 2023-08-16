package uncover

import (
	"crypto/tls"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryablehttp-go"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Session struct {
	Client   *retryablehttp.Client
	RetryMax int
}

func NewSession(retryMax int, timeout time.Duration, proxyFunc func(*http.Request) (*url.URL, error)) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: timeout,
		Proxy:                 proxyFunc,
	}

	httpclient := &http.Client{
		Transport: Transport,
		Timeout:   timeout,
	}

	options := retryablehttp.Options{RetryMax: retryMax}
	options.RetryWaitMax = timeout
	options.HttpClient = httpclient
	client := retryablehttp.NewClient(options)

	session := &Session{
		Client:   client,
		RetryMax: retryMax,
	}

	return session, nil
}
func NewHTTPRequest(method, url string, body io.Reader) (*retryablehttp.Request, error) {
	request, err := retryablehttp.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "PathScan - FOSS Project (github.com/wjlin0/pathScan)")
	request.Header.Set("Accept", "*/*")
	return request, nil
}

func (s *Session) Do(request *retryablehttp.Request) (*http.Response, error) {
	// close request connection (does not reuse connections)
	request.Close = true
	resp, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}
	//fmt.Println(resp.Body.Read(nil))

	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())
		return resp, errors.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}
	// var f *os.file
	// var err error
	// if _, _, ok := request.BasicAuth(); ok {
	// 	f, err = os.Open("/Users/marcornvh/go/src/github.com/projectdiscovery/uncover/uncover/agent/censys/example.json")
	// } else {
	// 	f, err = os.Open("/Users/marcornvh/go/src/github.com/projectdiscovery/uncover/uncover/agent/shodan/example.json")
	// }

	if err != nil {
		return nil, err
	}

	// resp := &http.Response{
	// 	StatusCode: 200,
	// 	Body:       f,
	// }
	return resp, nil
}
