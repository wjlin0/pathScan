package runner

import (
	"bytes"
	http "github.com/projectdiscovery/retryablehttp-go"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"math/rand"
	defaultHttp "net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var regByRetry = regexp.MustCompile(`<title.*>(.*?)</title>`)

func (r *Runner) customRetryableHeader(req *http.Request) {
	for k, v := range r.headers {
		switch v.(type) {
		case string:
			req.Header.Set(k, v.(string))
		case []string:
			rand.Seed(time.Now().Unix())
			i := v.([]string)
			req.Header.Set(k, i[rand.Intn(len(i))])
		}
	}
}

func (r *Runner) createRetryableRequest(target, path string) (*http.Request, error) {
	_url, err := url.JoinPath(target, path)
	if err != nil {
		return nil, err
	}
	method := "GET"
	if r.Cfg.Options.Method != "" {
		method = r.Cfg.Options.Method
	}
	req, err := http.NewRequest(method, _url, nil)
	if err != nil {
		return nil, err
	}
	r.customRetryableHeader(req)
	return req, nil
}
func (r *Runner) readRetryableHeader(resp *defaultHttp.Response) ([]byte, error) {
	buffer := bytes.Buffer{}
	err := resp.Header.Write(&buffer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func (r *Runner) readRetryableBody(resp *defaultHttp.Response) ([]byte, error) {
	buffer := bytes.Buffer{}
	_, err := io.Copy(&buffer, resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return buffer.Bytes(), nil
}

func (r *Runner) extractRetryableTitle(body []byte) string {
	t := regByRetry.FindStringSubmatch(string(body))
	if len(t) >= 2 {
		return t[1]
	}
	return ""
}
func (r *Runner) processRetryableResponse(target, path string, resp *defaultHttp.Response) (*result.TargetResult, bool, error) {
	headerBytes, err := r.readRetryableHeader(resp)
	if err != nil {
		return nil, false, err
	}

	bodyBytes, err := r.readRetryableBody(resp)
	if err != nil {
		return nil, false, err
	}

	title := r.extractTitle(bodyBytes)
	server := resp.Header.Get("Server")

	re := &result.TargetResult{
		Target:  target,
		Path:    path,
		Title:   title,
		Status:  resp.StatusCode,
		BodyLen: len(bodyBytes),
		Server:  server,
	}

	// 跳过
	check := r.checkSkip(re, headerBytes, bodyBytes)
	if check {
		return re, check, nil
	}
	tech := r.Parse(map[string]interface {
	}{
		"all_headers": headerBytes,
		"body":        bodyBytes,
	})
	re.Technology = tech
	return re, false, nil
}
func (r *Runner) checkSkip(re *result.TargetResult, head []byte, body []byte) bool {
	option := r.Cfg.Options
	if _, ok := r.skipCode[strconv.Itoa(re.Status)]; ok {
		return true
	}
	if option.SkipHash != "" {
		bodyHash, _ := util.GetHash(body, option.SkipHashMethod)
		if option.SkipHash == string(bodyHash) {
			return true
		}
	}

	if option.SkipBodyLen == re.BodyLen {
		return true
	}

	return false

}
func (r *Runner) GoTargetPathByRetryable(target, path string) (*result.TargetResult, bool, error) {
	req, err := r.createRetryableRequest(target, path)
	if err != nil {
		return nil, false, err
	}
	resp, err := r.retryable.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	re, check, err := r.processRetryableResponse(target, path, resp)
	if err != nil {
		return nil, false, err
	}
	return re, check, err
}

func newRetryableClient(options *Options, errUseLastResponse bool) *http.Client {
	httpOptions := http.Options{
		Timeout:      options.TimeoutHttp,
		RetryMax:     options.Retries,
		RetryWaitMax: options.TimeoutHttp,
		HttpClient:   newClient(options, errUseLastResponse),
	}
	return http.NewClient(httpOptions)
}
