package runner

import (
	"io"
	"net/http"
	"net/url"
	"pathScan/pkg/result"
	"regexp"
)

func (r *Runner) ConnectTarget(target string) (bool, error) {

	request, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("User-Agent", r.GetUserAgent())
	_, err = r.client.Do(request)
	if err != nil {
		return false, err
	}
	return true, err
}

func (r *Runner) GoTargetPath(target, path string) (*result.TargetResult, error) {
	defer r.wg.Done()
	reg := regexp.MustCompile(`<title>(.*?)</title>`)
	_url, err := url.JoinPath(target, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", r.GetUserAgent())
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t := reg.FindAllStringSubmatch(string(body), -1)
	title := ""
	if len(t) == 0 {
	} else if len(t[0]) <= 1 {
	} else if len(t[0]) == 2 {
		title = t[0][1]
	}
	if len(body) == 0 {
		title = "该请求内容为0"
	}
	re := &result.TargetResult{
		Target:  target,
		Path:    path,
		Title:   title,
		Status:  resp.StatusCode,
		BodyLen: len(string(body)),
	}

	return re, nil
}
