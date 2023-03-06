package runner

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/wjlin0/pathScan/pkg/result"
	"io"
	"net/http"
	"net/url"
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
	reg := regexp.MustCompile(`<title.*>(.*?)</title>`)
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
	server := resp.Header.Get("Server")

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
		Server:  server,
	}
	return re, nil
}
func (r *Runner) verifyTarget(target string) (bool, error) {
	path1 := RandStr(5) + "/" + RandStr(5)
	path2 := RandStr(5) + "/" + RandStr(5)
	p1, _ := url.JoinPath(target, path1)
	p2, _ := url.JoinPath(target, path2)
	get1, err1 := r.client.Get(p1)
	get2, err2 := r.client.Get(p2)
	if err1 != nil || err2 != nil {
		return false, errors.New(fmt.Sprintf("错误的两次请求：%s", target))
	}

	defer get1.Body.Close()
	defer get2.Body.Close()
	body1, _ := io.ReadAll(get1.Body)
	body2, _ := io.ReadAll(get2.Body)
	if get1.StatusCode == 200 && get2.StatusCode == 200 && (string(body1) == string(body2)) {
		return true, nil
	}
	return false, nil
}
