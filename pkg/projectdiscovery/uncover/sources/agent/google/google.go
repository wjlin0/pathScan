package google

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/sources"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	URL     = "https://www.google.com/search?q=%s&start=%d&num=50&filter=0&btnG=Search&gbv=1&hl=en"
	URLInit = "https://www.google.com/"
	Source  = "google"
)

type Agent struct {
	options *sources.Agent
}
type googleRequest struct {
	Q     string `json:"q"`
	Start int    `json:"start"`
}

func (agent *Agent) Name() string {
	return Source
}
func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {

	results := make(chan sources.Result)
	start := time.Now()
	go func() {
		defer close(results)
		var (
			err             error
			cookies         []*http.Cookie
			Results         map[string]struct{}
			numberOfResults int
			page            int
			ignoreNum       int
		)
		defer func() {
			gologger.Info().Msgf("%s took %s seconds to enumerate %v results.", agent.Name(), time.Since(start).Round(time.Second).String(), numberOfResults)
		}()

		cookies, err = agent.queryCookies(session)
		if err != nil {
			results <- sources.Result{Source: agent.Name(), Error: errors.Wrap(err, "get google cookies error")}
			return
		}
		Results = make(map[string]struct{})
		page = 1
		ignoreNum = 1
		q := fmt.Sprintf("site:.%s", query.Query)
		for {
			for k, _ := range Results {
				if k == query.Query {
					continue
				}
				// 如果请求长度大于32,超过google搜索字段的最大长度，则改变搜索策略翻页
				if ignoreNum >= 34 {
					continue
				}
				q = fmt.Sprintf("%s -site:%s", q, k)
				ignoreNum++
			}
			googleReq := &googleRequest{
				Q:     q,
				Start: page,
			}
			googleResponse, stop := agent.query(session, query.Query, URL, cookies, googleReq, Results, results)
			numberOfResults += len(googleResponse)
			if stop || numberOfResults > query.Limit {
				break
			}

			for i := 0; i < len(googleResponse); i++ {
				Results[googleResponse[i]] = struct{}{}
			}

			if ignoreNum >= 34 {
				page += 50
			}
		}

	}()

	return results, nil
}
func (agent *Agent) queryCookies(session *sources.Session) ([]*http.Cookie, error) {
	request, err := sources.NewHTTPRequest(http.MethodGet, URLInit, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Googlebot")
	request.Header.Set("Referer", URLInit)
	resp, err := session.Do(request, Source)
	if err != nil {
		return nil, err
	}
	return resp.Cookies(), nil
}
func (agent *Agent) query(session *sources.Session, domain string, URL string, cookies []*http.Cookie, googleRequest *googleRequest, Results map[string]struct{}, results chan sources.Result) ([]string, bool) {
	var (
		shouldIgnoreErrors bool
		newSub             []string
	)
	resp, err := agent.queryURL(session, URL, cookies, googleRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: errors.Wrap(err, "request error")}
		return nil, true
	}
	defer resp.Body.Close()
	body := bytes.Buffer{}
	_, err = io.Copy(&body, resp.Body)
	if err != nil {
		if strings.ContainsAny(err.Error(), "tls: user canceled") {
			shouldIgnoreErrors = true
		}
		if !shouldIgnoreErrors {
			results <- sources.Result{Source: agent.Name(), Error: err}
			return nil, true
		}
	}
	sub := sources.MatchSubdomains(domain, body.String(), true)

	for _, google := range sub {

		if _, ok := Results[google]; ok {
			continue
		}
		newSub = append(newSub, google)
		_, host, port := util.GetProtocolHostAndPort(google)
		result := sources.Result{Source: agent.Name()}
		result.Host = host
		result.Port = port
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	if !strings.Contains(body.String(), fmt.Sprintf("start=%d", googleRequest.Start+50)) || strings.Contains(body.String(), "302 Moved") {
		return newSub, true
	}
	return newSub, false
}
func (agent *Agent) queryURL(session *sources.Session, URL string, cookies []*http.Cookie, googleRequest *googleRequest) (*http.Response, error) {

	googleURL := fmt.Sprintf(URL, googleRequest.Q, googleRequest.Start)
	request, err := sources.NewHTTPRequest(http.MethodGet, googleURL, nil)
	if err != nil {
		return nil, err
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("User-Agent", "Googlebot")
	request.Header.Set("Referer", URLInit)
	return session.Do(request, agent.Name())
}
