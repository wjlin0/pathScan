package bing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/wjlin0/pathScan/pkg/query/uncover"
	"github.com/wjlin0/pathScan/pkg/query/utils"
	"io"
	"net/http"
	"strings"
)

const (
	URL     = "https://www.bing.com/search?q=%s&first=%d&count=20"
	URLInit = "https://www.bing.com/"
	Source  = "BingQuery"
)

type Agent struct {
	options *uncover.AgentOptions
}
type bingRequest struct {
	Q     string `json:"q"`
	First int    `json:"first"`
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}
func (agent *Agent) Name() string {
	return Source
}
func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {

	results := make(chan uncover.Result)
	go func() {
		defer close(results)
		var (
			err             error
			cookies         []*http.Cookie
			Results         map[string]struct{}
			numberOfResults int
			page            int
		)
		cookies, err = agent.queryCookies(session)
		if err != nil {
			results <- uncover.Result{Source: agent.Name(), Error: errors.Wrap(err, "get bing cookies error")}
			return
		}
		Results = make(map[string]struct{})
		page = 0
		q := fmt.Sprintf("site:.%s", query.Query)
		for {
			for k, _ := range Results {
				if k == query.Query {
					continue
				}
				q = fmt.Sprintf("%s -site:%s", q, k)
			}
			bingReq := &bingRequest{
				Q:     q,
				First: page,
			}
			bingResponse := agent.query(session, query.Query, URL, cookies, bingReq, Results, results)
			if len(bingResponse) == 0 || numberOfResults > query.Limit {
				break
			}
			numberOfResults += len(bingResponse)

			for i := 0; i < len(bingResponse); i++ {
				Results[bingResponse[i]] = struct{}{}
			}
		}

	}()

	return results, nil
}
func (agent *Agent) query(session *uncover.Session, domain string, URL string, cookies []*http.Cookie, bingRequest *bingRequest, Results map[string]struct{}, results chan uncover.Result) []string {
	var (
		shouldIgnoreErrors bool
	)
	resp, err := agent.queryURL(session, URL, cookies, bingRequest)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: errors.Wrap(err, "request error")}
		return nil
	}
	defer resp.Body.Close()
	body := bytes.Buffer{}
	_, err = io.Copy(&body, resp.Body)
	if err != nil {
		if strings.ContainsAny(err.Error(), "tls: user canceled") {
			shouldIgnoreErrors = true
		}
		if !shouldIgnoreErrors {
			results <- uncover.Result{Source: agent.Name(), Error: err}
			return nil
		}
	}
	if !strings.Contains(body.String(), "<div class=\"sw_next\">") {
		return nil
	}
	sub := utils.MatchSubdomains(domain, body.String(), false)

	for _, bing := range sub {
		if _, ok := Results[bing]; ok {
			continue
		}
		result := uncover.Result{Source: agent.Name()}
		result.Host = bing
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return sub
}
func (agent *Agent) queryURL(session *uncover.Session, URL string, cookies []*http.Cookie, bingRequest *bingRequest) (*http.Response, error) {

	bingURL := fmt.Sprintf(URL, bingRequest.Q, bingRequest.First)
	request, err := uncover.NewHTTPRequest(http.MethodGet, bingURL, nil)
	if err != nil {
		return nil, err
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	agent.options.RateLimiter.Take()
	return session.Do(request)
}
func (agent *Agent) queryCookies(session *uncover.Session) ([]*http.Cookie, error) {
	request, err := uncover.NewHTTPRequest(http.MethodGet, URLInit, nil)
	if err != nil {
		return nil, err
	}
	resp, err := session.Do(request)
	if err != nil {
		return nil, err
	}
	return resp.Cookies(), nil
}