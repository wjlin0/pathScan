package qianxun

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
	URL    = "https://www.dnsscan.cn/dns.html?keywords=%s&page=%d"
	DATA   = "&show=&ecmsfrom=127.0.0.1&um=&classid=0&keywords=%s&num="
	Source = "qianxunQuery"
)

type Agent struct {
	options *uncover.AgentOptions
}
type qianxunRequest struct {
	Domain string
	Page   int
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
			Results         map[string]struct{}
			numberOfResults int
			page            int
		)
		Results = make(map[string]struct{})
		page = 1
		for {
			qianxunReq := &qianxunRequest{
				Domain: query.Query,
				Page:   page,
			}
			qianxunResponse := agent.query(session, query.Query, URL, DATA, qianxunReq, Results, results)
			if len(qianxunResponse) == 0 || numberOfResults > query.Limit {
				break
			}
			numberOfResults += len(qianxunResponse)

			for i := 0; i < len(qianxunResponse); i++ {
				Results[qianxunResponse[i]] = struct{}{}
			}
			page++
		}

	}()

	return results, nil
}
func (agent *Agent) query(session *uncover.Session, domain string, URL string, DATA string, qianxunRequest *qianxunRequest, Results map[string]struct{}, results chan uncover.Result) []string {
	var (
		shouldIgnoreErrors bool
	)
	resp, err := agent.queryURL(session, URL, DATA, qianxunRequest)
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

	sub := utils.MatchSubdomains(domain, body.String(), false)

	for _, qianxun := range sub {
		if _, ok := Results[qianxun]; ok {
			continue
		}
		result := uncover.Result{Source: agent.Name()}
		result.Host = qianxun
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	if !strings.Contains(body.String(), "<div id=\"page\" class=\"pagelist\">") {
		return nil
	}
	if strings.Contains(body.String(), "<li class=\"disabled\"><span>&raquo;</span></li>") {
		return nil
	}
	return sub
}
func (agent *Agent) queryURL(session *uncover.Session, URL string, DATA string, qianxunRequest *qianxunRequest) (*http.Response, error) {
	bingURL := fmt.Sprintf(URL, qianxunRequest.Domain, qianxunRequest.Page)
	buffer := bytes.Buffer{}
	buffer.WriteString(fmt.Sprintf(DATA, qianxunRequest.Domain))
	request, err := uncover.NewHTTPRequest(http.MethodPost, bingURL, &buffer)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	agent.options.RateLimiter.Take()
	return session.Do(request)
}
