package ip138

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/wjlin0/pathScan/pkg/query/uncover"
	"github.com/wjlin0/pathScan/pkg/query/utils"
	"io"
	"net/http"
	"strings"
)

const (
	URL    = "https://site.ip138.com/%s/domain.htm"
	Source = "IP138Query"
)

type Agent struct {
	options *uncover.AgentOptions
}
type Query struct {
	Query string
}

func New() (uncover.Agent, error) {
	return &Agent{}, nil
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
		ip138Query := &Query{Query: query.Query}
		agent.query(URL, session, ip138Query, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *uncover.Session, URL string, query *Query) (*http.Response, error) {
	ip138URL := fmt.Sprintf(URL, query.Query)
	request, err := uncover.NewHTTPRequest(http.MethodGet, ip138URL, nil)
	if err != nil {
		return nil, err
	}
	agent.options.RateLimiter.Take()
	return session.Do(request)
}

func (agent *Agent) query(URL string, session *uncover.Session, request *Query, results chan uncover.Result) {
	var shouldIgnoreErrors bool
	resp, err := agent.queryURL(session, URL, request)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return
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
			return
		}
	}
	sub := utils.MatchSubdomains(request.Query, body.String(), true)
	for _, ip138 := range sub {
		result := uncover.Result{Source: agent.Name()}
		result.Host = ip138
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return
}
