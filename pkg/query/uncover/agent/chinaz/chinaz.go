package chinaz

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
	URL    = "https://alexa.chinaz.com/%s"
	Source = "ChinazQuery"
)

type Agent struct {
	options *uncover.AgentOptions
}
type chinazRequest struct {
	Domain string `json:"domain"`
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
		chinaz := &chinazRequest{Domain: query.Query}
		agent.query(URL, session, chinaz, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *uncover.Session, URL string, chinaz *chinazRequest) (*http.Response, error) {
	chinazURL := fmt.Sprintf(URL, chinaz.Domain)
	request, err := uncover.NewHTTPRequest(http.MethodGet, chinazURL, nil)
	if err != nil {
		return nil, err
	}
	agent.options.RateLimiter.Take()
	return session.Do(request)
}

func (agent *Agent) query(URL string, session *uncover.Session, chinaz *chinazRequest, results chan uncover.Result) {
	var shouldIgnoreErrors bool
	resp, err := agent.queryURL(session, URL, chinaz)
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
	sub := utils.MatchSubdomains(chinaz.Domain, body.String(), true)
	for _, ch := range sub {
		result := uncover.Result{Source: agent.Name()}
		result.Host = ch
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return
}
