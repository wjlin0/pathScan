package rapiddns

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
	URL    = "https://rapiddns.io/subdomain/%s?full=1"
	Source = "RapidDNSQuery"
)

type Agent struct {
	options *uncover.AgentOptions
}
type rapidDNS struct {
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
		request := &rapidDNS{Domain: query.Query}
		agent.query(URL, session, request, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *uncover.Session, URL string, rapid *rapidDNS) (*http.Response, error) {
	rapidURL := fmt.Sprintf(URL, rapid.Domain)
	request, err := uncover.NewHTTPRequest(http.MethodGet, rapidURL, nil)
	if err != nil {
		return nil, err
	}
	agent.options.RateLimiter.Take()
	return session.Do(request)
}

func (agent *Agent) query(URL string, session *uncover.Session, rapid *rapidDNS, results chan uncover.Result) {
	var shouldIgnoreErrors bool
	resp, err := agent.queryURL(session, URL, rapid)
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
	sub := utils.MatchSubdomains(rapid.Domain, body.String(), true)
	for _, ra := range sub {
		result := uncover.Result{Source: agent.Name()}
		result.Host = ra
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return
}
