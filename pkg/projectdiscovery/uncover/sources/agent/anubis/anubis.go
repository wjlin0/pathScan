package anubis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/sources"
	"io"
	"net/http"
	"strings"
)

const (
	URL    = "https://jldc.me/anubis/subdomains/%s"
	Source = "anubis"
)

type Agent struct {
	options *sources.Agent
}
type anubisRequest struct {
	Domain string `json:"domain"`
}

func (agent *Agent) Name() string {
	return Source
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {

	results := make(chan sources.Result)
	go func() {
		defer close(results)
		anubis := &anubisRequest{Domain: query.Query}
		agent.query(URL, session, anubis, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, anubis *anubisRequest) (*http.Response, error) {
	ip138URL := fmt.Sprintf(URL, anubis.Domain)
	request, err := sources.NewHTTPRequest(http.MethodGet, ip138URL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, anubis *anubisRequest, results chan sources.Result) {
	var shouldIgnoreErrors bool
	resp, err := agent.queryURL(session, URL, anubis)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
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
			results <- sources.Result{Source: agent.Name(), Error: err}
			return
		}
	}
	sub := sources.MatchSubdomains(anubis.Domain, body.String(), true)
	for _, anu := range sub {
		result := sources.Result{Source: agent.Name()}
		result.Host = anu
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return
}
