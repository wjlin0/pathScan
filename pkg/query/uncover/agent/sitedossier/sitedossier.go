package sitedossier

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
	URL    = "http://www.sitedossier.com/parentdomain/%s/%d"
	Source = "SiteDossierQuery"
)

type Agent struct {
	options *uncover.AgentOptions
}
type siteDossierRequest struct {
	Domain string `json:"domain"`
	Size   int    `json:"size"`
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
			size            int
		)
		Results = make(map[string]struct{})
		size = 1
		for {

			request := &siteDossierRequest{
				Domain: query.Query,
				Size:   size,
			}
			response := agent.query(session, URL, request, Results, results)
			if len(response) == 0 || numberOfResults > query.Limit {
				break
			}
			numberOfResults += len(response)

			for i := 0; i < len(response); i++ {
				Results[response[i]] = struct{}{}
			}
			size += 100
		}

	}()

	return results, nil
}
func (agent *Agent) query(session *uncover.Session, URL string, request *siteDossierRequest, Results map[string]struct{}, results chan uncover.Result) []string {
	var (
		shouldIgnoreErrors bool
	)
	resp, err := agent.queryURL(session, URL, request)
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
	sub := utils.MatchSubdomains(request.Domain, body.String(), false)

	for _, site := range sub {
		if _, ok := Results[site]; ok {
			continue
		}
		result := uncover.Result{Source: agent.Name()}
		result.Host = site
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	if !strings.ContainsAny(body.String(), "Show next 100 items") {
		return nil
	}
	return sub
}
func (agent *Agent) queryURL(session *uncover.Session, URL string, site *siteDossierRequest) (*http.Response, error) {

	requestURL := fmt.Sprintf(URL, site.Domain, site.Size)
	request, err := uncover.NewHTTPRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	agent.options.RateLimiter.Take()
	return session.Do(request)
}
