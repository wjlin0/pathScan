package quake

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover"
	"net/http"
)

const (
	URL  = "https://quake.360.net/api/v3/search/quake_service"
	Size = 100
)

type Agent struct {
	options *uncover.AgentOptions
}

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "quake"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.QuakeToken == "" {
		return nil, errors.New("empty quake keys")
	}

	results := make(chan uncover.Result)

	go func() {
		defer close(results)

		var numberOfResults, totalResults int
		for {
			quakeRequest := &Request{
				Query:       query.Query,
				Size:        Size,
				Start:       numberOfResults,
				IgnoreCache: true,
				Include:     []string{"ip", "port", "hostname", "service.name", "service.http.host"},
			}
			quakeResponse := agent.query(URL, session, quakeRequest, results)
			if quakeResponse == nil {
				break
			}
			if totalResults == 0 {
				totalResults = int(quakeResponse.Meta.Pagination.Total)
			}

			numberOfResults += len(quakeResponse.Data)
			if numberOfResults > query.Limit || len(quakeResponse.Data) == 0 || numberOfResults > totalResults {
				break
			}

		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *uncover.Session, quakeRequest *Request, results chan uncover.Result) *Response {
	resp, err := agent.queryURL(session, URL, quakeRequest)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	quakeResponse := &Response{}
	//body, _ := io.ReadAll(resp.Body)
	//fmt.Println(string(body))
	if err := json.NewDecoder(resp.Body).Decode(quakeResponse); err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	for _, quakeResult := range quakeResponse.Data {
		result := uncover.Result{Source: agent.Name()}
		result.IP = quakeResult.IP
		result.Port = quakeResult.Port
		switch {
		case quakeResult.Hostname != "":
			result.Host = quakeResult.Hostname
		case quakeResult.Service != nil && (quakeResult.Service.Name == "http" || quakeResult.Service.Name == "http/ssl") && quakeResult.Service.Http.Host != "":
			result.Host = quakeResult.Service.Http.Host
		default:
			result.Host = ""
		}
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return quakeResponse
}

func (agent *Agent) queryURL(session *uncover.Session, URL string, quakeRequest *Request) (*http.Response, error) {
	body, err := json.Marshal(quakeRequest)
	if err != nil {
		return nil, err
	}

	request, err := uncover.NewHTTPRequest(
		http.MethodPost,
		URL,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-QuakeToken", session.Keys.QuakeToken)

	agent.options.RateLimiter.Take()
	return session.Do(request)
}
