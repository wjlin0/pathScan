package binary

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"net/url"
	"pathScan/pkg/projectdiscovery/uncover/uncover"
)

type Agent struct {
	options *uncover.AgentOptions
}

const (
	URL  = "https://api.binaryedge.io/v2/query/domains/subdomain/%s?page=%d"
	Size = 100
)

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "binary"
}
func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.BinaryToken == "" {
		return nil, errors.New("empty binary keys")
	}
	results := make(chan uncover.Result)
	go func() {
		defer close(results)
		currentPage := 1
		var numberOfResults, totalResults int
		for {
			binaryRequest := &BinaryRequest{
				Query: query.Query,
				Page:  currentPage,
			}
			binaryResponse := agent.query(session, binaryRequest, results)
			if binaryResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(binaryResponse.Data)
			if totalResults == 0 {
				totalResults = binaryResponse.Total
			}
			// query certificates
			if numberOfResults > query.Limit || numberOfResults > totalResults || len(binaryResponse.Data) == 0 {
				break
			}
		}
	}()
	return results, nil
}

func (agent *Agent) query(session *uncover.Session, binaryRequest *BinaryRequest, results chan uncover.Result) *Response {
	resp, err := agent.queryURL(session, URL, binaryRequest)
	if err != nil {
		fmt.Println(err)
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	binaryResponse := &Response{}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	err = json.Unmarshal(body, binaryResponse)
	if err != nil {
		fmt.Println(err)
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	for _, binaryResult := range binaryResponse.Data {
		result := uncover.Result{Source: agent.Name()}
		result.Host = binaryResult
		result.Port = 80
		result.IP = binaryResult
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return binaryResponse

}
func (agent *Agent) queryURL(session *uncover.Session, URL string, binaryRequest *BinaryRequest) (*http.Response, error) {
	binaryURL := fmt.Sprintf(URL, url.QueryEscape(binaryRequest.Query), binaryRequest.Page)
	request, err := uncover.NewHTTPRequest(http.MethodGet, binaryURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Key", session.Keys.BinaryToken)
	agent.options.RateLimiter.Take()
	return session.Do(request)
}
