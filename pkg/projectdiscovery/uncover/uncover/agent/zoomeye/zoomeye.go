package zoomeye

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
	"net/url"

	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover"
)

const (
	URL = "https://api.zoomeye.org/domain/search?q=%s&page=%d&type=%d"
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
	return "zoomeye"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.ZoomEyeToken == "" {
		return nil, errors.New("empty zoomeye keys")
	}
	results := make(chan uncover.Result)

	go func() {
		defer close(results)

		currentPage := 1
		var numberOfResults, totalResults int
		for {
			zoomeyeRequest := &ZoomEyeRequest{
				Query: query.Query,
				Page:  currentPage,
				Type:  1,
			}

			zoomeyeResponse := agent.query(URL, session, zoomeyeRequest, results)
			if zoomeyeResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(zoomeyeResponse.List)
			if totalResults == 0 {
				totalResults = zoomeyeResponse.Total
			}

			// query certificates
			if numberOfResults > query.Limit || numberOfResults > totalResults || len(zoomeyeResponse.List) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *uncover.Session, URL string, zoomeyeRequest *ZoomEyeRequest) (*http.Response, error) {
	zoomeyeURL := fmt.Sprintf(URL, url.QueryEscape(zoomeyeRequest.Query), zoomeyeRequest.Page, zoomeyeRequest.Type)
	request, err := uncover.NewHTTPRequest(http.MethodGet, zoomeyeURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("API-KEY", session.Keys.ZoomEyeToken)
	agent.options.RateLimiter.Take()
	return session.Do(request)
}

func (agent *Agent) query(URL string, session *uncover.Session, zoomeyeRequest *ZoomEyeRequest, results chan uncover.Result) *ZoomEyeResponse {
	// query certificates
	resp, err := agent.queryURL(session, URL, zoomeyeRequest)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	zoomeyeResponse := &ZoomEyeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(zoomeyeResponse); err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	for _, listData := range zoomeyeResponse.List {
		if len(listData.Ip) == 0 {
			result := uncover.Result{Source: agent.Name()}
			result.Host = listData.Name

			results <- result
		} else {
			for _, ip := range listData.Ip {
				result := uncover.Result{Source: agent.Name()}
				result.Host = listData.Name
				result.IP = ip
				results <- result
			}
		}

	}

	return zoomeyeResponse
}

type ZoomEyeRequest struct {
	Query string
	Page  int
	Type  int
}
