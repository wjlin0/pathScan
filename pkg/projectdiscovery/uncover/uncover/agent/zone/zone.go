package zone

import (
	"bytes"
	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
	"github.com/pkg/errors"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type Agent struct {
	options *uncover.AgentOptions
}

const (
	URL  = "https://0.zone/api/data/"
	Size = 40
)

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "zone"
}
func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.ZoneToken == "" {
		return nil, errors.New("empty 0zone keys")
	}
	results := make(chan uncover.Result)
	go func() {
		defer close(results)
		currentPage := 1
		var numberOfResults, totalResults int
		for {
			zoneRequest := &ZoneRequest{
				Query:    query.Query,
				Page:     currentPage,
				PageSize: Size,
			}
			zoneResponse := agent.query(session, zoneRequest, results)
			if zoneResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(zoneResponse.Data)
			if totalResults == 0 {
				totalResults = zoneResponse.Total
			}
			//if zoneResponse.Code == 1 {
			//	gologger.Debug().Msg(zoneResponse.Message)
			//	break
			//}
			// query certificates
			if numberOfResults > query.Limit || numberOfResults > totalResults || len(zoneResponse.Data) == 0 {
				break
			}
		}
	}()
	return results, nil
}

func (agent *Agent) query(session *uncover.Session, zoneRequest *ZoneRequest, results chan uncover.Result) *Response {
	resp, err := agent.queryURL(session, URL, zoneRequest)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	zoneResponse := &Response{}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	extra.RegisterFuzzyDecoders()
	err = json.Unmarshal(body, zoneResponse)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, zoneResult := range zoneResponse.Data {
		result := uncover.Result{Source: agent.Name()}
		result.IP = zoneResult.Ip
		result.Port = zoneResult.Port
		var host string
		p, err := url.Parse(zoneResult.Url)
		if err != nil {
			host = result.IP + strconv.Itoa(result.Port)
		} else {
			host = p.Host
		}
		result.Host = host
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return zoneResponse

}
func (agent *Agent) queryURL(session *uncover.Session, URL string, zoneRequest *ZoneRequest) (*http.Response, error) {
	zoneRequest.ZoneKeyId = session.Keys.ZoneToken
	zoneRequest.QueryType = "site"
	body, err := json.Marshal(zoneRequest)
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
	agent.options.RateLimiter.Take()
	return session.Do(request)
}
