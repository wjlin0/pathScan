package shodanidb

import (
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net/http"
	"net/url"
	"time"

	"errors"

	"github.com/projectdiscovery/mapcidr"
	iputil "github.com/projectdiscovery/utils/ip"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/sources"
)

const (
	URL = "https://internetdb.shodan.io/%s"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "shodan-idb"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	results := make(chan sources.Result)
	start := time.Now()
	if !iputil.IsIP(query.Query) && !iputil.IsCIDR(query.Query) {
		return nil, errors.New("only ip/cidr are accepted")
	}

	go func() {
		defer close(results)

		shodanRequest := &ShodanRequest{Query: query.Query}
		sub := agent.query(URL, session, shodanRequest, results)
		gologger.Info().Msgf("%s took %s seconds to enumerate %v results.", agent.Name(), time.Since(start).Round(time.Second).String(), sub)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, shodanRequest *ShodanRequest) (*http.Response, error) {
	shodanURL := fmt.Sprintf(URL, url.QueryEscape(shodanRequest.Query))
	request, err := sources.NewHTTPRequest(http.MethodGet, shodanURL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, shodanRequest *ShodanRequest, results chan sources.Result) (sub []string) {
	var query string
	if iputil.IsIP(shodanRequest.Query) {
		if iputil.IsIPv4(shodanRequest.Query) {
			query = iputil.AsIPV4CIDR(shodanRequest.Query)
		} else if iputil.IsIPv6(shodanRequest.Query) {
			query = iputil.AsIPV6CIDR(shodanRequest.Query)
		}
	} else {
		query = shodanRequest.Query
	}
	ipChan, err := mapcidr.IPAddressesAsStream(query)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return
	}
	for ip := range ipChan {
		resp, err := agent.queryURL(session, URL, &ShodanRequest{Query: ip})
		if err != nil {
			results <- sources.Result{Source: agent.Name(), Error: err}
			continue
		}

		shodanResponse := &ShodanResponse{}
		if err := json.NewDecoder(resp.Body).Decode(shodanResponse); err != nil {
			results <- sources.Result{Source: agent.Name(), Error: err}
			continue
		}

		// we must output all combinations of ip/hostname with ports
		result := sources.Result{Source: agent.Name(), IP: shodanResponse.IP}
		result.Raw, _ = json.Marshal(shodanResponse)
		for _, port := range shodanResponse.Ports {
			result.Port = port
			results <- result
			sub = append(sub, "")
			for _, hostname := range shodanResponse.Hostnames {
				result.Host = hostname
				sub = append(sub, "")
				results <- result
			}
		}
	}
	return
}

type ShodanRequest struct {
	Query string
}
