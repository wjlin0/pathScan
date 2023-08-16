package query

import (
	"context"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/pkg/query/runner"
	"github.com/wjlin0/pathScan/pkg/query/uncover"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/anubis"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/bing"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/chinaz"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/google"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/ip138"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/qianxun"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/rapiddns"
	"github.com/wjlin0/pathScan/pkg/query/uncover/agent/sitedossier"
	"github.com/wjlin0/pathScan/pkg/util"
	"time"
)

const (
	maxConcurrentAgents = 50
)

func Query(delay, limit, retries int, timeout int, domains []string, engine []string, proxy, auth string) (chan string, error) {
	options := &runner.Options{
		Engine:  engine,
		Limit:   limit,
		Delay:   delay,
		Domains: domains,
		Proxy:   proxy,
		Auth:    auth,
		Retries: retries,
		Timeout: time.Duration(timeout) * time.Second,
	}
	return query(options)
}
func query(queryOptions *runner.Options) (chan string, error) {
	var rateLimiter *ratelimit.Limiter
	// create rateLimiter for uncover delay

	if queryOptions.Delay > 0 {
		rateLimiter = ratelimit.New(context.Background(), 5, time.Duration(queryOptions.Delay)*time.Second)
	} else {
		rateLimiter = ratelimit.NewUnlimited(context.Background())
	}
	var agents []uncover.Agent
	for _, engine := range queryOptions.Engine {
		var (
			agent uncover.Agent
			err   error
		)
		switch engine {
		case "ip138":
			agent, err = ip138.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "google":
			agent, err = google.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "bing":
			agent, err = bing.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "anubis":
			agent, err = anubis.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "chinaz":
			agent, err = chinaz.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "qianxun":
			agent, err = qianxun.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "rapiddns":
			agent, err = rapiddns.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "sitedossier":
			agent, err = sitedossier.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		default:
			err = errors.Errorf("%s unknown uncover agent type", engine)
		}
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}

	// enumerate
	swg := sizedwaitgroup.New(maxConcurrentAgents)
	ret := make(chan string)
	go func() {
		for _, d := range queryOptions.Domains {
			for _, agent := range agents {
				uncoverQuery := &uncover.Query{
					Query: d,
					Limit: queryOptions.Limit,
				}
				gologger.Debug().Msgf("request parameter is: %s", uncoverQuery.Query)

				swg.Add()
				go func(agent uncover.Agent, uq *uncover.Query) {
					defer swg.Done()
					session, err := uncover.NewSession(queryOptions.Retries, queryOptions.Timeout, util.GetProxyFunc(queryOptions.Proxy, queryOptions.Auth))
					if err != nil {
						gologger.Error().Label(agent.Name()).Msgf("couldn't create uncover new session: %s", err)
						return
					}
					ch, err := agent.Query(session, uq)
					if err != nil {
						gologger.Warning().Msgf("%s", err)
						return
					}
					for result := range ch {
						switch {
						case result.Error != nil:
							gologger.Warning().Msgf("Request %s sending error: %s", result.Source, result.Error)
						default:
							switch result.Source {
							default:
								ret <- result.Host
							}
						}

					}
				}(agent, uncoverQuery)
			}
		}
		swg.Wait()
		close(ret)
	}()
	return ret, nil
}
