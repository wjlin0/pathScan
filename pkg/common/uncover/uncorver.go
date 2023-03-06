package uncover

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/remeh/sizedwaitgroup"
	ucRunner "github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/runner"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/censys"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/fofa"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/hunter"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/netlas"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/quake"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/shodan"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/shodanidb"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/zone"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover/agent/zoomeye"
	"golang.org/x/net/context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var defaultProviderConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/pathScan/provider-config.yaml")

const maxConcurrentAgents = 50

func GetUncoverSupportedAgents() string {
	uncoverSupportedAgents := []string{"shodan", "shodan-idb", "fofa", "censys", "quake", "hunter", "zoomeye", "netlas", "zone"}
	return strings.Join(uncoverSupportedAgents, ",")
}
func GetTargetsFromUncover(delay, limit int, field string, engine, query []string) (chan string, error) {
	uncoverOptions := &ucRunner.Options{
		Provider: &ucRunner.Provider{},
		Delay:    delay,
		Limit:    limit,
		Query:    query,
		Engine:   engine,
	}
	_ = loadProvidersFrom(defaultProviderConfigLocation, uncoverOptions)

	//for _, eng := range engine {
	//	err := loadKeys(eng, uncoverOptions)
	//	if err != nil {
	//		gologger.Error().Label("WRN").Msgf(err.Error())
	//		continue
	//	}
	//}
	return getTargets(uncoverOptions, field)
}
func getTargets(uncoverOptions *ucRunner.Options, field string) (chan string, error) {
	var rateLimiter *ratelimit.Limiter
	// create rateLimiter for uncover delay
	if uncoverOptions.Delay > 0 {
		rateLimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
	} else {
		rateLimiter = ratelimit.NewUnlimited(context.Background())
	}
	var agents []uncover.Agent
	// declare clients
	for _, engine := range uncoverOptions.Engine {
		var (
			agent uncover.Agent
			err   error
		)
		switch engine {
		case "fofa":
			agent, err = fofa.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "shodan":
			agent, err = shodan.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "censys":
			agent, err = censys.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "shodan-idb":
			agent, err = shodanidb.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "quake":
			agent, err = quake.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "hunter":
			agent, err = hunter.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "zoomeye":
			agent, err = zoomeye.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "netlas":
			agent, err = netlas.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "zone":
			agent, err = zone.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
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
		for _, q := range uncoverOptions.Query {
			uncoverQuery := &uncover.Query{
				Query: q,
				Limit: uncoverOptions.Limit,
			}
			for _, agent := range agents {
				swg.Add()
				go func(agent uncover.Agent, uncoverQuery *uncover.Query) {
					defer swg.Done()
					keys := uncoverOptions.Provider.GetKeys()
					session, err := uncover.NewSession(&keys, uncoverOptions.Retries, uncoverOptions.Timeout)
					if err != nil {
						gologger.Error().Label(agent.Name()).Msgf("couldn't create uncover new session: %s", err)
					}
					ch, err := agent.Query(session, uncoverQuery)
					if err != nil {
						gologger.Warning().Msgf("%s", err)
						return
					}
					for result := range ch {
						replacer := strings.NewReplacer(
							"ip", result.IP,
							"host", result.Host,
							"port", fmt.Sprint(result.Port),
						)
						ret <- replacer.Replace(field)
					}
				}(agent, uncoverQuery)
			}
		}
		swg.Wait()
		close(ret)
	}()
	return ret, nil
}
func loadProvidersFrom(location string, options *ucRunner.Options) error {
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), options.Provider)
}
func loadKeys(engine string, options *ucRunner.Options) error {
	switch engine {
	case "fofa":
		if email, exists := os.LookupEnv("FOFA_EMAIL"); exists {
			if key, exists := os.LookupEnv("FOFA_KEY"); exists {
				options.Provider.Fofa = append(options.Provider.Fofa, fmt.Sprintf("%s:%s", email, key))
			} else {
				return errors.New("missing FOFA_KEY env variable")
			}
		} else {
			return errors.Errorf("FOFA_EMAIL & FOFA_KEY env variables are not configured")
		}
	case "shodan":
		if key, exists := os.LookupEnv("SHODAN_API_KEY"); exists {
			options.Provider.Shodan = append(options.Provider.Shodan, key)
		} else {
			return errors.Errorf("SHODAN_API_KEY env variable is not configured")
		}
	case "censys":
		if id, exists := os.LookupEnv("CENSYS_API_ID"); exists {
			if secret, exists := os.LookupEnv("CENSYS_API_SECRET"); exists {
				options.Provider.Censys = append(options.Provider.Censys, fmt.Sprintf("%s:%s", id, secret))
			} else {
				return errors.New("missing CENSYS_API_SECRET env variable")
			}
		} else {
			return errors.Errorf("CENSYS_API_ID & CENSYS_API_SECRET env variable is not configured")
		}
	case "hunter":
		if key, exists := os.LookupEnv("HUNTER_API_KEY"); exists {
			options.Provider.Hunter = append(options.Provider.Hunter, key)
		} else {
			return errors.Errorf("HUNTER_API_KEY env variable is not configured")
		}
	case "zoomeye":
		if key, exists := os.LookupEnv("ZOOMEYE_API_KEY"); exists {
			options.Provider.ZoomEye = append(options.Provider.ZoomEye, key)
		} else {
			return errors.Errorf("ZOOMEYE_API_KEY env variable is not configured")
		}
	case "quake":
		if key, exists := os.LookupEnv("QUAKE_TOKEN"); exists {
			options.Provider.Quake = append(options.Provider.Quake, key)
		} else {
			return errors.Errorf("QUAKE_TOKEN env variable is not configured")
		}
	case "netlas":
		if key, exists := os.LookupEnv("NETLAS_API_KEY"); exists {
			options.Provider.Netlas = append(options.Provider.Netlas, key)
		} else {
			return errors.Errorf("NETLAS_API_KEY env variable is not configured")
		}
	case "zone":
		if key, exists := os.LookupEnv("ZONE_API_KEY"); exists {
			options.Provider.Netlas = append(options.Provider.Zone, key)
		} else {
			return errors.Errorf("ZONE_API_KEY env variable is not configured")
		}
	default:
		return errors.Errorf("unknown uncover agent")
	}
	return nil
}
