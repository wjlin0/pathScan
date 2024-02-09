package scanner

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/gologger"
	folderutil "github.com/projectdiscovery/utils/folder"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/wjlin0/pathScan/pkg/writer"
	"github.com/wjlin0/uncover/sources"
	"path/filepath"
	"strings"
)

var DefaultPathScanDir = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan")
var DefaultProviderConfigLocation = filepath.Join(DefaultPathScanDir, "provider-config.yaml")

func (scanner *Scanner) ScanUncover(resultCallback func(event string)) (<-chan string, error) {
	var (
		err     error
		service = scanner.uncover
	)

	sources.DefaultProviderConfigLocation = DefaultProviderConfigLocation
	ret := make(chan string)
	ch, err := service.Execute(context.Background())
	if err != nil {
		return nil, err
	}
	go func() {
		defer close(ret)
		for result := range ch {
			switch {
			case result.Error != nil:
				gologger.Warning().Msgf("Request %s sending error: %s", result.Source, result.Error)
			case scanner.options.CSV:
				toString, err := writer.CSVToString(result)
				if err != nil {
					continue
				}
				resultCallback(string(toString))

				replacer := strings.NewReplacer("ip", result.IP, "host", result.Host,
					"port", fmt.Sprint(result.Port),
				)
				port := fmt.Sprintf("%d", result.Port)
				var field = scanner.options.UncoverField
				if (result.IP == "" || port == "0") && stringsutil.ContainsAny(field, "ip", "port") {
					field = "host"
				}
				outData := replacer.Replace(field)
				ret <- outData
			default:
				replacer := strings.NewReplacer("ip", result.IP, "host", result.Host,
					"port", fmt.Sprint(result.Port),
				)
				port := fmt.Sprintf("%d", result.Port)
				var field = scanner.options.UncoverField
				if (result.IP == "" || port == "0") && stringsutil.ContainsAny(field, "ip", "port") {
					field = "host"
				}
				outData := replacer.Replace(field)
				resultCallback(outData)
				ret <- outData

			}

		}
	}()
	return ret, nil
}

func (scanner *Scanner) rebaseUncover() {
	if !scanner.options.Subdomain {
		return
	}
	var (
		service = scanner.uncover
		agents  []sources.Agent
	)

	for _, agent := range service.Agents {
		switch agent.Name() {
		case "fofa":
			if service.Keys.FofaKey == "" || service.Keys.FofaEmail == "" {
				continue
			}
		case "quake":
			if service.Keys.QuakeToken == "" {
				continue
			}
		case "github":
			if service.Keys.GithubToken == "" {
				continue
			}
		case "shodan":
			if service.Keys.Shodan == "" {
				continue
			}
		case "censys":
			if service.Keys.CensysToken == "" || service.Keys.CensysSecret == "" {
				continue
			}
		case "hunter":
			if service.Keys.HunterToken == "" {
				continue
			}
		case "zoomeye":
			if service.Keys.ZoomEyeToken == "" {
				continue
			}
		case "netlas":
			if service.Keys.NetlasToken == "" {
				continue
			}
		case "criminalip":
			if service.Keys.CriminalIPToken == "" {
				continue
			}
		case "publicwww":
			if service.Keys.PublicwwwToken == "" {
				continue
			}
		case "hunterhow":
			if service.Keys.HunterHowToken == "" {
				continue
			}
		case "binaryedge":
			if service.Keys.BinaryedgeToken == "" {
				continue
			}

		}

		agents = append(agents, agent)

	}

	service.Agents = agents
}
