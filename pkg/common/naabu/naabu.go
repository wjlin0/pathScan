package naabu

import (
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"strings"
)

func DefaultOptions() *runner.Options {
	return &runner.Options{
		Timeout:       1000,
		MetricsPort:   63636,
		WarmUpTime:    2,
		StatsInterval: 5,
	}
}

func New(host []string, sourceIp, sourcePort, scanType string, ports string, topPorts string, retries int, rate int, threads int, proxy, proxyAuth string, resolvers []string, onlyHostDiscovery, skipHostDiscovery bool, verbose bool, output string, csv bool, silent bool, callback runner.OnResultCallback) (*runner.Options, error) {
	opt := DefaultOptions()

	opt.Host = host
	opt.ScanType = scanType
	opt.OnResult = callback
	opt.Ports = ports
	opt.TopPorts = topPorts
	opt.Retries = retries
	opt.Rate = rate
	opt.Threads = threads
	opt.Proxy = proxy
	opt.ProxyAuth = proxyAuth
	opt.Resolvers = strings.Join(resolvers, ",")
	opt.SkipHostDiscovery = skipHostDiscovery
	opt.Verbose = verbose
	opt.Output = output
	opt.CSV = csv
	opt.Silent = silent
	opt.SourceIP = sourceIp
	opt.SourcePort = sourcePort
	opt.OnlyHostDiscovery = onlyHostDiscovery

	opt.ConfigureHostDiscovery()

	if err := opt.ValidateOptions(); err != nil {
		return nil, err
	}
	return opt, nil
}

func Execute(opt *runner.Options) error {
	naabuRunner, err := runner.NewRunner(opt)
	if err != nil {
		return err
	}
	defer naabuRunner.Close()

	err = naabuRunner.RunEnumeration()
	if err != nil {
		return err
	}
	return nil
}
