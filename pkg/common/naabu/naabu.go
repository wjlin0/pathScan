package naabu

import (
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"strings"
)

func New(host []string, scanType string, ports string, topPorts string, retries int, rate int, threads int, proxy, proxyAuth string, resolvers []string, skipHostDiscovery bool, verbose bool, output string, csv bool, callback runner.OnResultCallback) *runner.Options {
	options := runner.Options{
		Host:              host,
		ScanType:          scanType,
		OnResult:          callback,
		Ports:             ports,
		TopPorts:          topPorts,
		Retries:           retries,
		Rate:              rate,
		Threads:           threads,
		Proxy:             proxy,
		ProxyAuth:         proxyAuth,
		Resolvers:         strings.Join(resolvers, ","),
		SkipHostDiscovery: skipHostDiscovery,
		Verbose:           verbose,
		Output:            output,
		CSV:               csv,
		Silent:            true,
	}

	return &options
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
