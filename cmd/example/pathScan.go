package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/v2/pkg/output"
	"github.com/wjlin0/pathScan/v2/pkg/runner"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"os"
)

func main() {
	options := types.DefaultOptions
	options.URL = []string{"wjlin0.com"}
	options.DisableAliveCheck = true
	options.DisableUpdateCheck = true

	options.ResultEventCallback = func(result output.ResultEvent) {
		fmt.Println(result)
	}

	runner.DefaultOptions(options)
	runner.ConfigureOutput(options)
	err := runner.ValidateRunEnumeration(options)
	if err != nil {
		gologger.Print().Msg(fmt.Sprintf("unable to create Runner:%s", err.Error()))
		os.Exit(-1)
		return
	}

	run, err := runner.NewRunner(options)
	if err != nil || run == nil {
		if err != nil {
			gologger.Print().Msg(fmt.Sprintf("unable to create Runner:%s", err.Error()))
			os.Exit(-1)
		}
		return
	}
	if err := run.RunEnumeration(); err != nil {
		gologger.Fatal().Msgf("unable to run enumeration: %s", err.Error())
	}

	run.Close()
}
