package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/runner"
	"os"
)

func main() {
	options := &runner.Options{Url: []string{
		"https://wjlin0.com/",
	},
		Timeout: 2,
		ResultBack: func(result *result.Result) {
			fmt.Println(result)
		},
		Method: []string{"GET"},
		Path:   []string{"/"},
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
}
