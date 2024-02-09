package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/v2/pkg/runner"
	"os"
	"os/signal"
)

func main() {
	run, err := runner.NewRunner(runner.ParserOptions())
	if err != nil || run == nil {
		if err != nil {
			gologger.Print().Msg(fmt.Sprintf("unable to create Runner:%s", err.Error()))
			os.Exit(-1)
		}
		return
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msg("ctrl+c press: exiting")
			run.Close()
			os.Exit(-1)
		}
	}()
	if err := run.RunEnumeration(); err != nil {
		gologger.Fatal().Msgf("unable to run enumeration: %s", err.Error())
	}

	run.Close()
}
