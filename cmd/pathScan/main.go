package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/runner"
	"github.com/wjlin0/pathScan/pkg/util"
	"os"
	"os/signal"
	"path/filepath"
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
			filename := util.RandStr(30) + ".cfg"
			fmt.Println(filepath.Join(runner.DefaultResumeFolderPath(), filename))
			err := run.Cfg.MarshalResume(filename)
			if err != nil {
				gologger.Error().Msgf("unable to create resume file: %s", err.Error())
			}
			run.Close()
			os.Exit(-1)
		}
	}()
	if err := run.RunEnumeration(); err != nil {
		panic(err)
	}
}
