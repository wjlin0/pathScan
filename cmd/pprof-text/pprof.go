package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/runner"
	"github.com/wjlin0/pathScan/pkg/util"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
)

var (
	cpuprofile = "cpu.pprof"
	memprofile = "mem.pprof"
)

func main() {

	f1, err := os.Create(cpuprofile)
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer f1.Close()

	if err := pprof.StartCPUProfile(f1); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	run, err := runner.NewRunner(runner.ParserOptions())
	if err != nil {
		gologger.Print().Msg(fmt.Sprintf("Unable to create Runner:%s", err.Error()))
		os.Exit(-1)
	}
	if run == nil {
		os.Exit(0)
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
			os.Exit(-1)
		}
	}()
	err = run.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Unable to run: %s", err.Error())
		os.Exit(0)
	}

	f, err := os.Create(memprofile)
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer f.Close()
	runtime.GC()

	if err := pprof.WriteHeapProfile(f); err != nil {
		log.Fatal("cound not write memory profile: ", err)
	}

}
