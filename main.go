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
	if err != nil {
		gologger.Print().Msg(fmt.Sprintf("无法创建Runner: %s", err.Error()))
		os.Exit(0)
	}
	if run == nil {
		os.Exit(0)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msg("CTRL+C 按下: Exiting")
			filename := util.RandStr(30) + ".cfg"
			fmt.Println(filepath.Join(runner.DefaultResumeFolderPath(), filename))
			err := run.Cfg.MarshalResume(filename)
			if err != nil {
				gologger.Error().Msgf("无法创建 resume 文件: %s", err.Error())
			}
			os.Exit(1)
		}
	}()
	err = run.Run()
	if err != nil {
		gologger.Fatal().Msgf("无法 运行: %s", err.Error())
	}
	run.Cfg.CleanupResumeConfig()
}
