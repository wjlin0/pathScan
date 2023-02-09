package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"
	"os/signal"
	"path/filepath"
	"pathScan/pkg/runner"
)

func main() {
	run, err := runner.NewRun(runner.ParserOptions())
	if err != nil {
		fmt.Println(fmt.Sprintf("无法创建Runner: %s", err.Error()))
		os.Exit(0)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msg("CTRL+C 按下: Exiting")
			filename := runner.RandFileName(30) + ".cfg"
			fmt.Println(filepath.Join(runner.DefaultResumeFolderPath(), filename))
			err := run.Cfg.MarshalResume(filename)
			if err != nil {
				gologger.Error().Msg("无法创建 resume 文件: %s" + err.Error())
			}
			os.Exit(1)
		}
	}()
	err = run.Run()
	if err != nil {
		gologger.Fatal().Msg("无法 运行: %s" + err.Error())
	}
	run.Cfg.CleanupResumeConfig()
}
