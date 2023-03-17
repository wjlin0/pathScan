package runner

import (
	"fmt"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	ucRunner "github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/runner"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"golang.org/x/net/context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	wg      sizedwaitgroup.SizedWaitGroup
	Cfg     *ResumeCfg
	client  *http.Client
	limiter *ratelimit.Limiter
	targets map[string]struct{}
	paths   map[string]struct{}
	headers map[string]interface{}
	stats   *clistats.Statistics
}

func NewRun(options *Options) (*Runner, error) {
	run := &Runner{}
	var err error
	if options.ResumeCfg != "" {
		cfg, err := ParserResumeCfg(options.ResumeCfg)
		if err != nil {
			return nil, err
		} else {
			if cfg.Results.Targets == nil {
				cfg.Results.Targets = make(map[string]struct{})
			}
			if cfg.Results.TargetPaths == nil {
				cfg.Results.TargetPaths = make(map[string]map[string]struct{})
			}
			if cfg.Results.Skipped == nil {
				cfg.Results.Skipped = make(map[string]map[string]struct{})
			}
			cfg.Options.ResumeCfg = options.ResumeCfg
		}
	} else {
		run.Cfg = &ResumeCfg{
			Rwm:     &sync.RWMutex{},
			Options: options,
			Results: result.NewResult(),
		}
	}

	run.Cfg.Options.configureOutput()
	err = run.Cfg.Options.Validate()
	if err != nil {
		return nil, err
	}
	if !run.Cfg.Options.UpdatePathScanVersion && !run.Cfg.Options.Silent {
		err := CheckVersion()
		if err != nil {
			gologger.Error().Msgf(err.Error())
		}
	}
	if run.Cfg.Options.UpdatePathDictVersion || run.Cfg.Options.UpdatePathScanVersion {
		if run.Cfg.Options.UpdatePathDictVersion {
			err = run.Cfg.Options.DownloadDict()
			if err != nil {
				gologger.Error().Msgf(err.Error())
			}
		}
		if run.Cfg.Options.UpdatePathScanVersion {
			ok, err := run.Cfg.Options.UpdateVersion()
			if err != nil && ok == false {
				gologger.Error().Msg(err.Error())
			}
		}
		return nil, nil
	}

	if run.Cfg.Options.ClearResume {
		_ = os.RemoveAll(DefaultResumeFolderPath())
		gologger.Print().Msgf("clear success: %s", DefaultResumeFolderPath())
		os.Exit(0)
	}

	run.client = newClient(run.Cfg.Options, run.Cfg.Options.ErrUseLastResponse)
	run.limiter = ratelimit.New(context.Background(), uint(run.Cfg.Options.RateHttp), time.Duration(1)*time.Second)
	run.wg = sizedwaitgroup.New(run.Cfg.Options.RateHttp)
	run.targets = run.handlerGetTargets()
	run.paths = run.handlerGetTargetPath()
	run.headers = run.handlerHeader()
	if run.Cfg.Options.EnableProgressBar {
		stats, err := clistats.New()
		if err != nil {
			gologger.Warning().Msgf("Couldn't create progress engine: %s\n", err)
		} else {
			run.stats = stats
		}
	}
	return run, nil
}

func (r *Runner) Run() error {

	targets := r.targets
	pathUrls := r.paths
	Retries := r.Cfg.Options.Retries
	var err error

	if len(pathUrls) == 1 {
		r.Cfg.Options.OnlyTargets = true
	}
	if r.Cfg.Options.OnlyTargets {
		pathUrls = map[string]struct{}{"/": {}}
	}

	pathCount := uint64(len(pathUrls))
	targetCount := uint64(len(targets))
	Range := pathCount * targetCount
	gologger.Info().Msgf("存活目标总数 -> %d", targetCount)
	gologger.Info().Msgf("请求总数 -> %d", Range*uint64(r.Cfg.Options.Retries))
	time.Sleep(5 * time.Second)
	if r.Cfg.Options.EnableProgressBar {
		r.stats.AddStatic("paths", pathCount)
		r.stats.AddStatic("targets", targetCount)
		r.stats.AddStatic("retries", r.Cfg.Options.Retries)
		r.stats.AddStatic("startedAt", time.Now())
		r.stats.AddCounter("packets", uint64(0))
		r.stats.AddCounter("errors", uint64(0))
		r.stats.AddCounter("total", Range*uint64(r.Cfg.Options.Retries))
		if err := r.stats.Start(makePrintCallback(), time.Duration(5)*time.Second); err != nil {
			gologger.Warning().Msgf("Couldn't start statistics: %s\n", err)
		}
	}
	var f *os.File
	outputWriter, _ := ucRunner.NewOutputWriter()
	if r.Cfg.Options.Output != "" {
		outputFolder := filepath.Dir(r.Cfg.Options.Output)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				return mkdirErr
			}
		}
		f, err = util.AppendCreate(r.Cfg.Options.Output)
		if err != nil {
			return err
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)
		outputWriter.AddWriters(f)
	}
	if r.Cfg.Options.Csv {
		path, err := LivingTargetHeader(&result.TargetResult{})
		if path != "" && err == nil {
			if !r.Cfg.Options.Silent {
				fmt.Println(path)
			}
			outputWriter.WriteString(path)

		}
	}

	for currentRetries := 0; currentRetries < Retries; currentRetries++ {
		for p := range pathUrls {
			for t := range targets {
				r.wg.Add()
				go func(target, path string) {
					defer func() {
						if r.Cfg.Options.EnableProgressBar {
							r.stats.IncrementCounter("packets", 1)
						}
						r.wg.Done()
					}()
					if r.Cfg.Results.HasSkipped(path, target) {
						return
					}
					if r.Cfg.Results.HasPath(target, path) {
						return
					}

					r.limiter.Take()
					targetResult, err := r.GoTargetPath(target, path)
					if targetResult != nil && err == nil {
						r.Cfg.Results.AddSkipped(targetResult.Path, targetResult.Target)
						if !r.Cfg.Options.OnlyTargets && !r.Cfg.Options.Verbose {

							if !r.Cfg.Options.SkipCode && targetResult.Status == 404 || targetResult.Status == 500 || targetResult.Status == 0 {
								return
							}
						}
						r.Cfg.Results.AddPathByResult(targetResult.Target, targetResult.Path)

						r.handlerOutputTarget(targetResult)
						switch {
						case !r.Cfg.Options.Csv:
							outputWriter.WriteString(targetResult.ToString())
						case r.Cfg.Options.Csv:
							row, _ := LivingTargetRow(targetResult)
							outputWriter.WriteString(row)
						}
					}
				}(t, p)

			}
		}
	}

	r.wg.Wait()
	r.Cfg.ClearResume()
	return nil
}

const bufferSize = 128

func makePrintCallback() func(stats clistats.StatisticsClient) {
	builder := &strings.Builder{}
	builder.Grow(bufferSize)
	return func(stats clistats.StatisticsClient) {
		builder.WriteRune('[')
		startedAt, _ := stats.GetStatic("startedAt")
		duration := time.Since(startedAt.(time.Time))
		builder.WriteString(clistats.FmtDuration(duration))
		builder.WriteRune(']')

		hosts, _ := stats.GetStatic("targets")
		builder.WriteString(" | Targets: ")
		builder.WriteString(clistats.String(hosts))

		ports, _ := stats.GetStatic("paths")
		builder.WriteString(" | Paths: ")
		builder.WriteString(clistats.String(ports))

		retries, _ := stats.GetStatic("retries")
		builder.WriteString(" | Retries: ")
		builder.WriteString(clistats.String(retries))

		packets, _ := stats.GetCounter("packets")
		total, _ := stats.GetCounter("total")

		builder.WriteString(" | PPS: ")
		builder.WriteString(clistats.String(uint64(float64(packets) / duration.Seconds())))

		builder.WriteString(" | Packets: ")
		builder.WriteString(clistats.String(packets))
		builder.WriteRune('/')
		builder.WriteString(clistats.String(total))
		builder.WriteRune(' ')
		builder.WriteRune('(')
		//nolint:gomnd // this is not a magic number
		builder.WriteString(clistats.String(uint64(float64(packets) / float64(total) * 100.0)))
		builder.WriteRune('%')
		builder.WriteRune(')')
		builder.WriteRune('\n')

		fmt.Fprintf(os.Stderr, "%s", builder.String())
		builder.Reset()
	}
}
