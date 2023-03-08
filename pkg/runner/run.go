package runner

import (
	"crypto/tls"
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	ucRunner "github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/runner"
	"github.com/wjlin0/pathScan/pkg/result"
	"golang.org/x/net/context"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	wg        sizedwaitgroup.SizedWaitGroup
	Cfg       *ResumeCfg
	client    *http.Client
	limiter   *ratelimit.Limiter
	targets   []string
	paths     []string
	userAgent []string
	stats     *clistats.Statistics
}

func NewRun(options *Options) (*Runner, error) {
	run := &Runner{}
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

	err := run.Cfg.Options.Validate()
	if err != nil {
		return nil, err
	}
	run.Cfg.Options.configureOutput()
	run.newClient()

	run.limiter = ratelimit.New(context.Background(), uint(run.Cfg.Options.RateHttp), time.Duration(1)*time.Second)
	run.wg = sizedwaitgroup.New(run.Cfg.Options.RateHttp)
	run.targets = run.getAllTargets()
	run.paths = run.getAllPaths()
	run.userAgent = []string{"Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5", "Mozilla/5.0 (Linux;u;Android 4.2.2;zh-cn;) AppleWebKit/534.46 (KHTML,like Gecko)Version/5.1 Mobile Safari/10600.6.3 (compatible; Baiduspider/2.0;+http://www.baidu.com/search/spider.html)", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)", "Mozilla/5.0 (iPhone;CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko)Version/9.0 Mobile/13B143 Safari/601.1 (compatible; Baiduspider-render/2.0;Smartapp; +http://www.baidu.com/search/spider.html)"}
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

func (r *Runner) GetUserAgent() string {
	rand.Seed(time.Now().Unix())
	return r.userAgent[rand.Intn(len(r.userAgent))]
}

func (r *Runner) newClient() *http.Client {
	options := r.Cfg.Options
	t := &http.Transport{
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}
	if options.Proxy != "" {
		proxyUrl, err := url.Parse(options.Proxy)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if options.ProxyAuth != "" {
			proxyUrl.User = url.UserPassword(strings.Split(options.ProxyAuth, ":")[0], strings.Split(options.ProxyAuth, ":")[1])
		}
		t.Proxy = http.ProxyURL(proxyUrl)
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: t,
	}
	if options.ErrUseLastResponse {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	r.client = client
	return client
}

func (r *Runner) SkippedHost() {
	var targets []string
	for target := range r.Cfg.Results.GetTargets() {
		targets = append(targets, target)
	}
	wg := sizedwaitgroup.New(100)
	for _, target := range targets {
		wg.Add()
		go func(target string) {
			defer wg.Done()
			exit, err := r.verifyTarget(target)
			if exit && err == nil {
				r.Cfg.Results.RemoveTargets(target)
				gologger.Info().Msgf("发现异常站点: %s", target)
			} else if err != nil {
				gologger.Debug().Msgf("%s", err.Error())
			}

		}(target)
	}
	wg.Wait()
}

func (r *Runner) DiscoveryHost(targets []string) {
	wg := sizedwaitgroup.New(r.Cfg.Options.Rate)
	for _, target := range targets {
		wg.Add()
		go func(target string) {
			defer wg.Done()
			if r.Cfg.Results.HasTarget(target) {
				return
			}
			exit, err := r.ConnectTarget(target)
			if exit && err == nil {
				r.Cfg.Results.AddTarget(target)
				if r.Cfg.Options.Silent {
					gologger.Silent().Msg(target)
				}
				gologger.Debug().Msgf("发现 %s 存活", target)
			} else if err != nil {
				gologger.Debug().Msgf("%s", err.Error())
			}

		}(target)
	}
	wg.Wait()
}

func (r *Runner) Run() error {

	targets := r.targets
	pathUrls := r.paths
	Retries := r.Cfg.Options.Retries
	// 下载远程字典
	err := r.DownloadDict()
	if err != nil {
		gologger.Error().Msgf(err.Error())
	}

	if len(pathUrls) == 1 {
		r.Cfg.Options.OnlyTargets = true
	}
	if r.Cfg.Options.OnlyTargets {
		pathUrls = []string{pathUrls[0]}
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
	cache, _ := lru.New(2048)
	if r.Cfg.Options.Output != "" {
		outputFolder := filepath.Dir(r.Cfg.Options.Output)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				return mkdirErr
			}
		}
		f, err = AppendCreate(r.Cfg.Options.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		outputWriter.AddWriters(f)
		if r.Cfg.Options.Csv {
			_ = LivingTargetCsv(nil, true, f, cache)
		}
	}

	for currentRetries := 0; currentRetries < Retries; currentRetries++ {
		pathUrls = randShuffle(pathUrls)
		targets = randShuffle(targets)
		for _, p := range pathUrls {
			for _, t := range targets {
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
						if !r.Cfg.Options.OnlyTargets {
							if targetResult.Status == 404 || targetResult.Status == 500 || targetResult.Status == 0 {
								return
							}
							if !r.Cfg.Options.SkipCode && targetResult.Status != 200 {
								return
							}
						}
						r.Cfg.Results.AddPathByResult(targetResult.Target, targetResult.Path)

						r.handlerOutputTarget(targetResult)
						switch {
						case f != nil && !r.Cfg.Options.Csv:
							outputWriter.WriteString(targetResult.Target)
						case f != nil && r.Cfg.Options.Csv:
							_ = LivingTargetCsv(targetResult, false, f, cache)
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
