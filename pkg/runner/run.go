package runner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/pkg/result"
	"golang.org/x/net/context"
	"io"
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
				cfg.Results.TargetPaths = make(map[string]map[string]*result.TargetResult)
			}
			if cfg.Results.Skipped == nil {
				cfg.Results.Skipped = make(map[string]map[string]*result.TargetResult)
			}
			cfg.Options.ResumeCfg = options.ResumeCfg
			run.Cfg = cfg
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
	run.limiter = ratelimit.New(context.Background(), uint(run.Cfg.Options.RateHttp), time.Duration(1)*time.Second)
	run.client = newClient(run.Cfg.Options)
	run.wg = sizedwaitgroup.New(run.Cfg.Options.Rate)
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
func newClient(options *Options) *http.Client {
	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if options.Proxy != "" {
		proxyUrl, _ := url.Parse(options.Proxy)
		if options.ProxyAuth != "" {
			proxyUrl.User = url.UserPassword(strings.Split(options.ProxyAuth, ":")[0], strings.Split(options.ProxyAuth, ":")[1])
		}
		t.Proxy = http.ProxyURL(proxyUrl)
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client
}

func (r *Runner) DiscoveryHost(targets []string) {

	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			if r.Cfg.Results.HasTarget(target) {
				return
			}
			r.limiter.Take()
			exit, err := r.ConnectTarget(target)
			if exit && err == nil {
				r.Cfg.Results.AddTarget(target)
				if r.Cfg.Options.Silent {
					gologger.Silent().Msg(target)
				}
				if r.Cfg.Options.OnlyTargets {
					gologger.Info().Msgf("发现 %s 存活", target)
				} else {
					gologger.Debug().Msgf("发现 %s 存活", target)
				}
			} else {
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
	showBanner()

	r.DiscoveryHost(targets)

	if r.Cfg.Options.OnlyTargets {
		return nil
	}
	pathCount := uint64(len(pathUrls))
	targetCount := uint64(r.Cfg.Results.Len())
	Range := pathCount * targetCount
	gologger.Info().Msgf("存活目标总数 -> %d", uint64(r.Cfg.Results.Len()))

	gologger.Info().Msgf("请求总数 -> %d", Range*uint64(r.Cfg.Options.Retries))
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

	for currentRetries := 0; currentRetries < Retries; currentRetries++ {

		for _, p := range pathUrls {
			for t := range r.Cfg.Results.GetTargets() {
				r.wg.Add()
				go func(target, path string) {
					defer r.wg.Done()
					skipped, ok := r.Cfg.Results.HasSkipped(target, path)
					if ok {
						r.Cfg.Results.AddPathByResult(skipped)
						return
					}
					r.limiter.Take()
					targetResult, err := r.GoTargetPath(target, path)
					if targetResult != nil && err == nil {
						r.Cfg.Results.AddPathByResult(targetResult)
						r.Cfg.Results.AddSkipped(targetResult.Target, targetResult.Path, targetResult.Title, targetResult.Status, targetResult.BodyLen)
						r.handlerOutputTarget(targetResult)
					}
				}(t, p)
				if r.Cfg.Options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
			}
		}
	}
	r.wg.Wait()
	r.handlerOutput(r.Cfg.Results)
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

func (r *Runner) getAllTargets() []string {
	at := make(map[string]struct{})
	var resp *http.Response
	var err error
	if r.Cfg.Options.Url != nil {
		for _, u := range r.Cfg.Options.Url {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasPrefix(u, "http") {
				u = "http://" + u
			}
			if _, ok := at[u]; !ok {
				at[u] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.UrlFile != nil {
		for _, u := range r.Cfg.Options.UrlFile {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasPrefix(u, "http") {
				u = "http://" + u
			}
			if _, ok := at[u]; !ok {
				at[u] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.UrlRemote != "" {
		resp, err = http.Get(r.Cfg.Options.UrlRemote)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			for _, u := range strings.Split(string(body), "\n") {
				u = strings.Trim(u, "\r")
				u = strings.Trim(u, "\n")
				if u == "" {
					continue
				}
				if !strings.HasPrefix(u, "http") {
					u = "http://" + u
				}
				if _, ok := at[u]; !ok {
					at[u] = struct{}{}
				}
			}
		}
	}

	var t []string
	for k, _ := range at {
		t = append(t, k)
	}
	if t == nil {
		e := "不存在目标"
		if err != nil {
			e += ":" + err.Error()
		}
		gologger.Error().Msg(e)
		return nil
	}
	return t
}

func (r *Runner) getAllPaths() []string {
	at := make(map[string]struct{})
	var resp *http.Response
	var err error
	if r.Cfg.Options.Path != nil {
		for _, p := range r.Cfg.Options.Path {
			if _, ok := at[p]; !ok {
				p = strings.TrimSpace(p)
				at[p] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.PathFile != nil {
		for _, p := range r.Cfg.Options.PathFile {
			if _, ok := at[p]; !ok {
				p = strings.TrimSpace(p)
				at[p] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.PathRemote != "" {
		request, _ := http.NewRequest("GET", r.Cfg.Options.PathRemote, nil)
		resp, err = r.client.Do(request)
		if err == nil {
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {

				}
			}(resp.Body)
			body, _ := io.ReadAll(resp.Body)
			for _, p := range strings.Split(string(body), "\n") {
				p = strings.Trim(p, "\r")
				p = strings.Trim(p, "\n")
				if p == "" {
					continue
				}
				if _, ok := at[p]; !ok {
					at[p] = struct{}{}
				}

			}
		}
		gologger.Info().Msg("从远程加载字典 完成...")
	}
	if len(at) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			gologger.Error().Msgf(err.Error())
			return nil
		}
		dictPath := filepath.Join(home, ".config", "pathScan", "dict")
		err = DownloadDict()
		if err != nil {
			gologger.Error().Msgf(err.Error())
			return nil
		}
		gologger.Debug().Msgf("远程字典下载成功-> %s", dictPath)
		mainDict := filepath.Join(dictPath, "main.txt")

		paths, err := fileutil.ReadFile(mainDict)
		if err != nil {
			gologger.Error().Msgf(err.Error())
			return nil
		}
		for p := range paths {
			p = strings.Trim(p, "\r")
			p = strings.Trim(p, "\n")
			if p == "" {
				continue
			}
			if _, ok := at[p]; !ok {

				at[p] = struct{}{}
			}
		}
	}
	var t []string
	for k, _ := range at {
		t = append(t, k)
	}
	//gologger.Debug().Msgf("加载字典 -> %d", len(t))
	return t
}

func (r *Runner) handlerOutput(scanResults *result.Result) {
	var (
		file   *os.File
		err    error
		output string
	)

	if r.Cfg.Options.Output != "" {
		output = r.Cfg.Options.Output

		// create path if not existing
		outputFolder := filepath.Dir(output)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				gologger.Error().Msgf("无法创建输出文件夹 %s: %s\n", outputFolder, mkdirErr)
				return
			}
		}

		file, err = os.Create(output)
		if err != nil {
			gologger.Error().Msgf("无法创建文件 %s: %s\n", output, err)
			return
		}
		defer file.Close()
	}

	switch {
	case scanResults.HasPaths():
		for scan, v := range scanResults.GetPathsByTarget() {
			if file != nil {
				err = WriteTargetOutput(scan, v, file)
			}
			if err != nil {
				gologger.Error().Msgf("无法写入文件 %s: %s\n", scan, err)
			}
		}

	case scanResults.HasTargets():
		for target := range scanResults.GetTargets() {
			if file != nil {
				bufwriter := bufio.NewWriter(file)
				sb := &strings.Builder{}
				sb.WriteString(target)
				sb.WriteString("\n")
				_, _ = bufwriter.WriteString(sb.String())
				sb.Reset()
				err := bufwriter.Flush()
				if err != nil {
					gologger.Error().Msgf("无法写入文件 %s: %s\n", target, err)
				}

			}
		}

	}
}
