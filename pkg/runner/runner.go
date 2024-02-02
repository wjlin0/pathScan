package runner

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/fatih/color"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/pkg/api"
	"github.com/wjlin0/pathScan/pkg/common/identification"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	updateutils "github.com/wjlin0/pathScan/pkg/util/update"
	"github.com/wjlin0/pathScan/pkg/writer"
	"github.com/wjlin0/uncover"
	"github.com/wjlin0/uncover/core"
	"golang.org/x/net/context"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	wg           *sizedwaitgroup.SizedWaitGroup
	Cfg          *ResumeCfg
	limiter      *ratelimit.Limiter
	client       *http.Client
	dialer       *fastdialer.Dialer
	targets_     []string
	paths        []string
	headers      map[string]interface{}
	skipCode     map[string]struct{}
	regOptions   []*identification.Options
	retryable    *retryablehttp.Client
	outputResult chan *result.Result
}

func NewRunner(options *Options) (*Runner, error) {

	run := &Runner{}
	var cfg *ResumeCfg
	var err error
	// 如果存在恢复配置，解析它并设置相应的选项
	if options.ResumeCfg != "" {
		cfg, err = ParserResumeCfg(options.ResumeCfg)
		if err != nil {
			return nil, err
		}

		// 将 ResumeCfg 字段设置为 options.ResumeCfg
		cfg.Options.ResumeCfg = options.ResumeCfg
	}
	if cfg == nil {
		run.Cfg = &ResumeCfg{
			Rwm:           &sync.RWMutex{},
			Options:       options,
			ResultsCached: NewCached(),
			OutputCached:  NewCached(),
		}
	} else {
		run.Cfg = cfg
	}

	// 配置输出方式
	run.Cfg.Options.configureOutput()
	// 验证选项是否合法
	if err = run.Cfg.Options.ValidateFunc(); err != nil {
		return nil, err
	}
	if run.Cfg.Options.Validate {
		// 检查 pathScan-match 是否正常
		if err := run.Cfg.Options.ValidateMatch(); err != nil {
			gologger.Error().Msgf("pathScan-match has been tampered with: %s", err.Error())
		} else {
			gologger.Info().Msgf("successfully validated pathScan-match")
		}
		return nil, nil
	}
	// 初始化
	if needPathScanInit() {
		gologger.Info().Msg("initializing in progress.")
		if err = initPathScan(); err != nil {
			return nil, err
		}
		PathScanMatchVersion, _ = util.GetMatchVersion(defaultMatchDir)
		gologger.Info().Msgf("Successfully initialized pathScan-match version %s => %s (%s)", defaultPathScanDir, PathScanMatchVersion, color.HiGreenString("latest"))
		gologger.Info().Msg("initialization completed.")
	}

	// 检查版本更新
	if !run.Cfg.Options.Silent && !run.Cfg.Options.SkipAutoUpdateMatch {
		latestVersion, err := updateutils.GetToolVersionCallback("", pathScanRepoName)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("%s version check failed: %v", toolName, err.Error())
			}
		} else {
			gologger.Info().Msgf("Current %s version %v %v", toolName, Version, updateutils.GetVersionDescription(Version, latestVersion))
		}
		psMVersion := strings.Replace(PathScanMatchVersion, "v", "", 1)
		latestVersion, err = updateutils.GetToolVersionCallback("", pathScanMatchRepoName)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("%s version check failed: %v", pathScanMatchRepoName, err.Error())
			}
		} else {
			gologger.Info().Msgf("Current %s version %v %v", pathScanMatchRepoName, psMVersion, updateutils.GetVersionDescription(psMVersion, latestVersion))
		}
		if updateutils.IsOutdated(psMVersion, latestVersion) {
			if err = updateutils.GetUpdateDirFromRepoCallback(pathScanMatchRepoName, defaultMatchDir, pathScanMatchRepoName)(); err != nil {
				if run.Cfg.Options.Verbose {
					gologger.Error().Msgf("Failed to update %s: %v", pathScanMatchRepoName, err)
				}
			} else {
				gologger.Info().Msgf("%v sucessfully updated %v -> %v (%s)", toolName, psMVersion, latestVersion, color.HiGreenString("latest"))
			}
		}
	}

	// 清除恢复文件夹
	if run.Cfg.Options.ClearResume {
		_ = os.RemoveAll(defaultResume)
		gologger.Info().Msgf("successfully cleaned up folder：%s", defaultResume)
		os.Exit(0)
	}

	// 创建 HTTP 客户端、速率限制器、等待组、目标列表、目标路径列表和头部列表
	fastOptons := fastdialer.DefaultOptions
	fastOptons.WithDialerHistory = true
	fastOptons.EnableFallback = true
	if len(options.Resolvers) > 0 {

		fastOptons.BaseResolvers = options.Resolvers
	}
	run.dialer, err = fastdialer.NewDialer(fastOptons)
	if err != nil {
		return nil, err
	}
	run.targets_, err = run.handlerGetTargets()
	run.paths, err = run.handlerGetTargetPath()
	if err != nil {
		return nil, err
	}
	run.retryable = run.NewRetryableClient()
	// 计算hash
	if run.Cfg.Options.GetHash {
		uri := run.Cfg.Options.Url[0]
		resp, err := run.retryable.Get(uri)
		if err != nil {
			return nil, err
		}
		buffer := bytes.Buffer{}
		_, err = io.Copy(&buffer, resp.Body)
		if err != nil {
			return nil, err
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		hash, _ := util.GetHash(buffer.Bytes(), run.Cfg.Options.SkipHashMethod)
		fmt.Printf("[%s] %s\n", color.GreenString(fmt.Sprintf("%s", run.Cfg.Options.SkipHashMethod)), string(hash))
		return nil, nil
	}

	run.limiter = ratelimit.New(context.Background(), uint(run.Cfg.Options.RateLimit), time.Second)
	run.wg = new(sizedwaitgroup.SizedWaitGroup)
	*run.wg = sizedwaitgroup.New(run.Cfg.Options.Threads)
	run.headers = run.handlerHeader()
	run.skipCode = make(map[string]struct{})
	for _, status := range run.Cfg.Options.SkipCode {
		run.skipCode[status] = struct{}{}
	}
	// 加载正则匹配规则
	matchPath := run.Cfg.Options.MatchPath
	if matchPath == "" {
		matchPath = defaultMatchDir
	}

	if run.regOptions, err = identification.ParserHandler(matchPath); err != nil {
		gologger.Print().Label(color.HiYellowString("WAN")).Msgf("Failed to load pathScan-match: %s use -validate", err)
	}
	// 统计数目
	regNum := 0
	for _, rOptions := range run.regOptions {
		regNum += len(rOptions.SubMatch)
	}
	if run.Cfg.Options.SkipBodyRegex != nil {
		for _, r := range run.Cfg.Options.SkipBodyRegex {
			compile, err := regexp.Compile(r)
			if err != nil {
				return nil, err
			}
			run.Cfg.Options.skipBodyRegex = append(run.Cfg.Options.skipBodyRegex, compile)
		}
	}
	gologger.Info().Msgf("pathScan-match templates loaded for current scan: %d", regNum)
	run.outputResult = make(chan *result.Result)
	return run, nil
}

func (r *Runner) RunEnumeration() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	startTime := time.Now()
	switch {
	default:
		outputWriter, err := writer.NewOutputWriter()
		if err != nil {
			return err
		}
		outputType := 0
		switch {
		case r.Cfg.Options.Csv:
			outputType = 1
		case r.Cfg.Options.Html:
			outputType = 2
		case r.Cfg.Options.Silent:
			outputType = 3
		}
		writers, err := writer.NewOutputWriters(r.Cfg.Options.Output, outputType)
		if err == nil && writers != nil {
			outputWriter.AddWriters(writers)
		}
		go outputWriter.Output(r.outputResult, outputType)
	}
	switch {
	case r.Cfg.Options.API:
		mapOpt := make(map[string]interface{})
		mapOpt["proxy-api-server"] = r.Cfg.Options.ProxyServerAddr
		mapOpt["proxy-api-cert-path"] = r.Cfg.Options.ProxyServerCaPath
		mapOpt["proxy-api-large-body"] = r.Cfg.Options.ProxyServerStremLargeBodies
		mapOpt["proxy-api-allow-hosts"] = []string(r.Cfg.Options.ProxyServerAllowHosts)
		mapOpt["proxy"] = r.Cfg.Options.Proxy
		mapOpt["proxy-auth"] = r.Cfg.Options.ProxyAuth
		mapOpt["output"] = r.outputResult
		mapOpt["regexOpts"] = r.regOptions
		opt, err := api.New(mapOpt)
		if err != nil {
			return err
		}
		return opt.Start()
	case r.Cfg.Options.Uncover:
		var (
			urls  []string
			paths = r.paths
		)
		if len(paths) == 0 {
			paths = []string{"/"}
		}

		gologger.Info().Msgf("Running: %s", strings.Join(r.Cfg.Options.UncoverEngine, ","))
		ch, err := core.GetTarget(r.Cfg.Options.UncoverLimit, r.Cfg.Options.UncoverField, r.Cfg.Options.Csv, r.Cfg.Options.UncoverOutput, r.Cfg.Options.UncoverEngine, r.Cfg.Options.UncoverQuery, r.Cfg.Options.Proxy, r.Cfg.Options.ProxyAuth, defaultProviderConfigLocation)
		if err != nil {
			return err
		}
		for c := range ch {
			urls = append(urls, c)
		}
		gologger.Info().Msgf("Successfully requested cyberspace mapping( %s ) and collected %d domain names", strings.Join(r.Cfg.Options.UncoverEngine, ","), len(urls))
		urls = util.RemoveDuplicateStrings(append(urls, r.targets_...))

		lenPath := len(paths)
		if lenPath <= 0 {
			lenPath = 1
		}
		gologger.Info().Msgf("This task will issue requests of over %d", len(urls)*lenPath)
		// 识别Favicon
		if r.Cfg.Options.Favicon {
			for o := range result.Rand(urls, []string{"/favicon.ico"}) {
				proto, t := util.GetProtocolAndHost(o[0])
				_url, err := url.Parse(fmt.Sprintf("%s://%s", proto, t))
				if err != nil {
					continue
				}
				t = _url.Host
				r.process(t, o[1], proto, []string{"GET"}, ctx, r.wg)
			}
		}
		for out := range result.Rand(urls, paths) {
			path := out[1]
			proto, t := util.GetProtocolAndHost(out[0])
			r.process(t, path, proto, r.Cfg.Options.Method, ctx, r.wg)
		}
		r.wg.Wait()
		cancel()
	case r.Cfg.Options.Subdomain:

		var (
			err   error
			urls  []string
			paths = r.paths
		)
		uncover.DefaultCallback = func(query string, agent string) string {
			if !util.IsValidDomain(query) {
				return query
			}
			switch agent {
			case "fofa":
				return fmt.Sprintf(`domain="%s"`, query)
			case "hunter":
				return fmt.Sprintf(`domain.suffix="%s"`, query)
			case "quake":
				return fmt.Sprintf(`domain:"%s"`, query)
			case "zoomeye":
				return fmt.Sprintf(`site:%s`, query)
			case "netlas":
				return fmt.Sprintf(`domain:%s`, query)
			case "fofa-spider":
				return fmt.Sprintf(`domain="%s"`, query)
			default:
				return query
			}
		}

		unc, err := core.GetTarget(r.Cfg.Options.SubdomainLimit, "host", r.Cfg.Options.Csv, r.Cfg.Options.SubdomainOutput, r.Cfg.Options.SubdomainEngine, r.Cfg.Options.SubdomainQuery, r.Cfg.Options.Proxy, r.Cfg.Options.ProxyAuth, defaultProviderConfigLocation)
		if err != nil {
			return err
		}
		for u := range unc {
			urls = append(urls, u)
		}
		gologger.Info().Msgf("Successfully requested cyberspace mapping( %s ) and collected %d domain names", strings.Join(r.Cfg.Options.SubdomainEngine, ","), len(urls))

		lenPath := len(paths)
		if lenPath <= 0 {
			lenPath = 1
		}

		// 去重
		urls = util.RemoveDuplicateStrings(append(urls, r.targets_...))
		gologger.Info().Msgf("This task will issue requests of over %d", len(urls)*lenPath)

		// 识别Favicon

		if r.Cfg.Options.Favicon {
			for o := range result.Rand(urls, []string{"/favicon.ico"}) {
				proto, t := util.GetProtocolAndHost(o[0])
				_url, err := url.Parse(fmt.Sprintf("%s://%s", proto, t))
				if err != nil {
					continue
				}
				t = _url.Host
				r.process(t, o[1], proto, []string{"GET"}, ctx, r.wg)
			}
		}

		out := result.Rand(urls, paths)
		for o := range out {
			proto, t := util.GetProtocolAndHost(o[0])
			r.process(t, o[1], proto, r.Cfg.Options.Method, ctx, r.wg)
		}
		r.wg.Wait()
		cancel()
	case r.Cfg.Options.RecursiveRun:
		gologger.Info().Msgf("Start recursive scanning, scanning depth %d", r.Cfg.Options.RecursiveRunTimes)
		var paths = r.paths
		var urls = r.targets_

		for o := range result.Rand(urls) {
			proto, t := util.GetProtocolAndHost(o[0])
			r.processRetry(t, paths, proto, ctx, r.wg)
		}
	default:
		var urls = r.targets_
		var paths = r.paths
		if r.Cfg.Options.OnlyTargets {
			paths = []string{"/"}
		}
		// 识别Favicon
		if r.Cfg.Options.Favicon {
			for o := range result.Rand(urls, []string{"/favicon.ico"}) {
				proto, t := util.GetProtocolAndHost(o[0])
				_url, err := url.Parse(fmt.Sprintf("%s://%s", proto, t))
				if err != nil {
					continue
				}
				t = _url.Host
				r.process(t, o[1], proto, []string{"GET"}, ctx, r.wg)
			}
		}

		gologger.Info().Msgf("This task will issue requests of over %d", len(urls)*len(paths))
		out := result.Rand(urls, paths)
		for o := range out {
			proto, t := util.GetProtocolAndHost(o[0])
			r.process(t, o[1], proto, r.Cfg.Options.Method, ctx, r.wg)
		}
		time.Sleep(time.Duration(r.Cfg.Options.WaitTimeout) * time.Second)
		r.wg.Wait()
		cancel()
	}
	r.Close()
	r.Cfg.ClearResume()

	gologger.Info().Msgf("This task takes %v seconds", time.Since(startTime).Seconds())
	return nil
}
func (r *Runner) Close() {
	func() {
		r.dialer.Close()
		r.limiter.Stop()
		close(r.outputResult)
	}()
}
func (r *Runner) processRetry(t string, paths []string, protocol string, ctx context.Context, wg *sizedwaitgroup.SizedWaitGroup) {
	protocols := []string{protocol}
	if protocol == HTTPandHTTPS {
		protocols = []string{HTTPS, HTTP}
	}
	targets := []string{t}
	wg2 := sizedwaitgroup.New(3)
	for _, protocol := range protocols {
		for _, t := range targets {
			wg2.Add()
			go func(protocol string, target string, paths []string) {
				defer wg2.Done()
				// 初始化目录结构层次目标
				targetsMap := make(map[int][]string)
				targetsMap[0] = append(targetsMap[0], target)
				backslashesNum := 0
				i := 0
				parse, err := url.Parse(fmt.Sprintf("%s://%s", protocol, target))
				if err == nil {
					if strings.Trim(parse.Path, "/") != "" {
						backslashesNum = strings.Count(strings.Trim(parse.Path, "/"), "/") + 1
					}
				}
			retries:
				for _, t := range targetsMap[i] {
					for _, path := range util.RemoveDuplicateStrings(paths) {
						wg.Add()
						go func(target string, protocol string, path string) {
							defer wg.Done()
							mapResult, err := r.analyze(protocol, result.Target{Host: target}, path, r.Cfg.Options.Method[0])
							if err != nil {
								gologger.Warning().Msgf("An error occurred: %s", err)
								return
							}
							if mapResult == nil || mapResult["result"] == nil || mapResult["check"] == nil {
								return
							}
							check := mapResult["check"].(bool)
							targetResult := mapResult["result"].(*result.Result)
							if check {
								return
							}
							if r.Cfg.Options.ResultBack != nil {
								r.Cfg.Options.ResultBack(targetResult)
								return
							}
							r.outputResult <- targetResult
							if r.Cfg.Options.FindOtherDomain && targetResult.Links != nil {
								for _, link := range targetResult.Links {
									go func(proto string, target string) {
										r.process(target, "", proto, []string{"GET"}, ctx, wg)
									}(util.GetProtocolAndHost(link))
								}
							}
							// 判断 是否目录
							ok1 := (targetResult.Status == 301) && !strings.HasSuffix(path, "/") && strings.Contains(targetResult.Header["Location"][0], fmt.Sprintf("%s/", targetResult.Path))
							ok2 := targetResult.Status == 200 && strings.HasSuffix(path, "/")
							if !(ok1 || ok2) || (strings.Contains(path, "%5C") || strings.Contains(path, "..")) {
								return
							}

							target = targetResult.HTTPurl.Host
							path = targetResult.Path
							if !strings.HasSuffix(path, "/") {
								path = fmt.Sprintf("%s/", path)
							}
							//fmt.Println("[+]", target, path)
							l := strings.Count(strings.Trim(path, "/"), "/")
							if l+1-backslashesNum > r.Cfg.Options.RecursiveRunTimes {
								return
							}
							joinPath, err := url.JoinPath(target, path)
							if err != nil {
								target = strings.TrimRight(target, "/")
								if !strings.HasPrefix(path, "/") {
									path = fmt.Sprintf("/%s", path)
								}
								joinPath = fmt.Sprintf("%s%s", target, path)
							}
							r.Cfg.Rwm.Lock()
							targetsMap[l+1-backslashesNum] = append(targetsMap[l+1-backslashesNum], joinPath)
							r.Cfg.Rwm.Unlock()
						}(t, protocol, path)
					}
				}
				wg.Wait()

				targetsMap[i+1] = util.RemoveDuplicateStrings(targetsMap[i+1])
				if i+1 <= r.Cfg.Options.RecursiveRunTimes && len(targetsMap[i+1]) > 0 {
					i++
					goto retries
				}
				count := 0
				for c, v := range targetsMap {
					if c == 0 {
						continue
					}
					count += len(util.RemoveDuplicateStrings(v))
				}
				gologger.Info().Msgf("%s has completed %d rounds of scanning and found a total of %d directories", target, r.Cfg.Options.RecursiveRunTimes, count)
				for c, v := range targetsMap {
					if c == 0 {
						continue
					}
					for _, vv := range util.RemoveDuplicateStrings(v) {
						gologger.Info().Msgf("%s://%s", protocol, vv)
					}
				}
				return

			}(protocol, t, paths)

		}
	}
	wg2.Wait()
}
func (r *Runner) process(t, path string, protocol string, methods []string, ctx context.Context, wg *sizedwaitgroup.SizedWaitGroup) {
	protocols := []string{protocol}
	if protocol == HTTPandHTTPS {
		protocols = []string{HTTPS, HTTP}
	}
	for target := range r.targets(t) {
		for _, method := range methods {
			for _, proto := range protocols {
				wg.Add()
				go func(target result.Target, path, protocol, method string) {

					defer wg.Done()

					mapResult, err := r.analyze(protocol, target, path, method)
					if err != nil {
						gologger.Warning().Msgf("An error occurred: %s", err)
						return
					}

					if mapResult == nil || mapResult["result"] == nil || mapResult["check"] == nil {
						return
					}
					check := mapResult["check"].(bool)
					targetResult := mapResult["result"].(*result.Result)
					if check {
						return
					}
					if r.Cfg.Options.ResultBack != nil {
						r.Cfg.Options.ResultBack(targetResult)
					}
					r.outputResult <- targetResult
					if !r.Cfg.Options.FindOtherDomain || targetResult.Links == nil {
						return
					}
					for _, link := range targetResult.Links {
						go func(proto string, target string) {
							r.process(target, "", proto, []string{"GET"}, ctx, wg)
						}(util.GetProtocolAndHost(link))
					}

				}(target, path, proto, method)
			}
		}
	}

	return
}
