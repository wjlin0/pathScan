package runner

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/pkg/api"
	"github.com/wjlin0/pathScan/pkg/common/identification"
	"github.com/wjlin0/pathScan/pkg/common/uncover"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"github.com/wjlin0/pathScan/pkg/writer"
	"golang.org/x/net/context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed js/template.html
var template string

//go:embed js/antd.min.css
var antdMinCss string

//go:embed js/antd.min.js
var antdMinJs string

//go:embed js/vue.min.js
var vueMinJs string

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
	err = run.Cfg.Options.Validate()
	if err != nil {
		return nil, err
	}
	// 初始化

	err = InitPathScan()
	if err != nil {
		return nil, err
	}

	// 检查版本更新
	if (!run.Cfg.Options.UpdatePathScanVersion && !run.Cfg.Options.UpdateMatchVersion) && !run.Cfg.Options.Silent && !run.Cfg.Options.SkipAutoUpdateMatch {
		err := CheckVersion()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}

		err, ok := CheckMatchVersion()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if ok && err == nil {
			ok, err = UpdateMatch()
			if err != nil && ok == false {
				gologger.Error().Msg(err.Error())
			} else {
				gologger.Info().Msgf("Successfully updated pathScan-match (%s) to %s. GoodLuck!", PathScanMatchVersion, defaultMatchDir)
			}
		}

	}
	// 下载字典或更新版本
	if run.Cfg.Options.UpdatePathScanVersion || run.Cfg.Options.UpdateMatchVersion {
		if run.Cfg.Options.UpdatePathScanVersion {
			ok, err := UpdateVersion()
			if err != nil && ok == false {
				gologger.Error().Msg(err.Error())
			}
		}
		if run.Cfg.Options.UpdateMatchVersion {
			ok, err := UpdateMatch()
			if err != nil && ok == false {
				gologger.Error().Msg(err.Error())
			}
		}
		return nil, nil
	}

	// 清除恢复文件夹
	if run.Cfg.Options.ClearResume {
		_ = os.Remove(DefaultResumeFolderPath())
		gologger.Info().Msgf("successfully cleaned up folder：%s", DefaultResumeFolderPath())
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
		defer resp.Body.Close()
		hash, _ := util.GetHash(buffer.Bytes(), run.Cfg.Options.SkipHashMethod)
		fmt.Printf("[%s] %s", aurora.Green("HASH").String(), string(hash))
		os.Exit(0)
	}

	run.limiter = ratelimit.New(context.Background(), uint(run.Cfg.Options.RateLimit), time.Second)
	run.wg = new(sizedwaitgroup.SizedWaitGroup)
	*run.wg = sizedwaitgroup.New(run.Cfg.Options.Threads)
	run.targets_, err = run.handlerGetTargets()
	run.paths, err = run.handlerGetTargetPath()
	if err != nil {
		return nil, err
	}
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

	run.regOptions, err = identification.ParserHandler(matchPath)
	if err != nil {
		return nil, err
	}
	// 统计数目
	regNum := 0
	for _, rOptions := range run.regOptions {
		regNum += len(rOptions.SubMatch)
	}
	gologger.Info().Msgf("pathScan-match templates loaded for current scan: %d", regNum)
	run.outputResult = make(chan *result.Result)
	return run, nil
}

func (r *Runner) RunEnumeration() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	var err error

	startTime := time.Now()
	getWriter := func(output string) (io.Writer, error) {
		var outputWriter io.Writer
		//outputWriter, _ := ucRunner.NewOutputWriter()

		switch {
		case r.Cfg.Options.Csv:
			if output != "" {
				outputFolder := filepath.Dir(output)
				if err = os.MkdirAll(outputFolder, 0700); err != nil {
					return nil, err
				}
				outputWriter, err = writer.NewCSVWriter(output, result.Result{})
				if err != nil {
					return nil, err
				}
			}
		case r.Cfg.Options.Html:
			if output != "" {
				if !util.FindStringInFile(output, `<title>HTML格式报告</title>`) {

					template2 := strings.Replace(template, "<!-- antd.min.css -->", fmt.Sprintf("<style>%s</style>", antdMinCss), -1)
					template2 = strings.Replace(template2, "<!-- vue.min.js -->", fmt.Sprintf("<script>%s</script>", vueMinJs), -1)
					template2 = strings.Replace(template2, "<!-- antd.min.js -->", fmt.Sprintf("<script>%s</script>", antdMinJs), -1)

					err = util.WriteFile(output, template2)
					if err != nil {
						return nil, err
					}
				}
				outputWriter, err = writer.NewHTMLWriter(output)
				if err != nil {
					return nil, err
				}
			}
		default:
			if output != "" {
				outputFolder := filepath.Dir(output)
				if err = os.MkdirAll(outputFolder, 0700); err != nil {
					return nil, err
				}
				create, err := util.AppendCreate(output)
				if err != nil {
					return nil, err
				}
				outputWriter = create
			}
		}
		return outputWriter, nil
	}
	outputWriter, err := writer.NewOutputWriter()
	if err != nil {
		return err
	}

	o, err := getWriter(r.Cfg.Options.Output)
	if err == nil && o != nil {
		outputWriter.AddWriters(o)
	}
	go r.output(outputWriter)
	switch {
	case r.Cfg.Options.API:
		mapOpt := make(map[string]interface{})
		mapOpt["proxy-api-server"] = r.Cfg.Options.ProxyServerAddr
		mapOpt["proxy-api-web-server"] = r.Cfg.Options.ProxyWebAddr
		mapOpt["proxy-api-cert-path"] = r.Cfg.Options.ProxyServerCaPath
		mapOpt["proxy-api-large-body"] = r.Cfg.Options.ProxyServerStremLargeBodies
		mapOpt["proxy-api-allow-hosts"] = []string(r.Cfg.Options.ProxyServerAllowHosts)
		mapOpt["proxy-api-ssl-insecure"] = r.Cfg.Options.ProxyServerSSLInsecure
		mapOpt["proxy"] = r.Cfg.Options.Proxy
		mapOpt["proxy-auth"] = r.Cfg.Options.ProxyAuth
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
		ch, err := uncover.GetTarget(r.Cfg.Options.UncoverLimit, r.Cfg.Options.UncoverField, r.Cfg.Options.Csv, r.Cfg.Options.UncoverOutput, r.Cfg.Options.UncoverEngine, r.Cfg.Options.UncoverQuery, r.Cfg.Options.Proxy, r.Cfg.Options.ProxyAuth)
		if err != nil {
			return err
		}
		for c := range ch {
			urls = append(urls, c)
		}
		urls = util.RemoveDuplicateStrings(urls)
		gologger.Info().Msgf("Successfully requested cyberspace mapping( %s ) and collected %d domain names", strings.Join(r.Cfg.Options.UncoverEngine, ","), len(urls))

		lenPath := len(paths)
		if lenPath <= 0 {
			lenPath = 1
		}
		gologger.Info().Msgf("This task will issue requests of over %d", len(urls)*lenPath)
		// 识别Favicon
		if r.Cfg.Options.Favicon {
			for o := range result.Rand(urls, []string{"/favicon.ico"}) {
				proto := HTTPorHTTPS
				if strings.HasPrefix(o[0], "http://") {
					proto = HTTP
					o[0] = strings.Replace(o[0], "http://", "", 1)
				} else if strings.HasPrefix(o[0], "https://") {
					proto = HTTPS
					o[0] = strings.Replace(o[0], "https://", "", 1)
				}
				r.process(o[0], o[1], proto, []string{"GET"}, ctx, r.wg)
			}
		}
		for out := range result.Rand(urls, paths) {
			target := out[0]
			path := out[1]
			proto := HTTPandHTTPS
			if strings.HasPrefix(target, "http://") {
				proto = HTTP
				target = strings.Replace(target, "http://", "", 1)
			} else if strings.HasPrefix(target, "https://") {
				proto = HTTPS
				target = strings.Replace(target, "https://", "", 1)
			}
			r.process(target, path, proto, r.Cfg.Options.Method, ctx, r.wg)
		}
		r.wg.Wait()
		cancel()
	case r.Cfg.Options.Subdomain:

		var (
			err   error
			urls  []string
			paths = r.paths
		)

		unc, err := uncover.GetTarget(r.Cfg.Options.SubdomainLimit, "host", r.Cfg.Options.Csv, r.Cfg.Options.SubdomainOutput, r.Cfg.Options.SubdomainEngine, r.Cfg.Options.SubdomainQuery, r.Cfg.Options.Proxy, r.Cfg.Options.ProxyAuth)
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
		urls = util.RemoveDuplicateStrings(urls)
		gologger.Info().Msgf("This task will issue requests of over %d", len(urls)*lenPath)
		// 识别Favicon
		if r.Cfg.Options.Favicon {
			for o := range result.Rand(urls, []string{"/favicon.ico"}) {
				proto := HTTPorHTTPS
				if strings.HasPrefix(o[0], "http://") {
					proto = HTTP
					o[0] = strings.Replace(o[0], "http://", "", 1)
				} else if strings.HasPrefix(o[0], "https://") {
					proto = HTTPS
					o[0] = strings.Replace(o[0], "https://", "", 1)
				}
				r.process(o[0], o[1], proto, []string{"GET"}, ctx, r.wg)
			}
		}

		out := result.Rand(urls, paths)
		for o := range out {
			target := o[0]
			path := o[1]
			proto := HTTPorHTTPS
			if strings.HasPrefix(o[0], "http://") {
				proto = HTTP
				target = strings.Replace(target, "http://", "", 1)
			} else if strings.HasPrefix(target, "https://") {
				proto = HTTPS
				target = strings.Replace(target, "https://", "", 1)
			}
			r.process(target, path, proto, r.Cfg.Options.Method, ctx, r.wg)
		}
		r.wg.Wait()
		cancel()
	case r.Cfg.Options.RecursiveRun:
		gologger.Info().Msgf("Start recursive scanning, scanning depth %d", r.Cfg.Options.RecursiveRunTimes)
		var paths = r.paths
		var urls = r.targets_

		for o := range result.Rand(urls) {
			proto := HTTPorHTTPS
			if strings.HasPrefix(o[0], "http://") {
				proto = HTTP
				o[0] = strings.Replace(o[0], "http://", "", 1)
			} else if strings.HasPrefix(o[0], "https://") {
				proto = HTTPS
				o[0] = strings.Replace(o[0], "https://", "", 1)
			}
			r.processRetry(o[0], paths, proto, ctx, r.wg)
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
				proto := HTTPorHTTPS
				if strings.HasPrefix(o[0], "http://") {
					proto = HTTP
					o[0] = strings.Replace(o[0], "http://", "", 1)
				} else if strings.HasPrefix(o[0], "https://") {
					proto = HTTPS
					o[0] = strings.Replace(o[0], "https://", "", 1)
				}
				r.process(o[0], o[1], proto, []string{"GET"}, ctx, r.wg)
			}
		}

		gologger.Info().Msgf("This task will issue requests of over %d", len(urls)*len(paths))
		out := result.Rand(urls, paths)
		for o := range out {
			proto := HTTPorHTTPS
			if strings.HasPrefix(o[0], "http://") {
				proto = HTTP
				o[0] = strings.Replace(o[0], "http://", "", 1)
			} else if strings.HasPrefix(o[0], "https://") {
				proto = HTTPS
				o[0] = strings.Replace(o[0], "https://", "", 1)
			}

			r.process(o[0], o[1], proto, r.Cfg.Options.Method, ctx, r.wg)
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
	i := 0
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
							check := mapResult["check"].(bool)
							targetResult := mapResult["result"].(*result.Result)
							if targetResult == nil || check {
								return
							}
							if r.Cfg.Options.ResultBack != nil {
								r.Cfg.Options.ResultBack(targetResult)
								return
							}
							r.outputResult <- targetResult
							if r.Cfg.Options.FindOtherDomain && targetResult.Links != nil {
								for _, link := range targetResult.Links {
									proto := HTTPorHTTPS
									if strings.HasPrefix(link, "http://") {
										proto = HTTP
										link = strings.Replace(link, "http://", "", 1)
									} else if strings.HasPrefix(link, "https://") {
										proto = HTTPS
										link = strings.Replace(link, "https://", "", 1)
									}
									go func(target string, proto string) {
										r.process(target, "", proto, []string{"GET"}, ctx, wg)
									}(link, proto)
								}
							}
							// 判断 status 状态码是否是跳转
							ok1 := (targetResult.Status == 301 || targetResult.Status == 302) && !strings.HasSuffix(path, "/") && targetResult.Header["Location"][0] == fmt.Sprintf("%s/", targetResult.Path)
							ok2 := targetResult.Status == 200 && strings.HasSuffix(path, "/")
							if !(ok1 || ok2) && (strings.Contains(path, "%5C") || strings.Contains(path, "..")) {
								return
							}
							tmp := path
							if !strings.HasSuffix(path, "/") {
								tmp = fmt.Sprintf("%s/", path)
							}
							l := strings.Count(strings.Trim(tmp, "/"), "/")
							if l <= r.Cfg.Options.RecursiveRunTimes {
								return
							}
							r.Cfg.Rwm.Lock()
							targetsMap[l+1] = append(targetsMap[l+1], fmt.Sprintf("%s%s", target, tmp))
							r.Cfg.Rwm.Unlock()
						}(t, protocol, path)
					}
				}
				wg.Wait()
				i++
				targetsMap[i] = util.RemoveDuplicateStrings(targetsMap[i])
				if i < r.Cfg.Options.RecursiveRunTimes && len(targetsMap[i]) > 0 {

					time.Sleep(5 * time.Second)
					goto retries
				}
				count := 0
				for c, v := range targetsMap {
					if c == 0 {
						continue
					}
					count += len(v)
				}
				gologger.Info().Msgf("%s has completed %d rounds of scanning and found a total of %d directories", target, i, count)
				for c, v := range targetsMap {
					if c == 0 {
						continue
					}
					for vi, _ := range v {
						gologger.Info().Msgf("%s://%s", protocol, v[vi])
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

					check := mapResult["check"].(bool)
					targetResult := mapResult["result"].(*result.Result)

					if targetResult == nil || check {
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
						proto := HTTPorHTTPS
						if strings.HasPrefix(link, "http://") {
							proto = HTTP
							link = strings.Replace(link, "http://", "", 1)
						} else if strings.HasPrefix(link, "https://") {
							proto = HTTPS
							link = strings.Replace(link, "https://", "", 1)
						}
						go func(target string, proto string) {
							r.process(target, "", proto, []string{"GET"}, ctx, wg)
						}(link, proto)
					}

				}(target, path, proto, method)
			}
		}
	}

	return
}
