package runner

import (
	"bytes"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/pkg/common/identification"
	ucRunner "github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/runner"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"golang.org/x/net/context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	wg            *sizedwaitgroup.SizedWaitGroup
	Cfg           *ResumeCfg
	limiter       *ratelimit.Limiter
	client        *http.Client
	dialer        *fastdialer.Dialer
	dirBack       map[string]struct{}
	targets       map[string]struct{}
	paths         map[string]struct{}
	headers       map[string]interface{}
	skipCode      map[string]struct{}
	regOptions    []*identification.Options
	retryable     *retryablehttp.Client
	otherLinkChan chan string
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

		// 如果目标、目标路径或跳过的目标为空，则创建一个空 map
		if cfg.Results.Targets == nil {
			cfg.Results.Targets = make(map[string]struct{})
		}
		if cfg.Results.TargetPaths == nil {
			cfg.Results.TargetPaths = make(map[string]map[string]struct{})
		}
		if cfg.Results.Skipped == nil {
			cfg.Results.Skipped = make(map[string]map[string]struct{})
		}

		// 将 ResumeCfg 字段设置为 options.ResumeCfg
		cfg.Options.ResumeCfg = options.ResumeCfg
	}
	if cfg == nil {
		run.Cfg = &ResumeCfg{
			Rwm:     &sync.RWMutex{},
			Options: options,
			Results: result.NewResult(),
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

	PathScanMatchVersion, err = util.GetMatchVersion(defaultMatchDir)
	if err != nil {
		return nil, err
	}
	// 检查版本更新
	if (!run.Cfg.Options.UpdatePathScanVersion && !run.Cfg.Options.UpdateMatchVersion) && !run.Cfg.Options.Silent && !run.Cfg.Options.UpdateHTMLTemplateVersion {
		err := CheckVersion()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err, ok := CheckMatchVersion()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if ok && err == nil && !run.Cfg.Options.SkipAutoUpdateMatch {
			ok, err = UpdateMatch()
			if err != nil && ok == false {
				gologger.Error().Msg(err.Error())
			} else {
				gologger.Info().Msgf("Successfully updated pathScan-match (%s) to %s. GoodLuck!", PathScanMatchVersion, defaultMatchDir)
			}

		}

	}
	// 下载字典或更新版本
	if run.Cfg.Options.UpdatePathDictVersion || run.Cfg.Options.UpdatePathScanVersion || run.Cfg.Options.UpdateMatchVersion || run.Cfg.Options.UpdateHTMLTemplateVersion {
		if run.Cfg.Options.UpdatePathDictVersion {
			err = DownloadDict()
			if err != nil {
				gologger.Error().Msgf(err.Error())
			}
		}
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
		if run.Cfg.Options.UpdateHTMLTemplateVersion {
			ok, err := UpdateHTMLTemplate()
			if err != nil && ok == false {
				gologger.Error().Msg(err.Error())
			}
		}
		return nil, nil
	}

	// 清除恢复文件夹
	if run.Cfg.Options.ClearResume {
		_ = os.RemoveAll(DefaultResumeFolderPath())
		gologger.Print().Msgf("Successfully cleaned up folder：%s", DefaultResumeFolderPath())
		os.Exit(0)
	}
	// 计算hash
	if run.Cfg.Options.GetHash {
		uri := run.Cfg.Options.Url[0]
		resp, err := http.Get(uri)
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

	// 创建 HTTP 客户端、速率限制器、等待组、目标列表、目标路径列表和头部列表
	fastOptons := fastdialer.Options{
		BaseResolvers:     fastdialer.DefaultResolvers,
		MaxRetries:        options.Retries,
		HostsFile:         true,
		ResolversFile:     true,
		CacheType:         fastdialer.Disk,
		DialerTimeout:     options.TimeoutHttp,
		DialerKeepAlive:   options.TimeoutHttp,
		WithDialerHistory: true,
	}
	dialer, err := fastdialer.NewDialer(fastOptons)
	if err != nil {
		return nil, err
	}
	run.retryable = newRetryableClient(run.Cfg.Options, run.Cfg.Options.ErrUseLastResponse, dialer)
	run.limiter = ratelimit.New(context.Background(), uint(run.Cfg.Options.RateHTTP), time.Duration(1)*time.Second)
	run.wg = new(sizedwaitgroup.SizedWaitGroup)
	*run.wg = sizedwaitgroup.New(run.Cfg.Options.Thread)
	run.targets, err = run.handlerGetTargets()
	run.paths, err = run.handlerGetTargetPath()
	run.dialer = dialer
	if err != nil {
		return nil, err
	}
	run.headers = run.handlerHeader()
	if run.Cfg.Options.RecursiveRun {
		// 读文件
		run.dirBack = make(map[string]struct{})
		c, err := fileutil.ReadFile(run.Cfg.Options.RecursiveRunFile)
		if err != nil {
			return nil, err
		}
		for dir := range c {
			dir = strings.TrimRight(dir, "/")
			run.dirBack[dir] = struct{}{}
		}
	}
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
	// 创建通道
	run.otherLinkChan = make(chan string)
	// 返回 Runner 实例和无误差
	return run, nil
}

func (r *Runner) Run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var urls []string
	var paths []string
	for p, _ := range r.targets {
		urls = append(urls, p)
	}
	for t, _ := range r.paths {
		paths = append(paths, t)
	}
	Retries := r.Cfg.Options.Retries
	var err error
	if r.Cfg.Options.OnlyTargets {
		paths = []string{"/"}
	}
	startTime := time.Now()
	gologger.Info().Msgf("There are %d requested URLs", len(urls))
	gologger.Info().Msgf("There are %d requested paths", len(paths))
	var f *os.File
	outputWriter, _ := ucRunner.NewOutputWriter()
	if r.Cfg.Options.Output != "" && !r.Cfg.Options.Html {
		outputFolder := filepath.Dir(r.Cfg.Options.Output)
		if err = os.MkdirAll(outputFolder, 0700); err != nil {
			return err
		}
		f, err = util.AppendCreate(r.Cfg.Options.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		outputWriter.AddWriters(f)
	}
	if r.Cfg.Options.Csv {
		path, err := LivingTargetHeader(&result.TargetResult{})
		if err != nil {
			return err
		}
		if !r.Cfg.Options.Silent {
			fmt.Println(path)
		}
		outputWriter.WriteString(path)
	}
	outputOtherWriter, _ := ucRunner.NewOutputWriter()
	if r.Cfg.Options.OutputOtherLik != "" {
		outputFolder := filepath.Dir(r.Cfg.Options.OutputOtherLik)
		if mkdirErr := os.MkdirAll(outputFolder, 0700); mkdirErr != nil {
			return mkdirErr
		}
		f, err = util.AppendCreate(r.Cfg.Options.OutputOtherLik)
		if err != nil {
			return err
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)
		outputOtherWriter.AddWriters(f)
		if r.Cfg.Options.Csv {
			path, err := LivingTargetHeader(&result.TargetResult{})
			if path != "" && err == nil {
				outputOtherWriter.WriteString(path)
			}
		}
	} else {
		outputOtherWriter = outputWriter
	}
	if r.Cfg.Options.Html && r.Cfg.Options.Output != "" && !util.FindStringInFile(r.Cfg.Options.Output, `<title>HTML格式报告</title>`) {
		if err = InitHtmlOutput(r.Cfg.Options.Output); err != nil {
			return err
		}
	}

	switch {
	// 流模式还没想好怎么做 有会的 帮帮忙 联系我 给你权限
	case r.Cfg.Options.RecursiveRun:
		// 递归扫描逻辑
		// 递归初始化path数组
		gologger.Info().Msgf("启动递归扫描，扫描深度 %d", r.Cfg.Options.RecursiveRunTimes)
		targetsMap := make(map[string][]string)
		// 初始化输入的递归扫描的路径
		for _, t := range urls {
			targetsMap[t] = []string{}
			for _, p := range paths {
				targetsMap[t] = append(targetsMap[t], p)
			}
		}
		i := 1
		for {
			findTemp := new(map[string][]string)
			*findTemp = make(map[string][]string)
			for i := 1; i < Retries; i++ {
				for t, v := range targetsMap {
					for _, p := range v {
						r.wg.Add()
						go r.GoHandler(t, p, outputWriter, ctx, paths, findTemp, r.wg)
					}
				}
			}
			r.wg.Wait()

			if len(*findTemp) == 0 {
				break
			}
			if i >= r.Cfg.Options.RecursiveRunTimes {
				break
			}
			targetsMap = *findTemp
			for k, _ := range targetsMap {
				gologger.Debug().Msgf("发现新的请求 ->", k)
			}
			i += 1
		}
		//fmt.Println(targetsMap)
	default:
		wg := new(sizedwaitgroup.SizedWaitGroup)
		*wg = sizedwaitgroup.New(r.Cfg.Options.Thread)
		r.wg.Add()
		go r.GoOtherLink(outputOtherWriter, ctx, r.wg)
		out := result.Rand(urls, paths)

		for o := range out {
			wg.Add()
			go r.GoHandler(o[0], o[1], outputWriter, ctx, nil, nil, wg)
		}
		wg.Wait()
		if len(urls)*len(paths) < 6 {
			time.Sleep(5 * time.Second)
		}
		cancel()
	}
	r.wg.Wait()
	r.Close()
	r.Cfg.ClearResume()
	endTime := time.Now()
	gologger.Info().Msgf("This task takes %v seconds", endTime.Sub(startTime).Seconds())
	return nil
}

func (r *Runner) GoHandler(target, path string, outputWriter *ucRunner.OutputWriter, ctx context.Context, paths []string, findTemp *map[string][]string, wg *sizedwaitgroup.SizedWaitGroup) {
	defer func() {
		wg.Done()
	}()
	if r.Cfg.Results.HasSkipped(path, target) {
		return
	}
	if r.Cfg.Results.HasPath(target, path) {
		return
	}

	mapResult, err := r.GoTargetPathByRetryable(target, path)
	if err != nil {
		gologger.Warning().Msgf("发生错误: %s", err)
		return
	}

	check := mapResult["check"].(bool)
	targetResult := mapResult["re"].(*result.TargetResult)
	if r.Cfg.Options.ResultBack != nil {
		r.Cfg.Options.ResultBack(targetResult)
		return
	}
	if targetResult != nil && err == nil {
		if r.Cfg.Results.HasSkipped(path, target) {
			return
		}
		if r.Cfg.Results.HasPath(target, path) {
			return
		}
		r.Cfg.Results.AddSkipped(target, path)
		// 跳过条件满足
		if check {
			return
		}

		// 这里得加锁
		if r.Cfg.Options.RecursiveRun {
			if _, ok := r.dirBack[targetResult.Path]; ok {
				key, _ := url.JoinPath(target, path)
				r.Cfg.Results.Lock()
				(*findTemp)[key] = paths
				r.Cfg.Results.Unlock()
			}
		}
		// 处理输出
		r.OutputHandler(target, path, mapResult, outputWriter)

		// 处理link 加锁
		if !r.Cfg.Options.RecursiveRun && r.Cfg.Options.FindOtherLink && mapResult["links"] != nil {
			link := mapResult["links"].([]string)
			go func() {
				for _, l := range link {
					select {
					case r.otherLinkChan <- l:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

	}
}

func (r *Runner) Close() {
	r.dialer.Close()
}
