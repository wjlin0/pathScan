package runner

import (
	"bytes"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/clistats"
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
	wg                *sizedwaitgroup.SizedWaitGroup
	Cfg               *ResumeCfg
	client            *http.Client
	limiter           *ratelimit.Limiter
	targetsBack       map[string][]string
	dirBack           map[string]struct{}
	targets           map[string]struct{}
	paths             map[string]struct{}
	headers           map[string]interface{}
	skipCode          map[string]struct{}
	stats             *clistats.Statistics
	regOptions        []*identification.Options
	retryable         *retryablehttp.Client
	outputOtherToFile bool // 发现其他链接时不输出other_link 到 outputOther 指定的文件中 增加可读性
	otherLinkChan     chan string
	pathContext       *context.Context
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
	if !run.Cfg.Options.NotInit {
		err = InitPathScan()
		if err != nil {
			gologger.Error().Msg(err.Error())
			return nil, err
		}
	}

	// 检查版本更新
	if !run.Cfg.Options.UpdatePathScanVersion && !run.Cfg.Options.Silent {
		err := CheckVersion()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}

	// 下载字典或更新版本
	if run.Cfg.Options.UpdatePathDictVersion || run.Cfg.Options.UpdatePathScanVersion || run.Cfg.Options.UpdateMatchVersion {
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
		return nil, nil
	}

	// 清除恢复文件夹
	if run.Cfg.Options.ClearResume {
		_ = os.RemoveAll(DefaultResumeFolderPath())
		gologger.Print().Msgf("清除成功：%s", DefaultResumeFolderPath())
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
	run.retryable = newRetryableClient(run.Cfg.Options, run.Cfg.Options.ErrUseLastResponse)
	run.limiter = ratelimit.New(context.Background(), uint(run.Cfg.Options.RateHttp), time.Duration(1)*time.Second)
	run.wg = new(sizedwaitgroup.SizedWaitGroup)
	*run.wg = sizedwaitgroup.New(run.Cfg.Options.RateHttp)
	run.targets = run.handlerGetTargets()
	run.paths = run.handlerGetTargetPath()
	run.headers = run.handlerHeader()
	if run.Cfg.Options.RecursiveRun {
		run.targetsBack = make(map[string][]string)
		// 读文件
		run.dirBack = make(map[string]struct{})
		c, err := fileutil.ReadFile(run.Cfg.Options.RecursiveRunFile)
		if err != nil {
			return nil, err
		}
		for dir := range c {
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
	var f *os.File
	outputWriter, _ := ucRunner.NewOutputWriter()
	if r.Cfg.Options.Output != "" && !r.Cfg.Options.Html {
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
	outputOtherWriter, _ := ucRunner.NewOutputWriter()
	if r.Cfg.Options.OutputOtherLik != "" {
		outputFolder := filepath.Dir(r.Cfg.Options.OutputOtherLik)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				return mkdirErr
			}
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
	if r.Cfg.Options.Html && r.Cfg.Options.Output != "" && !checkInitHtml(r.Cfg.Options.Output) {
		InitHtmlOutput(r.Cfg.Options.Output)

	}

	switch {
	// 流模式还没想好怎么做 有会的 帮帮忙 联系我 给你权限
	case r.Cfg.Options.RecursiveRun:
		// 递归扫描逻辑
		// 递归初始化path数组
		gologger.Info().Msgf("启动递归扫描，扫描深度 %d", r.Cfg.Options.RecursiveRunTimes)

		// 初始化输入的递归扫描的路径
		for _, t := range urls {
			r.targetsBack[t] = []string{}
			for _, p := range paths {
				r.targetsBack[t] = append(r.targetsBack[t], p)
			}
		}
		i := 1
		for {
			findTemp := new(map[string][]string)
			*findTemp = make(map[string][]string)
			for i := 1; i < Retries; i++ {
				for t, v := range r.targetsBack {
					for _, p := range v {
						r.wg.Add()
						go r.GoHandler(t, p, outputWriter, ctx, paths, findTemp, r.wg)
						// 这里得加锁
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
			r.targetsBack = *findTemp
			i += 1
		}

	default:
		wg := new(sizedwaitgroup.SizedWaitGroup)
		*wg = sizedwaitgroup.New(r.Cfg.Options.RateHttp)
		r.wg.Add()
		go r.GoOtherLink(outputOtherWriter, ctx, r.wg)
		out := result.Rand(urls, paths)

		for o := range out {
			wg.Add()
			go r.GoHandler(o[0], o[1], outputWriter, ctx, nil, nil, wg)
		}
		wg.Wait()
		time.Sleep(5)
		cancel()
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
	r.limiter.Take()
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
		link := mapResult["links"].([]string)

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
		if len(link) > 0 && !r.Cfg.Options.FindOtherLink && !r.Cfg.Options.RecursiveRun {
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
