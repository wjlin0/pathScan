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
	wg          sizedwaitgroup.SizedWaitGroup
	Cfg         *ResumeCfg
	client      *http.Client
	limiter     *ratelimit.Limiter
	targetsBack map[string][]string
	dirBack     map[string]struct{}
	targets     map[string]struct{}
	paths       map[string]struct{}
	headers     map[string]interface{}
	skipCode    map[string]struct{}
	stats       *clistats.Statistics
	regOptions  *identification.Options
	retryable   *retryablehttp.Client
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
	// 检查版本更新
	if !run.Cfg.Options.UpdatePathScanVersion && !run.Cfg.Options.Silent {
		err := CheckVersion()
		if err != nil {
			gologger.Error().Msgf(err.Error())
		}
	}

	// 下载字典或更新版本
	if run.Cfg.Options.UpdatePathDictVersion || run.Cfg.Options.UpdatePathScanVersion || run.Cfg.Options.UpdateMatchVersion {
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
		if run.Cfg.Options.UpdateMatchVersion {
			err := run.Cfg.Options.DownloadFile(defaultMatchConfigLocation, "https://github.com/wjlin0/pathScan/releases/download/v"+Version+"/match-config.yaml")
			if err != nil {
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
	run.wg = sizedwaitgroup.New(run.Cfg.Options.RateHttp)
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
	addPathsToSet(run.Cfg.Options.SkipCode, run.skipCode)
	// 加载正则匹配规则
	run.regOptions, err = identification.ParsesDefaultOptions(run.Cfg.Options.MatchPath)
	if err != nil {
		return nil, err
	}
	if run.regOptions.Version != "" {
		gologger.Info().Msgf("使用 pathScan匹配规则 %s", run.regOptions.Version)
	}

	// 如果启用了进度条，则创建统计信息引擎
	if run.Cfg.Options.EnableProgressBar {
		stats, err := clistats.New()
		if err != nil {
			gologger.Warning().Msgf("无法创建进度条引擎：%s\n", err)
		} else {
			run.stats = stats
		}
	}

	// 返回 Runner 实例和无误差
	return run, nil
}

func (r *Runner) Run() error {

	targets := r.targets
	pathUrls := r.paths
	Retries := r.Cfg.Options.Retries
	var err error

	if r.Cfg.Options.OnlyTargets {
		pathUrls = map[string]struct{}{"/": {}}
	}

	pathCount := uint64(len(pathUrls))
	targetCount := uint64(len(targets))
	Range := pathCount * targetCount

	gologger.Info().Msgf("存活目标总数 -> %d", targetCount)
	gologger.Info().Msgf("请求总数 -> %d", Range*uint64(Retries))
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
	switch {
	// 流模式还没想好怎么做 打算做递归路径扫描 有会的 帮帮忙 联系我 给你权限
	case r.Cfg.Options.RecursiveRun:
		// 递归扫描逻辑
		// 递归初始化path数组
		gologger.Info().Msgf("启动递归扫描，扫描深度 %d", r.Cfg.Options.RecursiveRunTimes)
		var pathArray []string
		for p := range pathUrls {
			pathArray = append(pathArray, p)
		}
		// 初始化输入的递归扫描的路径
		for t := range targets {
			r.targetsBack[t] = []string{}
			for p := range pathUrls {
				r.targetsBack[t] = append(r.targetsBack[t], p)
			}
		}
		i := 1
		for {
			findTemp := make(map[string][]string)
			for i := 1; i < Retries; i++ {
				for t, v := range r.targetsBack {
					for _, p := range v {
						r.wg.Add()
						go func(target, path string) {
							defer func() {
								if r.Cfg.Options.EnableProgressBar {
									r.stats.IncrementCounter("packets", 1)
								}
								r.wg.Done()
							}()
							if r.Cfg.Results.HasSkipped(target, path) {
								return
							}
							if r.Cfg.Results.HasPath(target, path) {
								return
							}
							r.limiter.Take()
							targetResult, check, err := r.GoTargetPathByRetryable(target, path)
							if targetResult != nil && err == nil {
								r.Cfg.Results.AddSkipped(targetResult.Path, targetResult.Target)
								// 跳过条件满足
								if check {
									return
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
								// 这里得加锁
								if _, ok := r.dirBack[targetResult.Path]; ok {
									key, _ := url.JoinPath(target, path)
									r.Cfg.Results.Lock()
									findTemp[key] = pathArray
									r.Cfg.Results.Unlock()
								}
							}
						}(t, p)

					}
				}
			}

			r.wg.Wait()
			if len(findTemp) == 0 {
				break
			}
			if i >= r.Cfg.Options.RecursiveRunTimes {
				break
			}
			r.targetsBack = findTemp
			i += 1
		}

	default:
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
					targetResult, check, err := r.GoTargetPathByRetryable(target, path)
					if targetResult != nil && err == nil {
						r.Cfg.Results.AddSkipped(targetResult.Path, targetResult.Target)
						// 跳过条件满足
						if check {
							return
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
		r.wg.Wait()
	}

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
