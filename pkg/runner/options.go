package runner

import (
	"github.com/fatih/color"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"os"
)

type Options struct {
	Url                goflags.StringSlice `json:"url,omitempty"`
	UrlFile            goflags.StringSlice `json:"url_file,omitempty"`
	UrlRemote          string              `json:"url_remote,omitempty"`
	Path               goflags.StringSlice `json:"path,omitempty"`
	PathFile           goflags.StringSlice `json:"path_file,omitempty"`
	PathRemote         string              `json:"path_remote,omitempty"`
	ResumeCfg          string              `json:"resume_cfg,omitempty"`
	Output             string              `json:"output,omitempty"`
	Rate               int                 `json:"rate,omitempty"`
	RateHttp           int                 `json:"rate_http,omitempty"`
	Retries            int                 `json:"retries,omitempty"`
	Proxy              string              `json:"proxy,omitempty"`
	ProxyAuth          string              `json:"proxy_auth,omitempty"`
	NoColor            bool                `json:"no_color"`
	Verbose            bool                `json:"verbose"`
	Silent             bool                `json:"silent"`
	OnlyTargets        bool                `json:"only_targets"`
	EnableProgressBar  bool                `json:"enable_progress_bar"`
	Skip404And302      bool                `json:"skip_404_and_302"`
	ErrUseLastResponse bool                `json:"err_use_last_response,omitempty"`
	Csv                bool                `json:"csv,omitempty"`
	ClearResume        bool                `json:"clear_resume,omitempty"`
}

func ParserOptions() *Options {
	options := &Options{}
	set := goflags.NewFlagSet()
	set.SetDescription("PathScan Go 扫描工具")
	set.CreateGroup("Input", "输入",
		set.StringSliceVarP(&options.Url, "url", "u", nil, "目标(以逗号分割)", goflags.NormalizedStringSliceOptions),
		set.StringSliceVarP(&options.UrlFile, "url-file", "uf", nil, "从文件中,读取目标", goflags.FileStringSliceOptions),
		set.StringVarP(&options.UrlRemote, "url-remote", "ur", "", "从远程加载目标"),
		set.StringVar(&options.ResumeCfg, "resume", "", "使用resume.cfg恢复扫描"),
	)
	set.CreateGroup("Dict", "扫描字典",
		set.StringSliceVarP(&options.Path, "path", "ps", nil, "路径(以逗号分割)", goflags.NormalizedStringSliceOptions),
		set.StringSliceVarP(&options.PathFile, "path-file", "pf", nil, "从文件中,读取路径", goflags.FileStringSliceOptions),
		set.StringVarP(&options.PathRemote, "path-remote", "pr", "", "从远程加载字典"),
	)
	set.CreateGroup("output", "输出",
		set.StringVarP(&options.Output, "output", "o", "", "输出文件路径（可忽略）"),
		set.BoolVarP(&options.Csv, "csv", "c", false, "csv格式输出"),
		set.BoolVarP(&options.NoColor, "no-color", "nc", false, "无颜色输出"),
		set.BoolVarP(&options.Verbose, "verbose", "vb", false, "详细输出模式"),
		set.BoolVarP(&options.Silent, "silent", "sl", false, "只输出状态码为200"),
		set.BoolVarP(&options.EnableProgressBar, "progressbar", "pb", false, "启用进度条"),
		set.BoolVar(&options.Skip404And302, "skip", false, "跳过404、302输出默认跳过"),
	)
	set.CreateGroup("config", "配置",
		set.IntVarP(&options.Retries, "retries", "rs", 3, "重试3次"),
		set.StringVarP(&options.Proxy, "proxy", "p", "", "代理"),
		set.StringVarP(&options.ProxyAuth, "proxy-auth", "pa", "", "代理认证，以冒号分割（username:password）"),
		set.BoolVarP(&options.OnlyTargets, "scan-target", "st", false, "只进行目标存活扫描"),
		set.BoolVarP(&options.ErrUseLastResponse, "not-new", "nn", false, "不允许HTTP最新请求"),
	)
	set.CreateGroup("rate", "速率",
		set.IntVarP(&options.Rate, "rate-limit", "rl", 30, "线程"),
		set.IntVarP(&options.RateHttp, "rate-http", "rh", 100, "允许每秒钟最大http请求数"),
	)
	set.CreateGroup("clear", "清理",
		set.BoolVar(&options.ClearResume, "clear", false, "清理历史任务"),
	)
	_ = set.Parse()
	if options.ClearResume {
		_ = os.RemoveAll(DefaultResumeFolderPath())

		os.Exit(0)
	}

	return options
}

func (o *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if o.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
		color.NoColor = true
	}
	if o.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if o.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
