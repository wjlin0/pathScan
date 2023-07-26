package runner

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/wjlin0/pathScan/pkg/common/uncover"
	"github.com/wjlin0/pathScan/pkg/result"
	"os"
	"time"
)

type Options struct {
	Url                   goflags.StringSlice               `json:"url"`
	UrlFile               goflags.StringSlice               `json:"url_file"`
	UrlRemote             string                            `json:"url_remote"`
	UrlChannel            bool                              `json:"url_channel"`
	Path                  goflags.StringSlice               `json:"path"`
	PathFile              goflags.StringSlice               `json:"path_file"`
	PathRemote            string                            `json:"path_remote"`
	ResumeCfg             string                            `json:"resume_cfg"`
	Output                string                            `json:"output"`
	RateHttp              int                               `json:"rate_http"`
	Retries               int                               `json:"retries"`
	Proxy                 string                            `json:"proxy"`
	ProxyAuth             string                            `json:"proxy_auth"`
	NoColor               bool                              `json:"no_color"`
	Verbose               bool                              `json:"verbose"`
	Silent                bool                              `json:"silent"`
	OnlyTargets           bool                              `json:"only_targets"`
	SkipUrl               goflags.StringSlice               `json:"skip_url"`
	SkipCode              goflags.StringSlice               `json:"skip_code"`
	SkipHash              string                            `json:"skip_hash"`
	SkipBodyLen           int                               `json:"skip_body_len"`
	SkipHashMethod        string                            `json:"skip_hash_method"`
	ErrUseLastResponse    bool                              `json:"err_use_last_response"`
	Csv                   bool                              `json:"csv,omitempty"`
	ClearResume           bool                              `json:"clear_resume"`
	Html                  bool                              `json:"html,omitempty"`
	Version               bool                              `json:"version"`
	Uncover               bool                              `json:"uncover"`
	UncoverQuery          goflags.StringSlice               `json:"uncover_query"`
	UncoverEngine         goflags.StringSlice               `json:"uncover_engine"`
	UncoverDelay          int                               `json:"uncover_delay"`
	UncoverLimit          int                               `json:"uncover_limit"`
	UncoverField          string                            `json:"uncover_field"`
	UncoverOutput         string                            `json:"uncover_output"`
	UpdatePathScanVersion bool                              `json:"update"`
	UpdatePathDictVersion bool                              `json:"update_path_dict_version"`
	UserAgent             goflags.StringSlice               `json:"user_agent"`
	Cookie                string                            `json:"cookie"`
	Authorization         string                            `json:"authorization"`
	Header                goflags.StringSlice               `json:"header"`
	HeaderFile            goflags.StringSlice               `json:"header_file"`
	TimeoutHttp           time.Duration                     `json:"timeout_http"`
	UpdateMatchVersion    bool                              `json:"update_match_version"`
	Method                string                            `json:"method"`
	MatchPath             string                            `json:"match_path"`
	RecursiveRun          bool                              `json:"recursive_run"`
	RecursiveRunTimes     int                               `json:"recursive_run_times"`
	RecursiveRunFile      string                            `json:"recursive_run_file"`
	GetHash               bool                              `json:"get_hash"`
	FindOtherLink         bool                              `json:"find_other_link"`
	OutputOtherLik        string                            `json:"output_other_lik"`
	ResultBack            func(result *result.TargetResult) `json:"-"`
	NotInit               bool                              `json:"not_init"`
	Body                  string                            `json:"body"`
	FindOtherDomain       bool                              `json:"find_other_domain"`
}

func ParserOptions() *Options {
	options := &Options{}
	set := goflags.NewFlagSet()
	set.SetDescription("PathScan Go 扫描、信息收集工具")
	set.CreateGroup("Input", "输入",
		set.StringSliceVarP(&options.Url, "target", "t", nil, "目标(以逗号分割)", goflags.NormalizedStringSliceOptions),
		set.StringSliceVarP(&options.UrlFile, "target-file", "tf", nil, "从文件中,读取目标", goflags.FileNormalizedStringSliceOptions),
		set.StringVarP(&options.UrlRemote, "target-remote", "tr", "", "从远程加载目标"),
		set.BoolVarP(&options.UrlChannel, "target-channel", "tc", false, "从通道中加载目标"),
		set.StringVar(&options.ResumeCfg, "resume", "", "使用resume.cfg恢复扫描"),
		set.StringVarP(&options.MatchPath, "match-file", "mf", "", "指纹文件"),
	)
	set.CreateGroup("recursive", "递归",
		set.BoolVarP(&options.RecursiveRun, "recursive", "r", false, "递归扫描"),
		set.IntVarP(&options.RecursiveRunTimes, "recursive-time", "rt", 3, "递归扫描深度"),
		set.StringVarP(&options.RecursiveRunFile, "recursive-file", "rf", defaultRecursiveRunFile, "递归扫描目录"),
	)
	set.CreateGroup("Skip", "跳过",
		set.StringSliceVarP(&options.SkipUrl, "skip-url", "su", nil, "跳过的目标(以逗号分割)", goflags.NormalizedStringSliceOptions),
		set.StringSliceVarP(&options.SkipCode, "skip-code", "sc", nil, "跳过状态码", goflags.NormalizedStringSliceOptions),
		set.StringVarP(&options.SkipHash, "skip-hash", "sh", "", "跳过指定hash"),
		set.IntVarP(&options.SkipBodyLen, "skip-body-len", "sbl", -1, "跳过body固定长度"),
	)
	set.CreateGroup("Dict", "扫描字典",
		set.StringSliceVarP(&options.Path, "path", "ps", nil, "路径(以逗号分割)", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.PathFile, "path-file", "pf", nil, "从文件中,读取路径", goflags.FileStringSliceOptions),
		set.StringVarP(&options.PathRemote, "path-remote", "pr", "", "从远程加载字典"),
	)
	set.CreateGroup("output", "输出",
		set.StringVarP(&options.Output, "output", "o", "", "输出文件路径（可忽略）"),
		set.StringVarP(&options.OutputOtherLik, "output-other", "oo", "", "请请求中发现其他URL输出文件路径（默认与output一致）"),
		set.BoolVar(&options.Csv, "csv", false, "csv格式输出"),
		set.BoolVar(&options.Html, "html", false, "html格式输出"),
		set.BoolVarP(&options.NoColor, "no-color", "nc", false, "无颜色输出"),
		set.BoolVarP(&options.Verbose, "verbose", "vb", false, "详细输出模式"),
		set.BoolVarP(&options.Silent, "silent", "sl", false, "管道模式"),
		set.BoolVarP(&options.Version, "version", "v", false, "输出版本"),
	)
	set.CreateGroup("tool", "工具",
		set.BoolVar(&options.ClearResume, "clear", false, "清理历史任务"),
		set.BoolVarP(&options.GetHash, "get-hash", "gh", false, "计算hash"),
		set.StringVarP(&options.SkipHashMethod, "skip-hash-method", "shm", "sha256", "指定hash的方法（sha256,md5,sha1）"),
	)
	set.CreateGroup("config", "配置",
		set.IntVarP(&options.Retries, "retries", "rs", 3, "重试3次"),
		set.StringVarP(&options.Proxy, "proxy", "p", "", "代理"),
		set.BoolVarP(&options.NotInit, "not-init", "ni", false, "跳过初始化"),
		set.StringVarP(&options.ProxyAuth, "proxy-auth", "pa", "", "代理认证，以冒号分割（username:password）"),
		set.BoolVarP(&options.OnlyTargets, "scan-target", "st", false, "只进行目标存活扫描"),
		set.BoolVarP(&options.ErrUseLastResponse, "not-new", "nn", false, "不允许重定向"),
		set.BoolVarP(&options.FindOtherLink, "scan-other", "so", false, "从响应中中发现其他URL"),
		set.BoolVarP(&options.FindOtherDomain, "scan-domain", "sd", false, "从响应中发现其他域名"),
	)
	set.CreateGroup("uncover", "引擎",
		set.BoolVarP(&options.Uncover, "uncover", "uc", false, "启用打开搜索引擎"),
		set.StringSliceVarP(&options.UncoverQuery, "uncover-query", "uq", nil, "搜索查询", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.UncoverEngine, "uncover-engine", "ue", nil, fmt.Sprintf("支持的引擎 (%s) (default quake,fofa)", uncover.GetUncoverSupportedAgents()), goflags.NormalizedStringSliceOptions),
		set.StringVarP(&options.UncoverField, "uncover-field", "uf", "host", "引擎返回字段 (ip,port,host)"),
		set.IntVarP(&options.UncoverLimit, "uncover-limit", "ul", 200, "发现要返回的结果"),
		set.IntVarP(&options.UncoverDelay, "uncover-delay", "ucd", 1, "打开查询请求之间的延迟（秒）"),
		set.StringVarP(&options.UncoverOutput, "uncover-output", "uo", "", "搜索引擎查询结果保存"),
	)
	set.CreateGroup("header", "请求头参数",
		set.StringVarP(&options.Method, "method", "m", "GET", "请求方法（GET、POST、PUT、OPTIONS、HEAD、CONNECT）"),
		set.StringSliceVarP(&options.UserAgent, "user-agent", "ua", nil, "User-Agent", goflags.CommaSeparatedStringSliceOptions),
		set.StringVarP(&options.Cookie, "cookie", "c", "", "cookie"),
		set.StringVarP(&options.Authorization, "authorization", "auth", "", "Auth请求头"),
		set.StringSliceVar(&options.Header, "header", nil, "自定义请求头,以逗号隔开", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.HeaderFile, "header-file", "hf", nil, "从文件中加载自定义请求头", goflags.FileStringSliceOptions),
		set.StringVarP(&options.Body, "body", "b", "", "自定义请求体"),
	)
	set.CreateGroup("rate", "速率",
		set.IntVarP(&options.RateHttp, "rate-http", "rh", 50, "允许每秒钟最大http请求数"),
		set.DurationVarP(&options.TimeoutHttp, "timeout-http", "th", 5*time.Second, "Http连接超时"),
	)
	set.CreateGroup("update", "更新",
		set.BoolVar(&options.UpdatePathScanVersion, "update", false, "更新版本"),
		set.BoolVarP(&options.UpdatePathDictVersion, "update-dict", "ud", false, "更新字典版本"),
		set.BoolVarP(&options.UpdateMatchVersion, "update-match", "um", false, "更新指纹识别库"),
	)
	_ = set.Parse()
	if !options.Silent {
		showBanner()
	}
	if options.Version {
		gologger.Print().Msgf("pathScan version: %s", Version)
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
