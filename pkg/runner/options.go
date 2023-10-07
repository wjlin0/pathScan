package runner

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/wjlin0/pathScan/pkg/common/uncover"
	"github.com/wjlin0/pathScan/pkg/result"
	"os"
)

type Options struct {
	Url                       goflags.StringSlice         `json:"url"`
	UrlFile                   goflags.StringSlice         `json:"url-file"`
	UrlRemote                 string                      `json:"url-remote"`
	UrlChannel                bool                        `json:"url-channel"`
	Path                      goflags.StringSlice         `json:"path"`
	PathFile                  goflags.StringSlice         `json:"path-file"`
	PathRemote                string                      `json:"path-remote"`
	Subdomain                 bool                        `json:"subdomain"`
	ResumeCfg                 string                      `json:"resume-cfg"`
	Output                    string                      `json:"output"`
	RateLimit                 int                         `json:"rate-http"`
	Threads                   int                         `json:"thread"`
	Retries                   int                         `json:"retries"`
	Proxy                     string                      `json:"proxy"`
	ProxyAuth                 string                      `json:"proxy-auth"`
	NoColor                   bool                        `json:"no-color"`
	Verbose                   bool                        `json:"verbose"`
	Silent                    bool                        `json:"silent"`
	OnlyTargets               bool                        `json:"only-targets_"`
	SkipUrl                   goflags.StringSlice         `json:"skip-url"`
	SkipCode                  goflags.StringSlice         `json:"skip-code"`
	SkipHash                  string                      `json:"skip-hash"`
	SkipBodyLen               int                         `json:"skip-body-len"`
	SkipHashMethod            string                      `json:"skip-hash-method"`
	ErrUseLastResponse        bool                        `json:"err-use-last-response"`
	Csv                       bool                        `json:"csv,omitempty"`
	ClearResume               bool                        `json:"clear-resume"`
	Html                      bool                        `json:"html,omitempty"`
	Version                   bool                        `json:"version"`
	Uncover                   bool                        `json:"uncover"`
	UncoverQuery              goflags.StringSlice         `json:"uncover-query"`
	UncoverEngine             goflags.StringSlice         `json:"uncover-engine"`
	UncoverDelay              int                         `json:"uncover-delay"`
	UncoverLimit              int                         `json:"uncover-limit"`
	UncoverField              string                      `json:"uncover-field"`
	UncoverOutput             string                      `json:"uncover-output"`
	UpdatePathScanVersion     bool                        `json:"update"`
	UpdatePathDictVersion     bool                        `json:"update-path-dict-version"`
	UserAgent                 goflags.StringSlice         `json:"user-agent"`
	Cookie                    string                      `json:"cookie"`
	Authorization             string                      `json:"authorization"`
	Header                    goflags.StringSlice         `json:"header"`
	HeaderFile                goflags.StringSlice         `json:"header-file"`
	Timeout                   int                         `json:"timeout"`
	UpdateMatchVersion        bool                        `json:"update-match-version"`
	UpdateHTMLTemplateVersion bool                        `json:"update-html-template-version"`
	Method                    goflags.StringSlice         `json:"method"`
	MatchPath                 string                      `json:"match-path"`
	RecursiveRun              bool                        `json:"recursive-run"`
	RecursiveRunTimes         int                         `json:"recursive-run-times"`
	GetHash                   bool                        `json:"get-hash"`
	FindOtherDomainList       goflags.StringSlice         `json:"find-other-domain-list"`
	ResultBack                func(result *result.Result) `json:"-"`
	NotInit                   bool                        `json:"not-init"`
	Body                      string                      `json:"body"`
	FindOtherDomain           bool                        `json:"find-other-domain"`
	SkipAutoUpdateMatch       bool                        `json:"skip-auto-update-match"`
	SubdomainLimit            int                         `json:"subdomain-limit"`
	SubdomainQuery            goflags.StringSlice         `json:"subdomain-query"`
	SubdomainEngine           goflags.StringSlice         `json:"subdomain-engine"`
	SubdomainOutput           string                      `json:"subdomain-output"`
	Resolvers                 goflags.StringSlice         `json:"resolvers"`
	WaitTimeout               int                         `json:"wait-timeout"`
}

func ParserOptions() *Options {
	options := &Options{}
	set := goflags.NewFlagSet()
	set.SetDescription("pathScan Go 扫描、信息收集工具")
	set.CreateGroup("Input", "输入",
		set.StringSliceVarP(&options.Url, "url", "u", nil, "目标(以逗号分割)", goflags.NormalizedStringSliceOptions),
		set.StringSliceVar(&options.UrlFile, "list", nil, "从文件中,读取目标", goflags.FileNormalizedStringSliceOptions),
		set.StringVarP(&options.UrlRemote, "target-remote", "tr", "", "从远程加载目标"),
		set.BoolVarP(&options.UrlChannel, "target-channel", "tc", false, "从通道中加载目标"),
		set.StringVar(&options.ResumeCfg, "resume", "", "使用resume.cfg恢复扫描"),
		set.StringVarP(&options.MatchPath, "match-file", "mf", "", "指纹文件"),
	)
	set.CreateGroup("Recursive", "递归",
		set.BoolVarP(&options.RecursiveRun, "recursive", "r", false, "递归扫描"),
		set.IntVarP(&options.RecursiveRunTimes, "recursive-time", "rt", 3, "递归扫描深度"),
	)
	set.CreateGroup("Subdomain", "子域名收集",
		set.BoolVarP(&options.Subdomain, "sub", "s", false, "子域名收集"),
		set.StringSliceVarP(&options.SubdomainQuery, "sub-query", "sq", nil, "需要收集的域名", goflags.NormalizedStringSliceOptions),
		set.IntVarP(&options.SubdomainLimit, "sub-limit", "sl", 1000, "每个搜索引擎返回的至少不超过数"),
		set.StringVarP(&options.SubdomainOutput, "sub-output", "so", "", "子域名搜索结果保存 支持csv格式输出"),
		set.StringSliceVarP(&options.SubdomainEngine, "sub-engine", "se", uncover.AllAgents(), "子域名搜索引擎", goflags.NormalizedStringSliceOptions),
	)

	set.CreateGroup("Uncover", "引擎",
		set.BoolVarP(&options.Uncover, "uncover", "uc", false, "启用打开搜索引擎"),
		set.StringSliceVarP(&options.UncoverQuery, "uncover-query", "uq", nil, "搜索查询", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.UncoverEngine, "uncover-engine", "ue", nil, fmt.Sprintf("支持的引擎 %s (default quake,fofa)", uncover.UncoverAgents()), goflags.NormalizedStringSliceOptions),
		set.StringVarP(&options.UncoverField, "uncover-field", "uf", "host", "引擎返回字段 (ip,port,host)"),
		set.IntVarP(&options.UncoverLimit, "uncover-limit", "ul", 200, "发现要返回的结果"),
		set.StringVarP(&options.UncoverOutput, "uncover-output", "uo", "", "搜索引擎查询结果保存 支持csv格式输出"),
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
	set.CreateGroup("Output", "输出",
		set.StringVarP(&options.Output, "output", "o", "", "输出文件路径（可忽略）"),
		set.BoolVar(&options.Csv, "csv", false, "csv格式输出"),
		set.BoolVar(&options.Html, "html", false, "html格式输出"),
		set.BoolVar(&options.Silent, "silent", false, "简略输出"),
		set.BoolVarP(&options.NoColor, "no-color", "nc", false, "无颜色输出"),
		set.BoolVarP(&options.Verbose, "verbose", "vb", false, "详细输出模式"),
		set.BoolVarP(&options.Version, "version", "v", false, "输出版本"),
	)
	set.CreateGroup("Tool", "工具",
		set.BoolVar(&options.ClearResume, "clear", false, "清理历史任务"),
		set.BoolVarP(&options.GetHash, "get-hash", "gh", false, "计算hash"),
		set.StringVarP(&options.SkipHashMethod, "skip-hash-method", "shm", "sha256", "指定hash的方法（sha256,md5,sha1）"),
	)
	set.CreateGroup("Config", "配置",
		set.IntVarP(&options.Retries, "retries", "rs", 0, "重试"),
		set.StringVarP(&options.Proxy, "proxy", "p", "", "代理"),
		set.StringSliceVar(&options.Resolvers, "resolvers", nil, "自定义DNS列表( 文件或逗号隔开 )", goflags.NormalizedStringSliceOptions),
		set.StringVarP(&options.ProxyAuth, "proxy-auth", "pa", "", "代理认证，以冒号分割（username:password）"),
		set.BoolVarP(&options.OnlyTargets, "scan-target", "st", false, "只进行目标存活扫描"),
		set.BoolVarP(&options.ErrUseLastResponse, "not-new", "nn", false, "不允许重定向"),
		set.StringSliceVarP(&options.FindOtherDomainList, "scan-domain-list", "sdl", nil, "从响应中中发现其他URL", goflags.NormalizedStringSliceOptions),
		set.BoolVarP(&options.FindOtherDomain, "scan-domain", "sd", false, "从响应中发现其他域名"),
	)
	set.CreateGroup("Header", "请求头参数",
		set.StringSliceVarP(&options.Method, "method", "m", goflags.StringSlice{"GET"}, fmt.Sprintf("请求方法 %s", httputil.AllHTTPMethods()), goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.UserAgent, "user-agent", "ua", nil, "User-Agent", goflags.CommaSeparatedStringSliceOptions),
		set.StringVarP(&options.Cookie, "cookie", "c", "", "cookie"),
		set.StringVarP(&options.Authorization, "authorization", "auth", "", "Auth请求头"),
		set.StringSliceVar(&options.Header, "header", nil, "自定义请求头,以逗号隔开", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.HeaderFile, "header-file", "hf", nil, "从文件中加载自定义请求头", goflags.FileStringSliceOptions),
		set.StringVarP(&options.Body, "body", "b", "", "自定义请求体"),
	)
	set.CreateGroup("Rate", "速率",
		set.IntVarP(&options.Threads, "thread", "t", 50, "线程"),
		set.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "每秒允许的HTTP连接数"),
		set.IntVar(&options.Timeout, "timeout", 10, "超时时间"),
		set.IntVarP(&options.WaitTimeout, "wait-timeout", "wt", 3, "自定义任务结束前的等待,一般用于结束结束时间果断,导致无法发现更多目标"),
	)
	set.CreateGroup("Update", "更新",
		set.BoolVar(&options.UpdatePathScanVersion, "update", false, "更新版本"),
		set.BoolVarP(&options.UpdatePathDictVersion, "update-dict", "ud", false, "更新字典版本"),
		set.BoolVarP(&options.UpdateMatchVersion, "update-match", "um", false, "更新指纹识别库"),
		set.BoolVarP(&options.UpdateHTMLTemplateVersion, "update-html", "uh", false, "更新HTML模板文件"),
		set.BoolVarP(&options.SkipAutoUpdateMatch, "auto-match", "am", false, "跳过自动更新"),
	)
	_ = set.Parse()
	if !options.Silent {
		showBanner()
	}
	if options.Version {
		gologger.Print().Msgf("pathScan version: %s", Version)
		os.Exit(0)
	}
	if options.Method == nil {
		options.Method = goflags.StringSlice{"GET"}
	}

	return options
}

func (o *Options) configureOutput() {
	switch {
	case o.Verbose:
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	case o.Silent:
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	case o.NoColor:
		color.NoColor = true
	}
}
