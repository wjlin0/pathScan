package runner

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	fileutil "github.com/projectdiscovery/utils/file"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/wjlin0/pathScan/pkg/common/identification"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"github.com/wjlin0/uncover"
	"os"
	"path/filepath"
	"regexp"
)

type Options struct {
	Url                         goflags.StringSlice         `json:"url"`
	UrlFile                     goflags.StringSlice         `json:"url-file"`
	UrlRemote                   string                      `json:"url-remote"`
	UrlChannel                  bool                        `json:"url-channel"`
	Path                        goflags.StringSlice         `json:"path"`
	PathFile                    goflags.StringSlice         `json:"path-file"`
	PathRemote                  string                      `json:"path-remote"`
	Subdomain                   bool                        `json:"subdomain"`
	ResumeCfg                   string                      `json:"resume-cfg"`
	Output                      string                      `json:"output"`
	RateLimit                   int                         `json:"rate-http"`
	Threads                     int                         `json:"thread"`
	Retries                     int                         `json:"retries"`
	Proxy                       string                      `json:"proxy"`
	ProxyAuth                   string                      `json:"proxy-auth"`
	NoColor                     bool                        `json:"no-color"`
	Verbose                     bool                        `json:"verbose"`
	Silent                      bool                        `json:"silent"`
	OnlyTargets                 bool                        `json:"only-targets_"`
	SkipUrl                     goflags.StringSlice         `json:"skip-url"`
	SkipCode                    goflags.StringSlice         `json:"skip-code"`
	SkipHash                    string                      `json:"skip-hash"`
	SkipBodyLen                 goflags.StringSlice         `json:"skip-body-len"`
	SkipHashMethod              string                      `json:"skip-hash-method"`
	ErrUseLastResponse          bool                        `json:"err-use-last-response"`
	Csv                         bool                        `json:"csv,omitempty"`
	ClearResume                 bool                        `json:"clear-resume"`
	Html                        bool                        `json:"html,omitempty"`
	Version                     bool                        `json:"version"`
	Uncover                     bool                        `json:"uncover"`
	UncoverQuery                goflags.StringSlice         `json:"uncover-query"`
	UncoverEngine               goflags.StringSlice         `json:"uncover-engine"`
	UncoverDelay                int                         `json:"uncover-delay"`
	UncoverLimit                int                         `json:"uncover-limit"`
	UncoverField                string                      `json:"uncover-field"`
	UncoverOutput               string                      `json:"uncover-output"`
	UpdatePathScanVersion       bool                        `json:"update"`
	UserAgent                   goflags.StringSlice         `json:"user-agent"`
	Cookie                      string                      `json:"cookie"`
	Authorization               string                      `json:"authorization"`
	Header                      goflags.StringSlice         `json:"header"`
	HeaderFile                  goflags.StringSlice         `json:"header-file"`
	Timeout                     int                         `json:"timeout"`
	UpdateMatchVersion          bool                        `json:"update-match-version"`
	Method                      goflags.StringSlice         `json:"method"`
	MatchPath                   string                      `json:"match-path"`
	RecursiveRun                bool                        `json:"recursive-run"`
	RecursiveRunTimes           int                         `json:"recursive-run-times"`
	GetHash                     bool                        `json:"get-hash"`
	FindOtherDomainList         goflags.StringSlice         `json:"find-other-domain-list"`
	ResultBack                  func(result *result.Result) `json:"-"`
	NotInit                     bool                        `json:"not-init"`
	Body                        string                      `json:"body"`
	FindOtherDomain             bool                        `json:"find-other-domain"`
	SkipAutoUpdateMatch         bool                        `json:"skip-auto-update-match"`
	SubdomainLimit              int                         `json:"subdomain-limit"`
	SubdomainQuery              goflags.StringSlice         `json:"subdomain-query"`
	SubdomainEngine             goflags.StringSlice         `json:"subdomain-engine"`
	SubdomainOutput             string                      `json:"subdomain-output"`
	Resolvers                   goflags.StringSlice         `json:"resolvers"`
	WaitTimeout                 int                         `json:"wait-timeout"`
	ProxyServerAllowHosts       goflags.StringSlice         `json:"proxy-server-allow-hosts"`
	ProxyServerCaPath           string                      `json:"proxy-server-ca-path"`
	ProxyServerStremLargeBodies int64                       `json:"proxy-server-strem-large-bodies"`
	ProxyServerAddr             string                      `json:"proxy-server-addr"`
	API                         bool                        `json:"api"`
	Favicon                     bool                        `json:"favicon"`
	SkipBodyRegex               goflags.StringSlice         `json:"skip-body-regex"`
	skipBodyRegex               []*regexp.Regexp
	LoadDefaultDict             bool   `json:"load-default-dict"`
	LoadAPIDict                 bool   `json:"load-api-dict"`
	Naabu                       bool   `json:"naabu"`
	Ports                       string `json:"ports"`
	TopPorts                    string `json:"top-ports"`
	SkipHostDiscovery           bool   `json:"skip-host-discovery"`
	NaabuOutput                 string `json:"naabu-output"`
	NaabuRate                   int    `json:"naabu-rate"`
	NaabuScanType               string `json:"naabu-scan-type"`
	NaabuSourceIP               string `json:"naabu-source-ip"`
	NaabuSourcePort             string `json:"naabu-source-port"`
	NaabuHostDiscovery          bool   `json:"naabu-host-discovery"`
	NaabuExcludeCdn             bool   `json:"naabu-exclude-cdn"`
	Debug                       bool   `json:"debug"`
	Validate                    bool   `json:"validate"`
}

func ParserOptions() *Options {
	options := &Options{}
	set := goflags.NewFlagSet()
	set.SetDescription(fmt.Sprintf("pathScan %s Go 扫描、信息收集工具 ", Version))
	set.CreateGroup("Input", "输入",
		set.StringSliceVarP(&options.Url, "url", "u", nil, "目标(以逗号分割)", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVar(&options.UrlFile, "list", nil, "从文件中,读取目标", goflags.FileCommaSeparatedStringSliceOptions),
		set.StringVarP(&options.UrlRemote, "target-remote", "tr", "", "从远程加载目标"),
		set.BoolVarP(&options.UrlChannel, "target-channel", "tc", false, "从通道中加载目标"),
		set.StringVar(&options.ResumeCfg, "resume", "", "使用resume.cfg恢复扫描"),
		set.StringVarP(&options.MatchPath, "match-file", "mf", "", "指纹文件目录或文件"),
	)
	set.CreateGroup("Recursive", "递归",
		set.BoolVarP(&options.RecursiveRun, "recursive", "r", false, "递归扫描"),
		set.IntVarP(&options.RecursiveRunTimes, "recursive-time", "rt", 3, "递归扫描深度"),
	)
	set.CreateGroup("Subdomain", "子域名收集",
		set.BoolVarP(&options.Subdomain, "sub", "s", false, "子域名收集"),
		set.StringSliceVarP(&options.SubdomainQuery, "sub-query", "sq", nil, "需要收集的域名 (支持从文件中录入 -sq /tmp/sub-query.txt)", goflags.FileStringSliceOptions),
		set.IntVarP(&options.SubdomainLimit, "sub-limit", "sl", 1000, "每个搜索引擎返回的至少不超过数"),
		set.StringVarP(&options.SubdomainOutput, "sub-output", "so", "", "子域名搜索结果保存 支持csv格式输出"),
		set.StringSliceVarP(&options.SubdomainEngine, "sub-engine", "se", nil, fmt.Sprintf("子域名搜索引擎 %s (default all)", uncover.AllAgents()), goflags.NormalizedStringSliceOptions),
	)
	set.CreateGroup("api", "被动发现",
		set.BoolVarP(&options.API, "api", "a", false, "被动发现"),
		set.StringVarP(&options.ProxyServerAddr, "api-server", "as", ":8081", "中间人劫持代理端口"),
		set.StringVarP(&options.ProxyServerCaPath, "api-ca-path", "ac", "", "中间人劫持证书路径"),
		set.StringSliceVarP(&options.ProxyServerAllowHosts, "api-allow-hosts", "ah", []string{"*"}, "允许的hosts (支持从文件中录入 -ah /tmp/allow-hosts.txt 支持 *.wjlin0.com 写法)", goflags.FileNormalizedStringSliceOptions),
	)
	set.CreateGroup("Uncover", "引擎",
		set.BoolVarP(&options.Uncover, "uncover", "uc", false, "启用打开搜索引擎"),
		set.StringSliceVarP(&options.UncoverQuery, "uncover-query", "uq", nil, "搜索查询", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.UncoverEngine, "uncover-engine", "ue", nil, fmt.Sprintf("支持的引擎 %s (default fofa)", uncover.UncoverAgents()), goflags.NormalizedStringSliceOptions),
		set.StringVarP(&options.UncoverField, "uncover-field", "uf", "host", "引擎返回字段 (ip,port,host)"),
		set.IntVarP(&options.UncoverLimit, "uncover-limit", "ul", 200, "发现要返回的结果"),
		set.StringVarP(&options.UncoverOutput, "uncover-output", "uo", "", "搜索引擎查询结果保存 支持csv格式输出"),
	)
	set.CreateGroup("Skip", "跳过",
		set.StringSliceVarP(&options.SkipUrl, "skip-url", "su", nil, "跳过的目标(以逗号分割,支持从文件读取 -su /tmp/skip-url.txt)", goflags.FileStringSliceOptions),
		set.StringSliceVarP(&options.SkipCode, "skip-code", "sc", nil, "跳过状态码(以逗号分割,支持从文件读取 -sc /tmp/skip-code.txt, 支持 5xx、300-399 )", goflags.FileNormalizedStringSliceOptions),
		set.StringVarP(&options.SkipHash, "skip-hash", "sh", "", "跳过指定hash"),
		set.StringSliceVarP(&options.SkipBodyLen, "skip-body-len", "sbl", nil, "跳过body固定长度(支持 100-200,即长度为100~200之间的均跳过,支持 从文件中读取 -sbl /tmp/skip-body-len.txt)", goflags.FileNormalizedStringSliceOptions),
		set.StringSliceVarP(&options.SkipBodyRegex, "skip-body-regex", "sbr", nil, "跳过body正则匹配(以逗号分割,支持从文件读取 -sbr /tmp/skip-regex.txt)", goflags.FileCommaSeparatedStringSliceOptions),
	)
	set.CreateGroup("Dict", "扫描字典",
		set.StringSliceVarP(&options.Path, "path", "ps", nil, "路径(以逗号分割)", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.PathFile, "path-file", "pf", nil, "从文件中,读取路径", goflags.FileStringSliceOptions),
		set.StringVarP(&options.PathRemote, "path-remote", "pr", "", "从远程加载字典"),
		set.BoolVarP(&options.LoadDefaultDict, "load-default-dict", "ldd", false, "目标超过一个时，是否加载默认字典"),
		set.BoolVarP(&options.LoadAPIDict, "load-api-dict", "lad", false, "是否加载api字典"),
	)
	set.CreateGroup("Output", "输出",
		set.StringVarP(&options.Output, "output", "o", "", "输出文件路径（可忽略）"),
		set.BoolVar(&options.Csv, "csv", false, "csv格式输出"),
		set.BoolVar(&options.Html, "html", false, "html格式输出"),
		set.BoolVar(&options.Silent, "silent", false, "简略输出"),
		set.BoolVarP(&options.NoColor, "no-color", "nc", false, "无颜色输出"),
		set.BoolVarP(&options.Verbose, "verbose", "vb", false, "详细输出模式"),
		set.BoolVar(&options.Debug, "debug", false, "调试输出"),
		set.BoolVarP(&options.Version, "version", "v", false, "输出版本"),
	)
	set.CreateGroup("Naabu", "端口扫描",
		set.BoolVarP(&options.Naabu, "naabu", "n", false, "端口扫描"),
		set.StringVar(&options.Ports, "port", "", "端口(80,443, 100-200)"),
		set.StringVarP(&options.TopPorts, "top-ports", "tp", "", "top端口(100,200,300)"),
		set.StringVarP(&options.NaabuScanType, "naabu-scan-type", "ns", "s", "端口扫描类型(SYN/CONNECT)"),
		set.BoolVarP(&options.NaabuHostDiscovery, "naabu-host-discovery", "sn", false, "只允许主机发现"),
		set.BoolVarP(&options.SkipHostDiscovery, "skip-host-discovery", "Pn", false, "跳过主机发现"),
		set.StringVarP(&options.NaabuOutput, "naabu-output", "no", "", "端口扫描结果保存 支持csv格式输出"),
		set.StringVarP(&options.NaabuSourceIP, "naabu-source-ip", "nsi", "", "端口扫描源IP"),
		set.StringVarP(&options.NaabuSourcePort, "naabu-source-port", "nsp", "", "端口扫描源端口"),
		set.BoolVarP(&options.NaabuExcludeCdn, "naabu-exclude-cdn", "ne", false, "端口扫描排除cdn"),
	)

	set.CreateGroup("Tool", "工具",
		set.BoolVar(&options.ClearResume, "clear", false, "清理历史任务"),
		set.BoolVarP(&options.GetHash, "get-hash", "gh", false, "计算hash"),
		set.StringVarP(&options.SkipHashMethod, "skip-hash-method", "shm", "sha256", "指定hash的方法（sha256,md5,sha1）"),
	)
	set.CreateGroup("Config", "配置",
		set.IntVarP(&options.Retries, "retries", "rs", 0, "重试"),
		set.StringVarP(&options.Proxy, "proxy", "p", "", "代理"),
		set.BoolVarP(&options.Favicon, "favicon", "f", false, "自动识别favicon"),
		set.StringSliceVar(&options.Resolvers, "resolvers", nil, "自定义DNS列表( 文件或逗号隔开 )", goflags.FileNormalizedStringSliceOptions),
		set.StringVarP(&options.ProxyAuth, "proxy-auth", "pa", "", "代理认证，以冒号分割（username:password）"),
		set.BoolVarP(&options.OnlyTargets, "scan-target", "st", false, "只进行目标存活扫描"),
		set.BoolVarP(&options.ErrUseLastResponse, "not-new", "nn", false, "允许重定向"),
		set.StringSliceVarP(&options.FindOtherDomainList, "scan-domain-list", "sdl", nil, "从响应中中发现其他域名（逗号隔开，支持文件读取 -sdl /tmp/otherDomain.txt）", goflags.FileNormalizedOriginalStringSliceOptions),
		set.BoolVar(&options.Validate, "validate", false, "验证指纹文件"),
		set.BoolVarP(&options.FindOtherDomain, "scan-domain", "sd", false, "从响应中发现其他域名"),
	)
	set.CreateGroup("Header", "请求头参数",
		set.StringSliceVarP(&options.Method, "method", "m", goflags.StringSlice{"GET"}, fmt.Sprintf("请求方法 %s", httputil.AllHTTPMethods()), goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.UserAgent, "user-agent", "ua", nil, "User-Agent (支持从文件中录入 -ua /tmp/user-agent.txt)", goflags.FileCommaSeparatedStringSliceOptions),
		set.StringVarP(&options.Cookie, "cookie", "c", "", "cookie"),
		set.StringVarP(&options.Authorization, "authorization", "auth", "", "Auth请求头"),
		set.StringSliceVar(&options.Header, "header", nil, "自定义请求头,以逗号隔开 (支持从文件中录入 -header /tmp/header.txt)", goflags.FileCommaSeparatedStringSliceOptions),
		set.StringVarP(&options.Body, "body", "b", "", "自定义请求体"),
	)
	set.CreateGroup("Rate", "速率",
		set.IntVarP(&options.Threads, "thread", "t", 30, "线程"),
		set.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "每秒允许的HTTP连接数"),
		set.IntVarP(&options.NaabuRate, "naabu-rate", "nr", 1000, "端口扫描速率"),
		set.IntVar(&options.Timeout, "timeout", 10, "超时时间"),
		set.IntVarP(&options.WaitTimeout, "wait-timeout", "wt", 3, "自定义任务结束前的等待,一般用于结束结束时间果断,导致无法发现更多目标"),
	)
	set.CreateGroup("Update", "更新",
		set.BoolVar(&options.UpdatePathScanVersion, "update", false, "更新版本"),
		set.BoolVarP(&options.UpdateMatchVersion, "update-match", "um", false, "更新指纹识别库"),
		set.BoolVarP(&options.SkipAutoUpdateMatch, "auto-match", "am", false, "跳过自动检查更新"),
	)
	set.SetCustomHelpText(`EXAMPLES:

运行 pathScan 扫描路径, 指定单个目标 跳过404输出:
    $ pathScan -u https://example.com/ -sc 404

运行 pathScan 递归扫描 指定单个目标:
    $ pathScan -r -u https://example.com/ -sc 404 

运行 pathScan 搜索引擎 并指定多个路径:
    $ pathScan -uc -ue fofa -uq 'app="tomcat"' -pf "/,/api/v1/user"

运行 pathScan 收集子域名 指定输出:
    $ pathScan -s -sq 'example.com' -csv -o out.csv

运行 pathScan 端口扫描 并指定前1000个端口:
    $ pathScan -u example.com -n -csv -o out.csv -tp 1000

运行 pathScan 收集子域名 并端口扫描:
    $ pathScan -s -sq 'example.com' -n -port 80,443,8080 -csv -o out.csv 

其他文档可在以下网址获得: https://github.com/wjlin0/pathScan/
`)
	// 判断 defaultPathScanDir 是否存在 若不存在则创建目录
	if _, err := os.Stat(defaultPathScanDir); os.IsNotExist(err) {
		_ = os.Mkdir(defaultPathScanDir, os.ModePerm)
	}
	set.SetConfigFilePath(filepath.Join(defaultPathScanConfig, "config.yaml"))
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

	if o.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	if o.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if o.Verbose || o.Validate {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if o.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(o.NoColor))
		color.NoColor = true
		//_ = os.Setenv("NO_COLOR", "true")
	}
}

func (o *Options) ValidateMatch() error {
	var (
		err       error
		matchPath string
		extension []string
		matchOpt  identification.Options
	)
	matchPath = defaultMatchDir
	if o.MatchPath != "" {
		matchPath = o.MatchPath
	}
	if extension, err = util.ListFilesWithExtension(matchPath, ".yaml"); err != nil {
		return err
	}
	if len(extension) == 0 {
		return fmt.Errorf("no match file found in %s", matchPath)
	}
	for _, ext := range extension {
		if err = fileutil.Unmarshal(fileutil.YAML, []byte(ext), &matchOpt); err != nil {
			return err
		}
		for _, sub := range matchOpt.SubMatch {
			if err = sub.Compile(); err != nil {
				return err
			}
		}
	}

	return err
}
