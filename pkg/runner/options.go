package runner

import (
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/retryablehttp-go"
	fileutil "github.com/projectdiscovery/utils/file"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/wjlin0/pathScan/v2/pkg/identification"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"github.com/wjlin0/uncover"
	updateutils "github.com/wjlin0/utils/update"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func ParserOptions() *types.Options {
	options := &types.Options{}

	set := goflags.NewFlagSet()
	set.SetDescription(fmt.Sprintf("pathScan %s Go 扫描、信息收集工具 ", Version))
	set.CreateGroup("Input", "输入",
		set.StringSliceVarP(&options.URL, "url", "u", nil, "目标(以逗号分割)", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVar(&options.List, "list", nil, "从文件中,读取目标", goflags.FileCommaSeparatedStringSliceOptions),
	)
	set.CreateGroup("Dict", "扫描字典",
		set.StringSliceVarP(&options.Path, "path", "ps", nil, "路径(以逗号分割)", goflags.CommaSeparatedStringSliceOptions),
		set.StringSliceVarP(&options.PathList, "path-list", "pl", nil, "从文件中,读取路径", goflags.FileStringSliceOptions),
		set.BoolVarP(&options.LoadAPIDict, "load-api-dict", "lad", false, "是否加载api字典"),
	)
	set.CreateGroup("AutoPathScan", "自动过滤扫描路径模式（默认）",
		set.StringSliceVarP(&options.BlackStatus, "black-status", "bs", goflags.StringSlice{"400", "410"}, "黑名单状态码(以逗号分割,支持从文件读取 -bs /tmp/skip-code.txt, 支持 5xx、300-399 )", goflags.FileNormalizedStringSliceOptions),
		set.BoolVarP(&options.DisableAutoPathScan, "disable-auto-path-scan", "daps", false, "禁用自动过滤扫描路径模式"),
		set.StringSliceVarP(&options.WafStatus, "waf-status", "ws", goflags.StringSlice{"493", "418"}, "WAF状态码(以逗号分割,支持从文件读取 -ws /tmp/skip-code.txt, 支持 5xx、300-399 ）", goflags.FileNormalizedStringSliceOptions),
		set.StringSliceVarP(&options.FuzzyStatus, "fuzzy-status", "fs", goflags.StringSlice{"403", "404", "500", "501", "502", "503"}, "模糊状态码(以逗号分割,支持从文件读取 -fs /tmp/skip-code.txt, 支持 5xx、300-399 )", goflags.FileNormalizedStringSliceOptions),
	)
	set.CreateGroup("Operator", "指纹识别模式",
		set.BoolVarP(&options.Operator, "operator", "op", false, "是否启用模版规则"),
		set.StringVarP(&options.MatchPath, "match-file", "mf", "", "指纹文件目录或文件"),
	)
	set.CreateGroup("Subdomain", "子域名收集模式",
		set.BoolVarP(&options.Subdomain, "sub", "s", false, "子域名收集"),
		set.StringSliceVarP(&options.SubdomainQuery, "sub-query", "sq", nil, "需要收集的域名 (支持从文件中录入 -sq /tmp/sub-query.txt)", goflags.FileStringSliceOptions),
		set.IntVarP(&options.SubdomainLimit, "sub-limit", "sl", defaultSubdomainLimit, "每个搜索引擎返回的至少不超过数"),
		set.StringVarP(&options.SubdomainOutput, "sub-output", "so", "", "子域名搜索结果保存 支持csv格式输出"),
		set.StringSliceVarP(&options.SubdomainEngine, "sub-engine", "se", nil, fmt.Sprintf("子域名搜索引擎 %s (default all)", uncover.AllAgents()), goflags.NormalizedStringSliceOptions),
	)

	set.CreateGroup("Uncover", "引擎搜索模式",
		set.BoolVarP(&options.Uncover, "uncover", "uc", false, "启用打开搜索引擎"),
		set.StringSliceVarP(&options.UncoverQuery, "uncover-query", "uq", nil, "搜索查询", goflags.StringSliceOptions),
		set.StringSliceVarP(&options.UncoverEngine, "uncover-engine", "ue", nil, fmt.Sprintf("支持的引擎 %s (default fofa)", uncover.UncoverAgents()), goflags.NormalizedStringSliceOptions),
		set.StringVarP(&options.UncoverField, "uncover-field", "uf", "host", "引擎返回字段 (ip,port,host)"),
		set.IntVarP(&options.UncoverLimit, "uncover-limit", "ul", defaultUncoverLimit, "发现要返回的结果"),
		set.StringVarP(&options.UncoverOutput, "uncover-output", "uo", "", "搜索引擎查询结果保存 支持csv格式输出"),
	)
	set.CreateGroup("Skip", "跳过",
		set.StringSliceVarP(&options.SkipURL, "skip-url", "su", nil, "跳过的目标(以逗号分割,支持从文件读取 -su /tmp/skip-url.txt)", goflags.FileStringSliceOptions),
		set.StringSliceVarP(&options.SkipCode, "skip-code", "sc", nil, "跳过状态码(以逗号分割,支持从文件读取 -sc /tmp/skip-code.txt, 支持 5xx、300-399 )", goflags.FileNormalizedStringSliceOptions),
		set.StringVarP(&options.SkipHash, "skip-hash", "sh", "", "跳过指定hash"),
		set.StringSliceVarP(&options.SkipBodyLen, "skip-body-len", "sbl", nil, "跳过body固定长度(支持 100-200,即长度为100~200之间的均跳过,支持 从文件中读取 -sbl /tmp/skip-body-len.txt)", goflags.FileNormalizedStringSliceOptions),
		set.StringSliceVarP(&options.SkipBodyRegex, "skip-body-regex", "sbr", nil, "跳过body正则匹配(以逗号分割,支持从文件读取 -sbr /tmp/skip-regex.txt)", goflags.FileCommaSeparatedStringSliceOptions),
	)

	set.CreateGroup("Output", "输出",
		set.StringVarP(&options.Output, "output", "o", "", "输出文件路径（可忽略）"),
		set.BoolVar(&options.CSV, "csv", false, "csv格式输出"),
		set.BoolVar(&options.HTML, "html", false, "html格式输出"),
		set.BoolVar(&options.Silent, "silent", false, "简略输出"),
		set.BoolVarP(&options.NoColor, "no-color", "nc", false, "无颜色输出"),
		set.BoolVarP(&options.Verbose, "verbose", "vb", false, "详细输出模式"),
		set.BoolVar(&options.Debug, "debug", false, "调试输出"),
	)

	set.CreateGroup("Tool", "工具",
		set.BoolVarP(&options.GetHash, "get-hash", "gh", false, "计算hash"),
		set.StringVarP(&options.SkipHashMethod, "skip-hash-method", "shm", "sha256", "指定hash的方法（sha256,md5,sha1）"),
	)
	set.CreateGroup("Config", "配置",
		set.BoolVar(&options.DisableStdin, "no-stdin", false, "disable stdin processing"),
		set.IntVarP(&options.RetryMax, "retries", "rs", defaultRetries, "重试"),
		set.StringSliceVarP(&options.Proxy, "proxy", "p", nil, "代理", goflags.FileCommaSeparatedStringSliceOptions),
		set.StringSliceVar(&options.Resolvers, "resolvers", nil, "自定义DNS列表( 文件或逗号隔开 )", goflags.FileNormalizedStringSliceOptions),
		set.BoolVarP(&options.ErrUseLastResponse, "not-new", "nn", false, "允许重定向"),
		set.BoolVar(&options.Validate, "validate", false, "验证指纹文件"),
		set.BoolVarP(&options.DisableAliveCheck, "disable-alive-check", "dac", false, "跳过活跃检查"),
		set.StringSliceVarP(&options.FindOtherDomainList, "scan-domain-list", "sdl", nil, "从响应中中发现其他域名（逗号隔开，支持文件读取 -sdl /tmp/otherDomain.txt）", goflags.FileNormalizedOriginalStringSliceOptions),
		set.BoolVarP(&options.FindOtherDomain, "scan-domain", "sd", false, "从响应中发现其他域名"),
		set.CallbackVarP(getVersionFromCallback(), "version", "v", "输出版本"),
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
		set.IntVarP(&options.Thread, "thread", "t", defaultThread, "线程"),
		set.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "每秒允许的HTTP连接数"),
		set.IntVar(&options.HttpTimeout, "http-timeout", defaultHTTPTimeout, "HTTP请求超时时间"),
	)
	set.CreateGroup("Update", "更新",
		set.CallbackVar(updateutils.GetUpdateToolCallback(pathScanRepoName, Version), "update", "更新版本"),
		set.CallbackVarP(updateutils.GetUpdateDirFromRepoNoErrCallback(pathScanMatchRepoName, DefaultMatchDir, pathScanMatchRepoName), "update-match", "um", "更新指纹识别库"),
		set.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "跳过自动检查更新"),
	)
	set.SetCustomHelpText(`EXAMPLES:

运行 pathScan 扫描路径, 指定单个目标:
    $ pathScan -u https://example.com/ 

运行 pathScan 搜索引擎:
    $ pathScan -ue fofa -uq 'app="tomcat"' -silent

运行 pathScan 指纹探测：
    $ pathScan -op -u https://example.com

运行 pathScan 收集子域名 并配合 nuclei 进行自动化漏洞扫描:
    $ pathScan -sq example.com -silent | nuclei

其他文档可在以下网址获得: https://github.com/wjlin0/pathScan/
`)

	err := initPathScan()
	if err != nil {
		gologger.Fatal().Msgf("init pathScan error: %s", err.Error())
	}

	set.SetConfigFilePath(filepath.Join(DefaultPathScanConfig))

	_ = set.Parse()

	options.Stdin = !options.DisableStdin && fileutil.HasStdin()

	// set default options
	DefaultOptions(options)

	// config output
	ConfigureOutput(options)

	// show banner
	showBanner()

	// validate options
	err = ValidateRunEnumeration(options)
	if err != nil {
		gologger.Fatal().Msgf("options validation error: %s", err.Error())
	}

	// validate match
	if options.Validate {
		if err = validateMatch(options); err != nil {
			gologger.Fatal().Msgf("validate match error: %s", err.Error())
		}
		gologger.Info().Msgf("match file validate success")
		os.Exit(0)

	}
	// get hash from url
	if options.GetHash {
		if err = getHash(options); err != nil {
			gologger.Fatal().Msgf("get hash error: %s", err.Error())
		}
		os.Exit(0)
	}

	return options
}

func ConfigureOutput(options *types.Options) {

	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.Verbose || options.Validate {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(options.NoColor))
		color.NoColor = true
	}
}

func getVersionFromCallback() func() {
	return func() {
		showBanner()
		gologger.Info().Msgf("PathScan Engine Version: v%s", Version)
		gologger.Info().Msgf("PathScan Match Config Version: %s", PathScanMatchVersion)
		gologger.Info().Msgf("PathScan Config Directory: %s", DefaultPathScanDir)
		os.Exit(0)
	}
}

func validateMatch(opts *types.Options) error {
	var (
		err       error
		matchPath string
		extension []string
	)
	matchPath = DefaultMatchDir
	if opts.MatchPath != "" {
		matchPath = opts.MatchPath
	}

	if fileutil.FileExists(matchPath) {
		oper := &identification.Operators{}
		if e := oper.LoadConfigFrom(matchPath); e != nil {
			return e
		}
		if e := oper.Compile(); e != nil {
			return e
		}
		return nil
	}

	if extension, err = util.ListFilesWithExtension(matchPath, ".yaml"); err != nil {
		return err
	}
	if len(extension) == 0 {
		return fmt.Errorf("no match file found in %s", matchPath)
	}
	for _, ext := range extension {
		oper := &identification.Operators{}
		if e := oper.LoadConfigFrom(ext); e != nil {
			return err
		}
		if e := oper.Compile(); e != nil {
			return err
		}
	}
	return err
}

func getHash(options *types.Options) error {
	var (
		err  error
		resp *http.Response
		hash []byte
	)

	uri := options.URL[0]
	if resp, err = retryablehttp.DefaultHTTPClient.Get(uri); err != nil {
		return err
	}
	buffer := bytes.Buffer{}
	if _, err = io.Copy(&buffer, resp.Body); err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	hash, _ = util.GetHash(buffer.Bytes(), options.SkipHashMethod)
	gologger.Print().Msgf("[%s] %s\n", color.GreenString(options.SkipHashMethod), string(hash))

	return nil
}
