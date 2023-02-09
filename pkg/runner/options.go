package runner

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

type Options struct {
	Url        goflags.StringSlice `json:"url,omitempty"`
	UrlFile    goflags.StringSlice `json:"url_file,omitempty"`
	UrlRemote  string              `json:"url_remote,omitempty"`
	Path       goflags.StringSlice `json:"path,omitempty"`
	PathFile   goflags.StringSlice `json:"path_file,omitempty"`
	PathRemote string              `json:"path_remote,omitempty"`
	ResumeCfg  string              `json:"resume_cfg,omitempty"`
	Output     string              `json:"output,omitempty"`
	Rate       int                 `json:"rate,omitempty"`
	RateHttp   int                 `json:"rate_http,omitempty"`
	Retries    int                 `json:"retries,omitempty"`
	Proxy      string              `json:"proxy,omitempty"`
	ProxyAuth  string              `json:"proxy_auth,omitempty"`
	NoColor    bool                `json:"no_color"`
	Verbose    bool                `json:"verbose"`
	Silent     bool                `json:"silent"`
}

func ParserOptions() *Options {
	option := &Options{}
	set := goflags.NewFlagSet()
	set.SetDescription("SpringBoot Scan Go ....")
	set.CreateGroup("Input", "输入",
		set.StringSliceVarP(&option.Url, "url", "u", nil, "目标(以逗号分割)", goflags.NormalizedStringSliceOptions),
		set.StringSliceVarP(&option.UrlFile, "url-file", "uf", nil, "从文件中,读取目标", goflags.FileStringSliceOptions),
		set.StringVarP(&option.UrlRemote, "url-remote", "ur", "", "从远程加载目标"),
		set.StringVar(&option.ResumeCfg, "resume", "", "使用resume.cfg恢复扫描"),
	)
	set.CreateGroup("Dict", "扫描字典",
		set.StringSliceVarP(&option.Path, "path", "ps", nil, "路径(以逗号分割)", goflags.NormalizedStringSliceOptions),
		set.StringSliceVarP(&option.PathFile, "path-file", "pf", nil, "从文件中,读取路径", goflags.FileStringSliceOptions),
		set.StringVarP(&option.PathRemote, "path-remote", "pr", "", "从远程加载字典"),
	)
	set.CreateGroup("output", "输出",
		set.StringVarP(&option.Output, "output", "o", "", "输出文件路径（可忽略）"),
		set.BoolVarP(&option.NoColor, "no-color", "nc", false, "无颜色输出"),
		set.BoolVarP(&option.Verbose, "verbose", "vb", false, "详细输出模式"),
		set.BoolVarP(&option.Silent, "silent", "sl", false, "只输出状态码为200"),
	)
	set.CreateGroup("config", "配置",
		set.IntVarP(&option.Retries, "retries", "rs", 3, "重试3次"),
		set.StringVarP(&option.Proxy, "proxy", "p", "", "代理"),
		set.StringVarP(&option.ProxyAuth, "proxy-auth", "pa", "", "代理认证，以冒号分割（username:password）"),
	)
	set.CreateGroup("rate", "速率",
		set.IntVarP(&option.Rate, "rate-limit", "rl", 150, "线程(默认150)"),
		set.IntVarP(&option.RateHttp, "rate-http", "rh", 20, "允许同时http请求数(默认20)"),
	)
	_ = set.Parse()
	//if option.Path == nil && option.PathFile == nil && option.PathRemote == "" && option.ResumeCfg == "" {
	//	abs, _ := filepath.Abs("springboot.txt")
	//	if !fileutil.FileExists(abs) {
	//		fmt.Println(fmt.Errorf("%s 无指定扫描字典 \n", abs))
	//		os.Exit(1)
	//	}
	//	option.PathFile, _ = goflags.ToStringSlice(abs, goflags.FileStringSliceOptions)
	//}
	showBanner()
	return option
}

func (o *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if o.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if o.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if o.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
