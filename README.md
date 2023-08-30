<h4 align="center">pathScan 是一个用Go编写的路径扫描、信息收集、指纹探索工具，它允许您快速可靠的扫描URL地址。这是一个非常简单的工具。</h4>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/wjlin0/pathScan?filename=go.mod" alt="">
<a href="https://github.com/wjlin0/pathScan/releases/"><img src="https://img.shields.io/github/release/wjlin0/pathScan" alt=""></a> 
<a href="https://github.com/wjlin0/pathScan" ><img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/wjlin0/pathScan"></a>
<a href="https://github.com/wjlin0/pathScan/releases"><img src="https://img.shields.io/github/downloads/wjlin0/pathScan/total" alt=""></a> 
<a href="https://github.com/wjlin0/pathScan"><img src="https://img.shields.io/github/last-commit/wjlin0/PathScan" alt=""></a> 
<a href="https://blog.wjlin0.com/"><img src="https://img.shields.io/badge/wjlin0-blog-green" alt=""></a>
</p>

# 特征

- 快速发现路径、快速从网络空间中收集信息、指纹识别
- 丰富的内置字典,自动下载字典,可远程加载目标或远程加载字典
- 可持续递归扫描,恢复上次扫描进度
- 从网络空间测绘中发现目标,从持续的扫描中发现目标
- 支持使用HTTP/SOCKS5代理
- 可自定义请求头,可自定义指纹识别规则
- 通过hash,len指定跳过
- 结果可回调处理

# 用法


- 更多用法查看 [BLOG](https://blog.wjlin0.com/%E4%B8%AA%E4%BA%BA%E7%9F%A5%E8%AF%86%E5%BA%93/06.pathScan-doc/04.%E6%89%AB%E6%8F%8F%E6%A8%A1%E5%BC%8F.html)
```shell
pathScan -h
```
```text
pathScan Go 扫描、信息收集工具

Usage:
  pathScan [flags]

Flags:
输入:
   -u, -url string[]           目标(以逗号分割)
   -list string[]              从文件中,读取目标
   -tr, -target-remote string  从远程加载目标
   -tc, -target-channel        从通道中加载目标
   -resume string              使用resume.cfg恢复扫描
   -mf, -match-file string     指纹文件

递归:
   -r, -recursive            递归扫描
   -rt, -recursive-time int  递归扫描深度 (default 3)

子域名收集:
   -s, -sub                   子域名收集
   -sq, -sub-query string[]   需要收集的域名
   -sl, -sub-limit int        每个搜索引擎返回的至少不超过数 (default 1000)
   -so, -sub-output string    子域名搜索结果保存 支持csv格式输出
   -se, -sub-engine string[]  子域名搜索引擎 (default ["shodan", "censys", "fofa", "quake", "hunter", "zoomeye", "netlas", "criminalip", "publicwww", "hunterhow", "binary", "shodan-idb", "anubis", "bing", "chinaz", "google", "ip
138", "qianxun", "rapiddns", "sitedossier"])

引擎:
   -uc, -uncover                  启用打开搜索引擎
   -uq, -uncover-query string[]   搜索查询
   -ue, -uncover-engine string[]  支持的引擎 [shodan censys fofa quake hunter zoomeye netlas criminalip publicwww hunterhow binary shodan-idb anubis bing chinaz google ip138 qianxun rapiddns sitedossier] (default quake,fofa)    
   -uf, -uncover-field string     引擎返回字段 (ip,port,host) (default "host")
   -ul, -uncover-limit int        发现要返回的结果 (default 200)
   -uo, -uncover-output string    搜索引擎查询结果保存 支持csv格式输出

跳过:
   -su, -skip-url string[]   跳过的目标(以逗号分割)
   -sc, -skip-code string[]  跳过状态码
   -sh, -skip-hash string    跳过指定hash
   -sbl, -skip-body-len int  跳过body固定长度 (default -1)

扫描字典:
   -ps, -path string[]       路径(以逗号分割)
   -pf, -path-file string[]  从文件中,读取路径
   -pr, -path-remote string  从远程加载字典

输出:
   -o, -output string  输出文件路径（可忽略）
   -csv                csv格式输出
   -html               html格式输出
   -silent             简略输出
   -nc, -no-color      无颜色输出
   -vb, -verbose       详细输出模式
   -v, -version        输出版本

工具:
   -clear                          清理历史任务
   -gh, -get-hash                  计算hash
   -shm, -skip-hash-method string  指定hash的方法（sha256,md5,sha1） (default "sha256")

配置:
   -rs, -retries int                 重试
   -p, -proxy string                 代理
   -resolvers string[]               自定义DNS列表( 文件或逗号隔开 )
   -pa, -proxy-auth string           代理认证，以冒号分割（username:password）
   -st, -scan-target                 只进行目标存活扫描
   -nn, -not-new                     不允许重定向
   -sdl, -scan-domain-list string[]  从响应中中发现其他URL
   -sd, -scan-domain                 从响应中发现其他域名

请求头参数:
   -m, -method string[]          请求方法 [GET HEAD POST PUT PATCH DELETE CONNECT OPTIONS TRACE] (default ["GET"])
   -ua, -user-agent string[]     User-Agent
   -c, -cookie string            cookie
   -auth, -authorization string  Auth请求头
   -header string[]              自定义请求头,以逗号隔开
   -hf, -header-file string[]    从文件中加载自定义请求头
   -b, -body string              自定义请求体

速率:
   -t, -thread int       线程 (default 50)
   -rl, -rate-limit int  每秒允许的HTTP连接数 (default 150)
   -timeout int          超时时间 (default 30)

更新:
   -update             更新版本
   -ud, -update-dict   更新字典版本
   -um, -update-match  更新指纹识别库
   -uh, -update-html   更新HTML模板文件
   -am, -auto-match    跳过自动更新
```
# 安装pathScan

pathScan需要**go1.19**才能安装成功。执行一下命令

```sh
go install -v github.com/wjlin0/pathScan@latest
```
下载准备运行的[二进制文件](https://github.com/wjlin0/pathScan/releases/latest)

```sh
wget https://github.com/wjlin0/pathScan/releases/download/v1.1.4/pathScan_v1.1.4_windows_amd64.zip
wget https://github.com/wjlin0/pathScan/releases/download/v1.1.4/pathScan_v1.1.4_linux_amd64.zip
```




Docker

```sh
# 已提供docker文件自行编译
docker build -t pathScan .
docker run --rm --name pathScan -it pathScan  -u https://wjlin0.com -vb
```


自行编译

```sh
git clone https://github.com/wjlin0/pathScan.git && cd pathScan
go install github.com/goreleaser/goreleaser@latest
goreleaser release --snapshot --skip-publish --skip-docker --rm-dist
```




# 运行pathScan

```text
pathScan -t https://wjlin0.com
# 从管道中加载
cat url.txt | pathScan -tc
# 恢复上次扫描
pathScan -resume Hc7wUXRoH2G1RjrNgjB2OMzXlXo1Hg.cfg
# 输出
pathScan -u https://wjlin0.com -csv -output 1.csv
# 自定义请求头
pathScan -u https://wjlin0.com -header User-Agent:pathScan/1.8,Cookie:a=1  -header a:1
# 跳过指定hash,指定长度
pathScan -u https://wjlin0.com -sh 291583051dfea8f6e512e25121cb09209b8e57402f0d32dcd8d1b611f16a3b20 -sbl 114763
```
# 收集某个资产
```sh
pathScan -s -sq baidu.com -sd -o output/baidu/baidu.csv -csv
```
# 自定义指纹

采用配置文件的方式，可自定义加载指纹识别库 -> [pathScan-match](https://github.com/wjlin0/pathScan-match) 
如果您掌握某些系统的指纹识别方法 欢迎至指纹识别库中提交 pull
```yaml
version: "v1.0.0"
rules:
  - name: "Thinkphp"
    matchers:
      - type: regex
        part: header
        regex:
          - "ThinkPHP"
  - name: "Apache"
    matchers:
      - type: regex
        part: header
        name: Apache
        regex: 
          - "Server: .*?([aA]{1}pache[/]?[\\d\\.]*) ?"
        group: 1
  - name: "Nginx"
    matchers:
      - type: regex
        name: nginx
        part: header
        regex: 
          - "Server: .*?([nN]{1}ginx[/]?[\\d\\.]*) ?"
        group: 1 # 指定后匹配的名字为正则匹配后的第1个元素
```

# 集成到自己的工具中
```go
package main

import (
    "fmt"
    "github.com/projectdiscovery/gologger"
    "github.com/wjlin0/pathScan/pkg/result"
    "github.com/wjlin0/pathScan/pkg/runner"
    "github.com/wjlin0/pathScan/pkg/util"
    "os"
    "os/signal"
    "path/filepath"
    "time"
)

func main() {
	options := &runner.Options{Url: []string{
		"https://localhost:8000",
	},
		RateHttp:    2,
		TimeoutTCP:  2 * time.Second,
		TimeoutHttp: 2 * time.Second,
		ResultBack: func(result *result.TargetResult) {
			fmt.Println(result)
		},
		Method: "GET",
		Path: []string{
			"/",
		},
	}
	run, err := runner.NewRunner(options)
	if err != nil {
		gologger.Print().Msg(fmt.Sprintf("无法创建Runner: %s", err.Error()))
		os.Exit(0)
	}
	if run == nil {
		os.Exit(0)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msg("CTRL+C 按下: Exiting")
			filename := util.RandStr(30) + ".cfg"
			fmt.Println(filepath.Join(runner.DefaultResumeFolderPath(), filename))
			err := run.Cfg.MarshalResume(filename)
			if err != nil {
				gologger.Error().Msgf("无法创建 resume 文件: %s", err.Error())
			}
			os.Exit(1)
		}
	}()
	err = run.Run()
	if err != nil {
		gologger.Fatal().Msgf("无法 运行: %s", err.Error())
	}
	run.Cfg.CleanupResumeConfig()
}
```


pathScan 支持默认配置文件位于下面两个路径，它允许您在配置文件中定义任何标志并设置默认值以包括所有扫描。
- $HOME/.config/pathScan/config.yaml
- $HOME/.config/pathScan/provider-config.yaml

# 警告
> ~~由于这个项目是自己一个人开发，在发布前没有做什么测试，都是在后面自己使用的时候发现问题才回去修复bug，所以大家尽量看到有新版本，即使更新~~
> 
> ~~我向下适配也做得不好，可能一些在线校对的（比如 字典、html模板等下载），不会去适配低版本，为了大家的体验还是尽量选择更新~~

# 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
