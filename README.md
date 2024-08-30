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

- 快速发现路径、收集信息
- 基于[指纹库](https://github.com/wjlin0/pathScan-match)的快速指纹探测
- 从网络空间测绘中发现目标,从持续的扫描中发现目标
- 利用搜索引擎快速搜索子域名
- 结果可回调自行处理


# 安装pathScan

pathScan需要**go1.21**才能安装成功。执行一下命令

```sh
go install -v github.com/wjlin0/pathScan/v2/cmd/pathScan@latest
```
下载准备运行的[二进制文件](https://github.com/wjlin0/pathScan/releases/latest)

- [macOS-arm64](https://github.com/wjlin0/pathScan/releases/download/v2.1.3/pathScan_2.1.3_macOS_arm64.zip)

- [macOS-amd64](https://github.com/wjlin0/pathScan/releases/download/v2.1.3/pathScan_2.1.3_macOS_amd64.zip)

- [linux-amd64](https://github.com/wjlin0/pathScan/releases/download/v2.1.3/pathScan_2.1.3_linux_amd64.zip)

- [windows-amd64](https://github.com/wjlin0/pathScan/releases/download/v2.1.3/pathScan_2.1.3_windows_amd64.zip)

- [windows-386](https://github.com/wjlin0/pathScan/releases/download/v2.1.3/pathScan_2.1.3_windows_386.zip)


# 用法

```shell
pathScan -h
```
```yaml
pathScan 2.1.3 Go 扫描、信息收集工具

Usage:
  pathScan [flags]

Flags:
输入:
  -u, -url string[]  目标(以逗号分割)
  -list string[]     从文件中,读取目标

扫描字典:
  -ps, -path string[]       路径(以逗号分割)
  -pl, -path-list string[]  从文件中,读取路径
  -lad, -load-api-dict      是否加载api字典

自动过滤扫描路径模式（默认）:
  -bs, -black-status string[]     黑名单状态码(以逗号分割,支持从文件读取 -bs /tmp/skip-code.txt, 支持 5xx、300-399 ) (default ["400", "410"])
  -daps, -disable-auto-path-scan  禁用自动过滤扫描路径模式
  -ws, -waf-status string[]       WAF状态码(以逗号分割,支持从文件读取 -ws /tmp/skip-code.txt, 支持 5xx、300-399 ） (default ["493", "418"])
  -fs, -fuzzy-status string[]     模糊状态码(以逗号分割,支持从文件读取 -fs /tmp/skip-code.txt, 支持 5xx、300-399 ) (default ["403", "404", "500", "501", "502", "503"])

指纹识别模式:
  -op, -operator           是否启用模版规则
  -mf, -match-file string  指纹文件目录或文件

子域名收集模式:
  -s, -sub                   子域名收集
  -sq, -sub-query string[]   需要收集的域名 (支持从文件中录入 -sq /tmp/sub-query.txt)
  -sl, -sub-limit int        每个搜索引擎返回的至少不超过数 (default 1000)
  -so, -sub-output string    子域名搜索结果保存 支持csv格式输出
  -se, -sub-engine string[]  子域名搜索引擎 [shodan censys fofa quake hunter zoomeye netlas criminalip publicwww hunterhow binaryedge github fullhunt zone0 daydaymap shodan-ids-spider sitedossier-spider fofa-spider bing-spider chinaz-spider google-spider ip138-spider qianxun-spider rapiddns-spider baidu-spider yahoo-spider zoomeye-spider] (default all)

引擎搜索模式:
  -uc, -uncover                  启用打开搜索引擎
  -uq, -uncover-query string[]   搜索查询
  -ue, -uncover-engine string[]  支持的引擎 [shodan censys fofa quake hunter zoomeye netlas criminalip publicwww hunterhow binaryedge github fullhunt zone0 daydaymap] (default)
  -uf, -uncover-field string     引擎返回字段 (ip,port,host) (default "host:port")
  -ul, -uncover-limit int        发现要返回的结果 (default 100)
  -uo, -uncover-output string    搜索引擎查询结果保存 支持csv格式输出

跳过:
  -su, -skip-url string[]          跳过的目标(以逗号分割,支持从文件读取 -su /tmp/skip-url.txt)
  -sc, -skip-code string[]         跳过状态码(以逗号分割,支持从文件读取 -sc /tmp/skip-code.txt, 支持 5xx、300-399 )
  -sh, -skip-hash string           跳过指定hash
  -sbl, -skip-body-len string[]    跳过body固定长度(支持 100-200,即长度为100~200之间的均跳过,支持 从文件中读取 -sbl /tmp/skip-body-len.txt)
  -sbr, -skip-body-regex string[]  跳过body正则匹配(以逗号分割,支持从文件读取 -sbr /tmp/skip-regex.txt)

输出:
  -o, -output string  输出文件路径（可忽略）
  -csv                csv格式输出
  -html               html格式输出
  -silent             简略输出
  -nc, -no-color      无颜色输出
  -vb, -verbose       详细输出模式
  -debug              调试输出

工具:
  -gh, -get-hash                  计算hash
  -shm, -skip-hash-method string  指定hash的方法（sha256,md5,sha1） (default "sha256")

配置:
  -no-stdin                         disable stdin processing
  -rs, -retries int                 重试
  -p, -proxy string[]               代理
  -resolvers string[]               自定义DNS列表( 文件或逗号隔开 )
  -nn, -not-new                     允许重定向
  -validate                         验证指纹文件
  -dac, -disable-alive-check        跳过活跃检查
  -sdl, -scan-domain-list string[]  从响应中中发现其他域名（逗号隔开，支持文件读取 -sdl /tmp/otherDomain.txt）
  -sd, -scan-domain                 从响应中发现其他域名
  -v, -version                      输出版本

请求头参数:
  -m, -method string[]          请求方法 [GET HEAD POST PUT PATCH DELETE CONNECT OPTIONS TRACE] (default ["GET"])
  -ua, -user-agent string[]     User-Agent (支持从文件中录入 -ua /tmp/user-agent.txt)
  -c, -cookie string            cookie
  -auth, -authorization string  Auth请求头
  -header string[]              自定义请求头,以逗号隔开 (支持从文件中录入 -header /tmp/header.txt)
  -b, -body string              自定义请求体

速率:
  -t, -thread int       线程 (default 50)
  -rl, -rate-limit int  每秒允许的HTTP连接数 (default 150)
  -http-timeout int     HTTP请求超时时间 (default 15)

更新:
  -update                      更新版本
  -um, -update-match           更新指纹识别库
  -duc, -disable-update-check  跳过自动检查更新


EXAMPLES:

运行 pathScan 扫描路径, 指定单个目标:
  $ pathScan -u https://example.com/

运行 pathScan 搜索引擎:
  $ pathScan -ue fofa -uq 'app="tomcat"' -silent

  运行 pathScan 指纹探测：
  $ pathScan -op -u https://example.com

运行 pathScan 收集子域名 并配合 nuclei 进行自动化漏洞扫描:
  $ pathScan -sq example.com -silent | nuclei

其他文档可在以下网址获得: https://github.com/wjlin0/pathScan/
```

## 提供API KEY 配置

默认的提供程序配置文件应位于`$HOME/.config/pathScan/provider-config.yaml`，并具有以下内容作为示例

> **注**：API密钥是必需的，必须在运行网络空间搜索之前进行配置。


>  $HOME/.config/pathScan/provider-config.yaml
```yaml
shodan:
  - SHODAN_API_KEY_1
  - SHODAN_API_KEY_2
censys:
  - CENSYS_API_ID_1:CENSYS_API_SECRET_1
  - CENSYS_API_ID_2:CENSYS_API_SECRET_2
github:
  - GITHUB_TOKEN_1
  - GITHUB_TOKEN_2
fofa:
  - FOFA_EMAIL_1:FOFA_KEY_1
  - FOFA_EMAIL_2:FOFA_KEY_2
quake:
  - QUAKE_TOKEN_1
  - QUAKE_TOKEN_2
hunter:
  - HUNTER_API_KEY_1
  - HUNTER_API_KEY_2
zoomeye:
  - ZOOMEYE_API_KEY_1
  - ZOOMEYE_API_KEY_2
netlas:
  - NETLAS_API_KEY_1
  - NETLAS_API_KEY_2
criminalip:
  - CRIMINALIP_API_KEY_1
  - CRIMINALIP_API_KEY_2
publicwww:
  - PUBLICWWW_API_KEY_1
  - PUBLICWWW_API_KEY_2
hunterhow:
  - HUNTERHOW_API_KEY_1 
  - HUNTERHOW_API_KEY_2
fullhunt:
  - FULLHUNT_API_KEY_1
  - FULLHUNT_API_KEY_2
binaryedge:
  - BINARYEDGE_API_KEY_1
  - BINARYEDGE_API_KEY_2
zone0:
  - ZONE0_API_KEY_1
  - ZONE0_API_KEY_2
daydaymap:
    - DAYDAYMAP_API_KEY_1
    - DAYDAYMAP_API_KEY_2
```

当在配置文件中为同一提供程序指定了多个密钥/凭据时，每次执行都将使用随机密钥。

或者，您也可以在bash概要文件中将API键设置为环境变量。

```yaml
export SHODAN_API_KEY=xxx
export ZOOMEYE_API_KET=xxx
export GITHUB_TOKEN=xxx
export QUAKE_TOKEN=xxx
export BINARYEDGE_API_KEY=xxx
export HUNTER_API_KEY=xxx
export NETLAS_API_KEY=xxx
export CENSYS_API_ID=xxx
export CENSYS_API_SECRET=xxx
export FOFA_EMAIL=xxx
export FOFA_KEY=xxx
export FULLHUNT_API_KEY=xxx
export HUNTERHOW_API_KEY=xxx
export PUBLICWWW_API_KEY=xxx
export CRIMINALIP_API_KEY=xxx
export ZOOE0_API_KEY=xxx
export DAYDAYMAP_API_KEY=xxx
```

所需的API密钥可以通过在以下平台上注册获得
 - [Shodan](https://account.shodan.io/register)
 - [Censys](https://censys.io/register)
 - [Fofa](https://fofa.info/toLogin)
 - [Quake](https://quake.360.net/quake/#/index)
 - [Hunter](https://user.skyeye.qianxin.com/user/register?next=https%3A//hunter.qianxin.com/api/uLogin&fromLogin=1)
 - [ZoomEye](https://www.zoomeye.org/login)
 - [Netlas](https://app.netlas.io/registration/)
 - [CriminalIP](https://www.criminalip.io/register)
 - [Publicwww](https://publicwww.com/profile/signup.html) 
 - [binary](https://app.binaryedge.io/login)
 - [fullhunt](https://fullhunt.io/)
 - [daydaymao](https://www.daydaymap.com/)



## 自定义指纹

采用配置文件的方式，可自定义加载指纹识别库 -> [pathScan-match](https://github.com/wjlin0/pathScan-match) 
如果您掌握某些系统的指纹识别方法 欢迎至指纹识别库中提交 pull
```yaml
name: nginx
request:
  - method: GET
    path:
      - /
matchers:
  - type: regex
    name: nginx
    part: header
    regex:
      - '(?i)Server: .*?(nginx[/\d\.]*).*?'
    group: 1

```

## 集成到自己的工具中
```go
package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/v2/pkg/output"
	"github.com/wjlin0/pathScan/v2/pkg/runner"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"os"
)

func main() {
	options := types.DefaultOptions
	options.URL = []string{"wjlin0.com"}
	options.DisableAliveCheck = true
	options.DisableUpdateCheck = true

	options.ResultEventCallback = func(result output.ResultEvent) {
		fmt.Println(result)
	}

	runner.DefaultOptions(options)
	runner.ConfigureOutput(options)
	err := runner.ValidateRunEnumeration(options)
	if err != nil {
		gologger.Print().Msg(fmt.Sprintf("unable to create Runner:%s", err.Error()))
		os.Exit(-1)
		return
	}

	run, err := runner.NewRunner(options)
	if err != nil || run == nil {
		if err != nil {
			gologger.Print().Msg(fmt.Sprintf("unable to create Runner:%s", err.Error()))
			os.Exit(-1)
		}
		return
	}
	if err := run.RunEnumeration(); err != nil {
		gologger.Fatal().Msgf("unable to run enumeration: %s", err.Error())
	}

	run.Close()
}

```


pathScan 支持默认配置文件位于下面两个路径，它允许您在配置文件中定义任何标志并设置默认值以包括所有扫描。
- $HOME/.config/pathScan/config.yaml
- $HOME/.config/pathScan/provider-config.yaml
# 更多用法
- https://www.wjlin0.com/archives/1711956620976
# 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
