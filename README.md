<h4 align="center">pathScan 是一个用Go编写的路径扫描工具，它允许您快速可靠的扫描URL地址。这是一个非常简单的工具。</h4>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/wjlin0/pathScan?filename=go.mod" alt="">
<a href="https://github.com/wjlin0/pathScan/releases/"><img src="https://img.shields.io/github/release/wjlin0/pathScan" alt=""></a> 
<a href="https://hub.docker.com/repository/docker/wjlin0/path_scan/general" ><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/wjlin0/path_scan"></a>
<a href="https://github.com/wjlin0/pathScan/releases"><img src="https://img.shields.io/github/downloads/wjlin0/pathScan/total" alt=""></a> 
<a href="https://github.com/wjlin0/pathScan"><img src="https://img.shields.io/github/last-commit/wjlin0/PathScan" alt=""></a> 
<a href="https://wjlin0.com/"><img src="https://img.shields.io/badge/wjlin0-blog-green" alt=""></a>
</p>

# 特征

- 快速发现路径
- 丰富的内置字典,自动下载字典,可远程加载目标或远程加载字典
- 可持续递归扫描,恢复上次扫描进度
- 从网络空间测绘中发现目标,从持续的扫描中发现目标
- 支持使用HTTP/SOCKS5代理
- 可自定义请求头,可自定义指纹识别规则
- 通过hash,len指定跳过
- 结果可回调处理

# 用法

```shell
pathScan -h
```
```yaml
Usage:
  pathScan [flags]

Flags:
输入:
  -t, -target string[]        目标(以逗号分割)
  -tf, -target-file string[]  从文件中,读取目标
  -tr, -target-remote string  从远程加载目标
  -resume string              使用resume.cfg恢复扫描
  -mf, -match-file string     指纹文件

递归:
  -r, -recursive               递归扫描
  -rt, -recursive-time int     递归扫描深度 (default 3)
  -rf, -recursive-file string  递归扫描目录 (default "/root/.config/pathScan/dict/dir.txt")

跳过:
  -su, -skip-url string[]   跳过的目标(以逗号分割)
  -sc, -skip-code string[]  跳过状态码
  -sh, -skip-hash string    跳过指定hash
  -sbl, -skip-body-len int  跳过body固定长度 (default -1)

扫描字典:
  -ps, -path string[]       路径(以逗号分割)
  -pf, -path-file string[]  从文件中,读取路径
  -pr, -path-remote string  从远程加载字典
..................
..................
..................
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
docker pull wjlin0/path_scan:latest
docker run --rm --name pathScan -it wjlin0/path_scan:latest  -t https://wjlin0.com -vb
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
cat url.txt | pathScan -silent
# 使用搜索引擎
pathScan -uc -ue "fofa" -uq "domain=baidu.com"
# 恢复上次扫描
pathScan -resume Hc7wUXRoH2G1RjrNgjB2OMzXlXo1Hg.cfg
# 输出
pathScan -t https://wjlin0.com -csv -output 1.csv
# 自定义请求头
pathScan -t https://wjlin0.com -header User-Agent:pathScan/1.8,Cookie:a=1  -header a:1
# 跳过指定hash,指定长度
pathScan -t https://wjlin0.com -sh 291583051dfea8f6e512e25121cb09209b8e57402f0d32dcd8d1b611f16a3b20 -sbl 114763
```
# 自定义指纹

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
- $HOME/.config/pathScan/match-config.yaml

# 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
