<h4 align="center">pathScan 是一个用Go编写的路径扫描工具，它允许您快速可靠的扫描URL地址。这是一个非常简单的工具。</h4>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/wjlin0/pathScan?filename=go.mod" alt="">
<a href="https://github.com/wjlin0/pathScan/releases"><img src="https://img.shields.io/github/downloads/wjlin0/pathScan/total" alt=""></a> 
<a href="https://github.com/wjlin0/pathScan/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors-anon/wjlin0/pathScan"></a> 
<a href="https://github.com/wjlin0/pathScan/releases/"><img src="https://img.shields.io/github/release/wjlin0/pathScan" alt=""></a> 
<a href="https://hub.docker.com/repository/docker/wjlin0/path_scan/general" ><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/wjlin0/path_scan"></a>
<a href="https://wjlin0.com/"><img src="https://img.shields.io/badge/wjlin0-blog-green" alt=""></a>
</p>

# 特征

- 快速发现路径
- 可远程加载目标或远程加载字典
- 丰富的内置字典,自动下载字典
- 可恢复上次扫描进度
- 从网络空间测绘中发现目标
- 支持使用HTTP/SOCKS代理
- 可自定义请求头
- 可自定义指纹识别规则

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

跳过:
  -su, -skip-url string[]   跳过的目标(以逗号分割)
  -sc, -skip-code string[]  跳过状态码

扫描字典:
  -ps, -path string[]       路径(以逗号分割)
  -pf, -path-file string[]  从文件中,读取路径
  -pr, -path-remote string  从远程加载字典

输出:
  -o, -output string  输出文件路径（可忽略）
  -csv                csv格式输出
  -nc, -no-color      无颜色输出
  -vb, -verbose       详细输出模式
  -sl, -silent        管道模式
  -pb, -progressbar   启用进度条
  -v, -version        输出版本

配置:
  -rs, -retries int        重试3次 (default 3)
  -p, -proxy string        代理
  -pa, -proxy-auth string  代理认证，以冒号分割（username:password）
  -st, -scan-target        只进行目标存活扫描
  -nn, -not-new            不允许重定向
  -clear                   清理历史任务

引擎:
  -uc, -uncover                  启用打开搜索引擎
  -uq, -uncover-query string[]   搜索查询
  -ue, -uncover-engine string[]  支持的引擎 (shodan,shodan-idb,fofa,censys,quake,hunter,zoomeye,netlas,zone,binary) (default quake,fofa)
  -uf, -uncover-field string     引擎返回字段 (ip,port,host) (default "host")
  -ul, -uncover-limit int        发现要返回的结果 (default 200)
  -ucd, -uncover-delay int       打开查询请求之间的延迟（秒） (default 1)
  -uo, -uncover-output string    搜索引擎查询结果保存

请求头参数:
  -m, -method string            请求方法 (default "GET")
  -ua, -user-agent string[]     User-Agent
  -c, -cookie string            cookie
  -auth, -authorization string  Auth请求头
  -header string[]              自定义请求头,以逗号隔开
  -hf, -header-file string[]    从文件中加载自定义请求头

速率:
  -rh, -rate-http int          允许每秒钟最大http请求数 (default 50)
  -tt, -timeout-tcp duration   TCP连接超时 (default 10s)
  -th, -timeout-http duration  Http连接超时 (default 5s)

更新:
  -update             更新版本
  -ud, -update-dict   更新字典版本
  -um, -update-match  更新指纹识别库

```
# 安装pathScan

pathScan需要**go1.19**才能安装成功。执行一下命令

```sh
go install -v github.com/wjlin0/pathScan@latest
```

或下载准备运行的[二进制文件](https://github.com/wjlin0/pathScan/releases/latest)

<table>
    <tr>
    <td>

**Docker：**

```sh
docker pull wjlin0/path_scan:latest
docker run --rm --name pathScan -it wjlin0/path_scan:latest  -t https://wjlin0.com -vb
```
</td>
</tr>
</table>

<table>
<tr>
<td>

**自行编译：**

```sh
git clone https://github.com/wjlin0/pathScan.git && cd pathScan
go install github.com/goreleaser/goreleaser@latest
goreleaser release --snapshot --skip-publish --skip-docker --rm-dist
```
</td>
</tr>
</table>



# 运行pathScan

```text
pathScan -t https://baidu.com/
# 远程加载
pathScan -t https://www.google.com/ -pr https://raw.githubusercontent.com/wjlin0/pathScan/main/dict/api-user.txt
# 从管道中加载
cat url.txt | pathScan -silent
# 使用搜索引擎
pathScan -uc -ue "fofa" -uq "domain=baidu.com"
# 回复上次扫描
pathScan -resume Hc7wUXRoH2G1RjrNgjB2OMzXlXo1Hg.cfg
# 输出
pathScan -t https://www.baidu.com -csv -output 1.csv
# 自定义请求头
pathScan -t http://www.baidu.com -header User-Agent:pathScan/1.8,Cookie:a=1  -header a:1
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
  - name: "Django"
    matchers:
      - type: word
        part: body
        words:
          - "<title>The install worked successfully! Congratulations!</title>"
          - "Django tried these URL patterns"
          - "Django will display a standard"
```



pathScan 支持默认配置文件位于下面两个路径，它允许您在配置文件中定义任何标志并设置默认值以包括所有扫描。
- $HOME/.config/pathScan/config.yaml
- $HOME/.config/pathScan/provider-config.yaml
- $HOME/.config/pathScan/match-config.yaml

# 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
