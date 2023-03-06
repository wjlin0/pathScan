# PathScan
pathScan 是一个用Go编写的路径扫描工具，它允许您快速可靠的扫描URL地址。这是一个非常简单的工具。

## 特征

```console
pathScan -t http://www.google.com/ 

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.5
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```

- 快速发现路径
- 可远程加载目标或远程加载字典
- 丰富的内置字典,自动下载字典
- 可恢复上次扫描进度
- 从网络空间测绘中发现目标
- 支持使用HTTP/SOCKS代理
- 随机UserAgent、证书跳过验证
- Csv输出

## 技术栈
- net/http 实现
- channel 安全通道传输
- sync.RWMutex 高并发下的读写锁实现
- go goroutine 轻量线程
- remeh/sizedwaitgroup 控制并发量
- projectdiscovery/logger 等级输出
- projectdiscovery/goflags 参数管理实现
- projectdiscovery/ratelimit 每秒最多并发量线程控制

## 用法
```shell
pathScan -h
```
```yaml
Usage:
  ./pathScan [flags]

Flags:
输入:
  -t, -target string[]        目标(以逗号分割)
  -tf, -target-file string[]  从文件中,读取目标
  -tr, -target-remote string  从远程加载目标
  -resume string              使用resume.cfg恢复扫描

跳过:
  -su, -skip-url string[]  跳过的目标(以逗号分割)
  -scn, -skip-code-not     不跳过其他状态输出
  -sh, -skip-host          跳过目标验证

扫描字典:
  -ps, -path string[]       路径(以逗号分割)
  -pf, -path-file string[]  从文件中,读取路径
  -pr, -path-remote string  从远程加载字典

输出:
  -o, -output string  输出文件路径（可忽略）
  -c, -csv            csv格式输出
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
  -nn, -not-new            不允许跳转
  -clear                   清理历史任务

引擎:
  -uc, -uncover                  启用打开搜索引擎
  -uq, -uncover-query string[]   搜索查询
  -ue, -uncover-engine string[]  支持的引擎 (shodan,shodan-idb,fofa,censys,quake,hunter,zoomeye,netlas) (default fofa) (default ["fofa"])
  -uf, -uncover-field string     uncover fields to return (ip,port,host) (default "ip:port")
  -ul, -uncover-limit int        发现要返回的结果 (default 200)
  -ucd, -uncover-delay int       打开查询请求之间的延迟（秒）(0 to disable) (default 1)

速率:
  -rh, -rate-http int  允许每秒钟最大http请求数 (default 500)

```
## 安装

下载准备运行的[二进制文件](https://github.com/wjlin0/pathScan/releases/latest)或使用 GO 安装
### GO
```shell
go install -v github.com/wjlin0/pathScan@latest
```
### Docker
```shell
docker pull wjlin0/path_scan:latest
docker run --rm --name pathScan -it wjlin0/path_scan:latest  -u http://baidu.com -vb
```
### 自行编译
```shell
go install github.com/goreleaser/goreleaser@latest
goreleaser release --snapshot --skip-publish --skip-docker --rm-dist
```

## 远程加载
```console
pathScan -t http://www.google.com/ -pr https://raw.githubusercontent.com/wjlin0/pathScan/main/dict/api-user.txt

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.5
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```
## 从通道中加载目标
待补充 - 后续见面
## 从搜索引擎中加载目标
```console
pathScan -uc -ue "fofa" -uq "domain=baidu.com" -ps "api/users"

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.5
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```

## 详细模式
```console
pathScan -t https://google.com -vb

[DBG] 远程字典下载成功-> /root/.config/pathScan/dict

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.5
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```
## 通道模式
```console
pathScan -t https://google.com -sl
https://google.com
https://google.com/partners
```
## 恢复扫描
- 注意使用 回复扫描 其他参数均为上一次启动参数
```console
pathScan -resume Hc7wUXRoH2G1RjrNgjB2OMzXlXo1Hg.cfg

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.5
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```
## Csv格式输出
```console
pathScan -t https://www.baidu.com -csv -output 1.csv

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.5
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```

## 配置文件
pathScan 支持默认配置文件位于下面两个路径，它允许您在配置文件中定义任何标志并设置默认值以包括所有扫描。
- $HOME/.config/pathScan/config.yaml
- $HOME/.config/pathScan/provider-config.yaml

## 仅主机发现
```console
pathScan -t https://google.com -st

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.4
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```
## 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
