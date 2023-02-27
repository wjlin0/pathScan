# PathScan
pathScan 是一个用Go编写的路径扫描工具，它允许您快速可靠的扫描URL地址。这是一个非常简单的工具。

## 特征

```console
pathScan -u http://www.google.com/ -ps /docs

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.4
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```

- 快速发现路径
- 可远程加载目标或远程加载字典
- 丰富的内置字典,自动下载字典
- 可恢复上次扫描进度
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
  -u, -url string[]        目标(以逗号分割)
  -uf, -url-file string[]  从文件中,读取目标
  -ur, -url-remote string  从远程加载目标
  -resume string           使用resume.cfg恢复扫描

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
  -nn, -not-new            允许HTTP最新请求
  -clear                   清理历史任务

速率:
  -rl, -rate-limit int  线程 (default 30)
  -rh, -rate-http int   允许每秒钟最大http请求数 (default 100)


清理:
  -clear  清理历史任务
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
chmod +x build_linux.sh
./build_linux
```
## 远程加载
```console
pathScan -u http://www.google.com/ -pr https://raw.githubusercontent.com/wjlin0/pathScan/main/dict/api-user.txt

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.4
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[INF] 从远程加载字典 完成...
[INF] 状态码200 http://www.google.com:80/apis 文章标题: Google Code 页面长度:5325
[INF] 状态码200 http://www.google.com:80/apis/ 文章标题: Google Code 页面长度:5325
```
## 从通道中加载目标
待补充 - 后续见面

## 详细模式
```console
pathScan -u https://google.com -vb

[DBG] 远程字典下载成功-> /root/.config/pathScan/dict

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.4
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[DBG] 发现 https://google.com 存活
[INF] 存活目标总数 -> 1
[INF] 请求总数 -> 18408
[VER] 状态码 301 https://google.com/developer 文章标题  页面长度 229
[VER] 状态码 301 https://google.com/profiles/testing/testing.info 文章标题  页面长度 249
[VER] 状态码 301 https://google.com/technology 文章标题  页面长度 230
[VER] 状态码 301 https://google.com/survey 文章标题  页面长度 226
[VER] 状态码 404 https://google.com/js/tinymce/ 文章标题 Error 404 (Not Found)!!1 页面长度 1572
```
## 只输出200模式
```console
pathScan -u https://google.com -sl
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
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.4
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[WRN] 状态码404 http://www.google.com:80/lyfhtxy 文章标题: Error 404 (Not Found)!!1 页面长度:1568
[WRN] 状态码404 http://www.google.com:80/en/netdu 文章标题: Error 404 (Not Found)!!1 页面长度:1569
[WRN] 状态码404 http://www.google.com:80/a_zbzn 文章标题: Error 404 (Not Found)!!1 页面长度:1567
```
## Csv格式输出
```console
pathScan -u https://www.baidu.com -csv -output 1.csv

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.4
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
```

## 配置文件
pathScan 支持默认配置文件位于`$HOME/.config/pathScan/config.yaml`，它允许您在配置文件中定义任何标志并设置默认值以包括所有扫描。

## 仅主机发现
```console
pathScan -u https://google.com -st

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.4
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[INF] 发现 https://google.com 存活
```
## 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
