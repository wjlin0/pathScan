#
pathScan 是一个用Go编写的路径扫描工具，它允许您快速可靠的扫描URL地址。这是一个非常简单的工具。

## 特征

```console
pathScan -u http://www.google.com/ -ps /docs

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[INF] 状态码200 http://www.google.com:80/docs 文章标题: Sign in - Google Accounts 页面长度:144418
```

- 快速发现路径
- 可远程加载目标或远程加载字典
- 丰富的内置字典
- 可恢复上次扫描进度
- 支持使用HTTP/SOCKS代理
- 智能识别目标地址 (example.com 和http://example.com/ 以及http://example.com 都不会报错)
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

扫描字典:
   -ps, -path string[]       路径(以逗号分割)
   -pf, -path-file string[]  从文件中,读取路径
   -pr, -path-remote string  从远程加载字典

输出:
   -o, -output string  输出文件路径（可忽略）
   -nc, -no-color      无颜色输出
   -vb, -verbose       详细输出模式
   -sl, -silent        只输出状态码为200

配置:
   -rs, -retries int        重试3次 (default 3)
   -p, -proxy string        代理
   -pa, -proxy-auth string  代理认证，以冒号分割（username:password）

速率:
   -rl, -rate-limit int  线程(默认150) (default 150)
```
## 安装

下载准备运行的[二进制文件](https://github.com/wjlin0/pathScan/releases/latest)或使用 GO 安装
### GO
```shell
go install -v github.com/wjlin0/pathScan
```
## 远程加载
```console
pathScan -u http://www.google.com/ -pr https://raw.githubusercontent.com/wjlin0/pathScan/main/dict/api-user.txt

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[INF] 从远程加载字典 完成...
[INF] 状态码200 http://www.google.com:80/apis 文章标题: Google Code 页面长度:5325
[INF] 状态码200 http://www.google.com:80/apis/ 文章标题: Google Code 页面长度:5325```
```

## 详细模式
```console
pathScan -u http://www.google.com/ -ps /docs,/api/user -vb

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[WRN] 状态码404 http://www.google.com:80/api/user 文章标题: Error 404 (Not Found)!!1 页面长度:1569
[INF] 状态码200 http://www.google.com:80/docs 文章标题: Sign in - Google Accounts 页面长度:144550
```
## 恢复扫描
- 注意使用 回复扫描 其他参数均为上一次启动参数
```console
pathScan -resume Hc7wUXRoH2G1RjrNgjB2OMzXlXo1Hg.cfg

               __   __    ____
   ___  ___ _ / /_ / /   / __/____ ___ _ ___
  / _ \/ _  // __// _ \ _\ \ / __// _  // _ \
 / .__/\_,_/ \__//_//_//___/ \__/ \_,_//_//_/  v1.0.0
/_/

                        wjlin0.com

慎用。你要为自己的行为负责
开发者不承担任何责任，也不对任何误用或损坏负责.
[WRN] 状态码404 http://www.google.com:80/lyfhtxy 文章标题: Error 404 (Not Found)!!1 页面长度:1568
[WRN] 状态码404 http://www.google.com:80/en/netdu 文章标题: Error 404 (Not Found)!!1 页面长度:1569
[WRN] 状态码404 http://www.google.com:80/a_zbzn 文章标题: Error 404 (Not Found)!!1 页面长度:1567
```
## 配置文件
pathScan 支持默认配置文件位于$HOME/.config/pathScan/config.yaml，它允许您在配置文件中定义任何标志并设置默认值以包括所有扫描。

## 主机排除
pathScan 自动探测主机存货情况并排除访问失败的URL
## 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
