package runner

import (
	"bufio"
	_ "embed"
	"fmt"
	"github.com/corpix/uarand"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"github.com/wjlin0/uncover/sources"
	"os"
	"strings"
)

const (
	HeaderKeyUserAgent     = "User-Agent"
	HeaderKeyCookie        = "Cookie"
	HeaderKeyAuthorization = "Authorization"
)

func handlerHeaders(opts *types.Options) map[string]interface{} {
	headerMap := make(map[string]interface{})

	if len(opts.UserAgent) > 0 {
		headerMap[HeaderKeyUserAgent] = []string(opts.UserAgent)
	}
	if opts.Cookie != "" {
		headerMap[HeaderKeyCookie] = opts.Cookie
	}
	if opts.Authorization != "" {
		headerMap[HeaderKeyAuthorization] = opts.Authorization
	}

	for _, header := range append(opts.Header) {
		split := strings.SplitN(header, ":", 2)
		if len(split) == 2 {
			headerMap[strings.TrimSpace(split[0])] = strings.TrimSpace(split[1])
		}
	}

	if userAgent, ok := headerMap[HeaderKeyUserAgent]; !ok || len(userAgent.([]string)) == 0 {
		headerMap[HeaderKeyUserAgent] = uarand.GetRandom()
	}
	headerMap["Accept-Charset"] = "utf-8"
	return headerMap
}

//go:embed dict/main.txt
var mainTxt string

//go:embed dict/api.txt
var apiTxt string

func handlerPaths(opts *types.Options) []string {

	var paths []string

	// 处理 Path 和 PathFile
	for _, path := range append(opts.Path, opts.PathList...) {
		paths = append(paths, path)
	}

	if opts.LoadAPIDict {
		for _, path := range strings.Split(apiTxt, "\n") {
			paths = append(paths, strings.TrimSpace(path))
		}
	}

	// 如果未指定路径，则处理默认文件名
	if len(paths) == 0 && !opts.Operator && !opts.Subdomain && !opts.Uncover && opts.Path == nil && opts.PathList == nil {
		for _, path := range strings.Split(mainTxt, "\n") {
			paths = append(paths, strings.TrimSpace(path))
		}
	}

	// 如果没有添加任何路径，则将根目录添加到结果中
	if len(paths) == 0 {
		paths = append(paths, "/")
	}
	return paths
}

func handlerTargets(opts *types.Options) []string {
	var targets []string
	// 处理 Url 和 UrlFile
	for _, url := range append(opts.URL, opts.List...) {
		targets = append(targets, url)
	}

	// 处理从标准输入读取的 URL
	if opts.Stdin {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			if u := strings.TrimSpace(s.Text()); u != "" {
				targets = append(targets, u)
			}

		}
		_ = os.Stdin.Close()
	}
	return targets
}

func initPathScan() error {
	var (
		err error
	)
	// 判断 DefaultPathScanDir 是否存在 若不存在则创建目录
	if _, err = os.Stat(DefaultPathScanDir); os.IsNotExist(err) {
		if err = os.MkdirAll(DefaultPathScanDir, os.ModePerm); err != nil {
			return fmt.Errorf("create pathScan config directory error: %s", err.Error())
		}
	}

	if !fileutil.FileExists(DefaultProviderConfigLocation) {
		if err = fileutil.Marshal(fileutil.YAML, []byte(DefaultProviderConfigLocation), sources.Provider{}); err != nil {
			return err
		}
	}
	// 解决不出网时无法运行的问题
	//if !fileutil.FileExists(filepath.Join(DefaultMatchDir, ".version")) {
	//	_ = updateutils.GetUpdateDirFromRepoCallback(pathScanMatchRepoName, DefaultMatchDir, pathScanMatchRepoName)()
	//}

	return nil
}
