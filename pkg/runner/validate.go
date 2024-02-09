package runner

import (
	"bufio"
	"fmt"
	"github.com/pkg/errors"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	httputil "github.com/projectdiscovery/utils/http"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	proxyutils "github.com/wjlin0/utils/proxy"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func ValidateRunEnumeration(options *types.Options) error {
	var (
		err error
	)

	// loading the proxy server list from file or cli and test the connectivity
	if err = loadProxyServers(options); err != nil {
		return err
	}

	for _, m := range options.Method {
		if !stringsutil.ContainsAny(m, httputil.AllHTTPMethods()...) {
			return fmt.Errorf("not supported method: %s", m)
		}
	}
	for i, _ := range options.Method {
		options.Method[i] = strings.ToUpper(options.Method[i])
	}
	if !sliceutil.ContainsItems(httputil.AllHTTPMethods(), options.Method) {
		return fmt.Errorf("not supported method: %s", options.Method)
	}
	if options.SkipHash != "" || options.GetHash {
		if _, err = util.GetHash([]byte("1"), options.SkipHashMethod); err != nil {
			return err
		}
	}
	if options.GetHash && len(options.URL) == 0 {
		return errors.New("get-hash need url")
	}

	if (options.CSV && options.HTML) || (options.CSV && options.Silent) || (options.HTML && options.Silent) {
		return errors.New("silent output can't be used with csv or html")
	}

	if options.Subdomain && options.Uncover {
		return errors.New("subdomain and uncover can't be used at the same time")
	}

	if options.Subdomain && len(options.SubdomainQuery) < 1 {
		return errors.New("subdomain need subdomain-query")
	}

	if options.Uncover && len(options.UncoverQuery) < 1 {
		return errors.New("uncover need uncover-query")
	}

	f := func(path string) (output string, err error) {
		file, err := os.Stat(path)
		output = path
		if err == nil && file.IsDir() {
			output = filepath.Join(output, "output."+options.OutputType())
		} else if os.IsNotExist(err) {
			err = fileutil.CreateFolder(filepath.Dir(output))
			if err != nil {
				return "", err
			}
		}

		return output, nil
	}

	if options.Output != "" {
		if options.Output, err = f(options.Output); err != nil {
			return err
		}
	}

	if options.SubdomainOutput != "" {

		if options.SubdomainOutput, err = f(options.SubdomainOutput); err != nil {
			return err
		}
	}

	if options.UncoverOutput != "" {
		if options.UncoverOutput, err = f(options.UncoverOutput); err != nil {
			return err
		}
	}

	return nil
}

func loadProxyServers(options *types.Options) error {
	var (
		file       *os.File
		err        error
		aliveProxy string
		proxyURL   *url.URL
	)

	if len(options.Proxy) == 0 {
		return nil
	}
	proxyList := []string{}
	for _, p := range options.Proxy {
		if fileutil.FileExists(p) {
			if file, err = os.Open(p); err != nil {
				return fmt.Errorf("could not open proxy file: %w", err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if proxy := scanner.Text(); strings.TrimSpace(proxy) == "" {
					continue
				} else {
					proxyList = append(proxyList, proxy)
				}

			}
		} else {
			proxyList = append(proxyList, p)
		}
	}
	aliveProxy, err = proxyutils.GetAnyAliveProxy(options.HttpTimeout, proxyList...)
	if err != nil {
		return err
	}
	proxyURL, err = url.Parse(aliveProxy)
	if err != nil {
		return errorutil.WrapfWithNil(err, "failed to parse proxy got %v", err)
	}
	types.ProxyURL = proxyURL.String()
	return nil
}
