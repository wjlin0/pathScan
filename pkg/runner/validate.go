package runner

import (
	"fmt"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	httputil "github.com/projectdiscovery/utils/http"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/wjlin0/pathScan/pkg/common/uncover"
	"github.com/wjlin0/pathScan/pkg/util"
)

func (o *Options) Validate() error {
	if o.RateLimit <= 0 && o.Threads <= 0 {
		return errors.New("没有正确的线程次数")
	}
	if o.Verbose && o.Silent {
		return errors.New("同时指定了详细模式和通道模式")
	}
	if o.Timeout <= 0 {
		return errors.New("时间不能小于0")
	}
	for _, m := range o.Method {
		if !stringsutil.ContainsAny(m, httputil.AllHTTPMethods()...) {
			return fmt.Errorf("error method %s", m)
		}
	}

	if o.SkipHash != "" || o.GetHash {
		_, err := util.GetHash([]byte("1"), o.SkipHashMethod)
		if err != nil {
			return err
		}
	}
	if o.GetHash && len(o.Url) == 0 {
		return errors.New("缺失计算hash的对象")
	}
	if (o.Csv && o.Html) || (o.Csv && o.Silent) || (o.Html && o.Silent) {
		return errors.New("csv、silent、html 同时只能存在一个")
	}
	if o.Subdomain && len(o.SubdomainQuery) < 1 {
		return errors.New("parameter query required")
	}
	if o.Subdomain && o.Path == nil {
		o.Path = []string{"/"}
	}
	if o.Subdomain && o.SubdomainEngine == nil {
		o.SubdomainEngine = uncover.AllAgents()
	}

	if o.Uncover && o.UncoverEngine == nil {
		o.UncoverEngine = []string{"fofa"}
	}
	if o.Method == nil {
		o.Method = []string{"GET"}
	}
	var resolvers []string
	for _, resolver := range o.Resolvers {
		if fileutil.FileExists(resolver) {
			chFile, err := fileutil.ReadFile(resolver)
			if err != nil {
				return errors.Wrapf(err, "Couldn't process resolver file \"%s\"", resolver)
			}
			for line := range chFile {
				resolvers = append(resolvers, line)
			}
		} else {
			resolvers = append(resolvers, resolver)
		}
	}

	o.Resolvers = resolvers
	return nil
}
