package runner

import (
	"fmt"
	"github.com/pkg/errors"
	httputil "github.com/projectdiscovery/utils/http"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/wjlin0/pathScan/pkg/util"
	"github.com/wjlin0/uncover"
)

func (o *Options) ValidateFunc() error {
	if o.RateLimit <= 0 && o.Threads <= 0 {
		return errors.New("没有正确的线程次数")
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
		if _, err := util.GetHash([]byte("1"), o.SkipHashMethod); err != nil {
			return err
		}
	}
	if o.GetHash && len(o.Url) == 0 {
		return errors.New("get hash need url")
	}
	if (o.Csv && o.Html) || (o.Csv && o.Silent) || (o.Html && o.Silent) {
		// 英文提示
		return errors.New("csv, html and silent cannot be used at the same time")
	}
	if o.Subdomain && len(o.SubdomainQuery) < 1 {
		return errors.New("subdomain need subdomain-query")
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
		resolvers = append(resolvers, resolver)
	}

	o.Resolvers = resolvers

	return nil
}
