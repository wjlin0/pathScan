package runner

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/stringsutil"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/wjlin0/pathScan/pkg/util"
)

func (o *Options) Validate() error {
	if o.RateLimit <= 0 && o.Retries <= 0 && o.Threads <= 0 {
		return errors.New("没有正确的线程次数或正确的重复次数")
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
	return nil
}
