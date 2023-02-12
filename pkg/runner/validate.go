package runner

import (
	"github.com/pkg/errors"
)

func (o *Options) Validate() error {
	if o.Url == nil && o.UrlFile == nil && o.UrlRemote == "" {
		return errors.New("没有正确的目标")
	}
	if o.RateHttp <= 0 && o.Rate <= 0 && o.Retries <= 0 {
		return errors.New("没有正确的线程次数或正确的重复次数")
	}
	if o.Verbose && o.Silent {
		return errors.New("同时指定了详细输出模式和只输出状态码为200模式")
	}
	return nil
}
