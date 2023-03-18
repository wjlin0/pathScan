package runner

import (
	"github.com/pkg/errors"
)

func (o *Options) Validate() error {
	if o.RateHttp <= 0 && o.Retries <= 0 {
		return errors.New("没有正确的线程次数或正确的重复次数")
	}
	if o.Verbose && o.Silent {
		return errors.New("同时指定了详细模式和通道模式")
	}
	if o.TimeoutTCP <= 0 && o.TimeoutHttp <= 0 {
		return errors.New("时间不能小于0")
	}

	return nil
}
