package runner

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/wjlin0/pathScan/pkg/util"
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
	if !(o.Method == "GET" || o.Method == "POST" || o.Method == "HEAD" || o.Method == "PUT" || o.Method == "OPTIONS" || o.Method == "CONNECT") {
		return errors.New(fmt.Sprintf("不支持 %s 该方法", o.Method))
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
	if o.Csv && o.Html {
		return errors.New("不能同时指定 csv 格式和 html 格式")
	}
	return nil
}
