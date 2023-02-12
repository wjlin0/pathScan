package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/result"
	"net/url"
)

func (r *Runner) handlerOutputTarget(re *result.TargetResult) {
	path, err := url.JoinPath(re.Target, re.Path)
	if err != nil {
		path = re.Target
	}
	if re.Status == 200 && r.Cfg.Options.Silent {
		gologger.Silent().Msg(path)
	}
	if re.Status == 200 {
		gologger.Info().Msgf("状态码 %d %s 文章标题 %s 页面长度 %d\n", re.Status, path, re.Title, re.BodyLen)
	} else {
		gologger.Verbose().Msgf("状态码 %d %s 文章标题 %s 页面长度 %d\n", re.Status, path, re.Title, re.BodyLen)

	}

}
