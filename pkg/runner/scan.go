package runner

import (
	"github.com/projectdiscovery/gologger"
	"io"
)

func (r *Runner) checkAlive(target string) bool {
	r.limiter.Take()
	resp, err := r.client.Get(target)
	if err != nil {
		gologger.Debug().Msgf("%s 请求 失败", target)
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) == "" {
		return false
	}
	return true
}
