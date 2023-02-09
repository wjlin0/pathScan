package runner

import (
	"github.com/fatih/color"
	"github.com/projectdiscovery/gologger"
	"io"
	"net/http"
	"pathScan/pkg/result"
	"pathScan/pkg/util"
	"regexp"
	"strconv"
)

func (r *Runner) getResult() {
	for rc := range r.resultChan {
		msg := "状态码" + strconv.Itoa(rc.Status) + " " + rc.TargetPath()
		if rc.Title != "" {
			msg += " 文章标题: " + color.GreenString(rc.Title)
		}
		if rc.BodyLen != 0 {
			msg += " 页面长度:" + strconv.Itoa(rc.BodyLen)
		}
		if rc.Status == 200 {
			gologger.Info().Msg(msg)
		} else if rc.Status < 500 && rc.Status >= 400 {
			gologger.Warning().Msg(msg)
		}
		if r.isTargetIn(rc.TargetPath()) {
			continue
		} else {
			r.Cfg.Rwm.RLock()
			if rc.Ended {
				r.Cfg.Results = append(r.Cfg.Results, rc)
			}
			r.Cfg.Rwm.RUnlock()
		}
	}

}
func (r *Runner) handlerRun(u *result.Result) {
	defer r.wg2.Done()
	defer r.wg.Done()
	reg := regexp.MustCompile(`<title>(.*?)</title>`)
	request, err := http.NewRequest("GET", u.TargetPath(), nil)
	if err != nil {

		r.resultChan <- u
		return
	}

	//fmt.Println(u.TargetPath())
	resp, err := util.ReconDial(r.client, request, 1, r.Cfg.Options.Retries)
	u.Start()
	if err != nil {
		gologger.Warning().Msgf("%s -> %s ", u.TargetPath(), " 重试次数超过 3次")
		r.resultChan <- u
		return
	}
	u.Status = resp.StatusCode

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	u.BodyLen = len(string(body))
	t := reg.FindAllStringSubmatch(string(body), -1)

	if len(t) == 0 {
		u.Title = ""
	} else if len(t[0]) <= 1 {
		u.Title = ""
	} else if len(t[0]) == 2 {
		u.Title = t[0][1]
	}
	if len(body) == 0 {
		u.Title = "该请求内容为0"
	}
	u.End()
	r.resultChan <- u
}
