package runner

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/wjlin0/pathScan/pkg/result"
	"net/http"
	"strconv"
	"strings"
)

func (r *Runner) handlerOutputTarget(re *result.TargetResult) {
	path := re.ToString()
	nocolor := r.Cfg.Options.NoColor
	builder := &strings.Builder{}
	builder.WriteString(path)
	statusCode := re.Status
	skip := r.Cfg.Options.Skip404And302
	if !skip && (statusCode == 404 || statusCode == 302 || statusCode == 301) && !r.Cfg.Options.Verbose {
		return
	}
	if !r.Cfg.Options.Silent {
		builder.WriteString(" [")
		if !nocolor {
			switch {
			case statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices:
				builder.WriteString(aurora.Green(strconv.Itoa(statusCode)).String())
			case statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest:
				builder.WriteString(aurora.Yellow(strconv.Itoa(statusCode)).String())
			case statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError:
				builder.WriteString(aurora.Red(strconv.Itoa(statusCode)).String())
			case statusCode > http.StatusInternalServerError:
				builder.WriteString(aurora.Bold(aurora.Yellow(strconv.Itoa(statusCode))).String())
			}
		} else {
			builder.WriteString(strconv.Itoa(statusCode))
		}
		builder.WriteRune(']')

		bodyLen := re.BodyLen
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Magenta(strconv.Itoa(bodyLen)).String())
		} else {
			builder.WriteString(strconv.Itoa(bodyLen))
		}
		builder.WriteRune(']')

		title := re.Title
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Cyan(title).String())
		} else {
			builder.WriteString(title)
		}
		builder.WriteRune(']')
		location := re.Location
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Cyan(location).String())
		} else {
			builder.WriteString(location)
		}
		builder.WriteRune(']')
	}

	fmt.Println(builder.String())
	//if re.Status == 200 && r.Cfg.Options.Silent {
	//	gologger.Silent().Msg(path)
	//}
	//if re.Status == 200 {
	//	gologger.Info().Msgf("状态码 %d %s 文章标题 %s 页面长度 %d\n", re.Status, path, re.Title, re.BodyLen)
	//} else {
	//	gologger.Verbose().Msgf("状态码 %d %s 文章标题 %s 页面长度 %d\n", re.Status, path, re.Title, re.BodyLen)
	//
	//}

}
