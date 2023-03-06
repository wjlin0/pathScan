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
		server := re.Server
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Cyan(server).String())
		} else {
			builder.WriteString(server)
		}
		builder.WriteRune(']')
	}

	fmt.Println(builder.String())

}
