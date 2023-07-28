package runner

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/wjlin0/pathScan/pkg/result"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

var cacheString = make(map[string]struct{})
var lock = sync.Mutex{}

func (r *Runner) handlerOutputTarget(re *result.TargetResult) {
	path := re.ToString()
	lock.Lock()
	if _, ok := cacheString[path]; ok {
		lock.Unlock()
		return
	}
	cacheString[path] = struct{}{}
	lock.Unlock()
	nocolor := r.Cfg.Options.NoColor
	builder := &strings.Builder{}

	statusCode := re.Status
	switch {
	case !r.Cfg.Options.Silent && r.Cfg.Options.Csv:
		row, _ := LivingTargetRow(re)
		builder.WriteString(row)
	case !r.Cfg.Options.Silent && !r.Cfg.Options.Csv:
		builder.WriteString(path)
		builder.WriteString(" [")
		if !nocolor {
			switch {
			case statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices:
				builder.WriteString(aurora.Green(strconv.Itoa(statusCode)).String())
			case statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest:
				builder.WriteString(aurora.Yellow(strconv.Itoa(statusCode)).String())
			case statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError:
				builder.WriteString(aurora.Red(strconv.Itoa(statusCode)).String())
			case statusCode >= http.StatusInternalServerError:
				builder.WriteString(aurora.Bold(aurora.Yellow(strconv.Itoa(statusCode))).String())
			default:
				builder.WriteString(aurora.Bold(aurora.Yellow(strconv.Itoa(statusCode))).String())
			}
		} else {
			builder.WriteString(strconv.Itoa(statusCode))
		}
		builder.WriteRune(']')

		if re.ContentLength != 0 {
			bodyLen := int(re.ContentLength)
			builder.WriteString(" [")
			if !nocolor {
				builder.WriteString(aurora.Magenta(strconv.Itoa(bodyLen)).String())
			} else {
				builder.WriteString(strconv.Itoa(bodyLen))
			}
			builder.WriteRune(']')
		}
		if re.Host != "" {
			builder.WriteString(" [")
			if !nocolor {
				builder.WriteString(aurora.Magenta(re.Host).String())
			} else {
				builder.WriteString(re.Host)
			}
			builder.WriteRune(']')
		}
		if len(re.Technology) != 0 {
			tech := re.Technology
			builder.WriteString(" [")
			if !nocolor {
				builder.WriteString(aurora.Green(strings.Join(tech, ",")).String())
			} else {
				builder.WriteString(strings.Join(tech, ","))
			}
			builder.WriteRune(']')
		}
		if re.Title != "" {
			title := re.Title
			builder.WriteString(" [")
			if !nocolor {
				builder.WriteString(aurora.White(title).String())
			} else {
				builder.WriteString(title)
			}
			builder.WriteRune(']')
		}
		if re.Server != "" {
			server := re.Server
			builder.WriteString(" [")
			if !nocolor {
				builder.WriteString(aurora.Cyan(server).String())
			} else {
				builder.WriteString(server)
			}
			builder.WriteRune(']')
		}
	case r.Cfg.Options.Silent:
		builder.WriteString(path)
	}

	fmt.Println(builder.String())

}
