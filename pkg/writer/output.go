package writer

import (
	"github.com/logrusorgru/aurora"
	"github.com/wjlin0/pathScan/pkg/result"
	"net/http"
	"strconv"
	"strings"
)

type OutputWriter struct {
}

func NewOutputWriter() *OutputWriter {
	return &OutputWriter{}
}

func (o *OutputWriter) Write(b []byte) (int, error) {
	return 0, nil
}

func OutputToString(out *result.Result, nocolor bool) string {
	path := out.ToString()
	builder := &strings.Builder{}
	statusCode := out.Status
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

	if out.ContentLength != 0 {
		bodyLen := int(out.ContentLength)
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Magenta(strconv.Itoa(bodyLen)).String())
		} else {
			builder.WriteString(strconv.Itoa(bodyLen))
		}
		builder.WriteRune(']')
	}
	if out.Host != "" {
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Magenta(out.Host).String())
		} else {
			builder.WriteString(out.Host)
		}
		builder.WriteRune(']')
	}
	if len(out.Technology) != 0 {
		tech := out.Technology
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Green(strings.Join(tech, ",")).String())
		} else {
			builder.WriteString(strings.Join(tech, ","))
		}
		builder.WriteRune(']')
	}
	if out.Title != "" {
		title := out.Title
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.White(title).String())
		} else {
			builder.WriteString(title)
		}
		builder.WriteRune(']')
	}
	if out.Server != "" {
		server := out.Server
		builder.WriteString(" [")
		if !nocolor {
			builder.WriteString(aurora.Cyan(server).String())
		} else {
			builder.WriteString(server)
		}
		builder.WriteRune(']')
	}
	return builder.String()
}
