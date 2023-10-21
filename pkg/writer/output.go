package writer

import (
	_ "embed"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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

//go:embed js/template.html
var template string

//go:embed js/antd.min.css
var antdMinCss string

//go:embed js/antd.min.js
var antdMinJs string

//go:embed js/vue.min.js
var vueMinJs string

func NewOutputWriters(output string, outType int) (io.Writer, error) {
	var (
		outputWriter io.Writer
		err          error
	)

	switch outType {
	case 1:
		if output != "" {
			outputFolder := filepath.Dir(output)
			if err = os.MkdirAll(outputFolder, 0700); err != nil {
				return nil, err
			}
			outputWriter, err = NewCSVWriter(output, result.Result{})
			if err != nil {
				return nil, err
			}
		}
	case 2:
		if output != "" {
			if !util.FindStringInFile(output, `<title>HTML格式报告</title>`) {

				template2 := strings.Replace(template, "<!-- antd.min.css -->", fmt.Sprintf("<style>%s</style>", antdMinCss), -1)
				template2 = strings.Replace(template2, "<!-- vue.min.js -->", fmt.Sprintf("<script>%s</script>", vueMinJs), -1)
				template2 = strings.Replace(template2, "<!-- antd.min.js -->", fmt.Sprintf("<script>%s</script>", antdMinJs), -1)

				err = util.WriteFile(output, template2)
				if err != nil {
					return nil, err
				}
			}
			outputWriter, err = NewHTMLWriter(output)
			if err != nil {
				return nil, err
			}
		}
	default:
		if output != "" {
			outputFolder := filepath.Dir(output)
			if err = os.MkdirAll(outputFolder, 0700); err != nil {
				return nil, err
			}
			create, err := util.AppendCreate(output)
			if err != nil {
				return nil, err
			}
			outputWriter = create
		}
	}
	return outputWriter, nil
}
