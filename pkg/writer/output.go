package writer

import (
	_ "embed"
	"fmt"
	"github.com/fatih/color"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func OutputToString(out *result.Result) string {
	path := out.ToString()
	builder := &strings.Builder{}
	statusCode := out.Status
	builder.WriteString(path)
	builder.WriteString(" [")
	switch {
	case statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices:
		builder.WriteString(color.HiGreenString(strconv.Itoa(statusCode)))
	case statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest:
		builder.WriteString(color.HiYellowString(strconv.Itoa(statusCode)))
	case statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError:
		builder.WriteString(color.HiRedString(strconv.Itoa(statusCode)))
	case statusCode >= http.StatusInternalServerError:
		builder.WriteString(color.HiRedString(strconv.Itoa(statusCode)))
	default:
		builder.WriteString(color.HiYellowString(strconv.Itoa(statusCode)))
	}
	builder.WriteRune(']')

	if out.ContentLength != 0 {
		bodyLen := int(out.ContentLength)
		builder.WriteString(" [")
		builder.WriteString(color.HiWhiteString(strconv.Itoa(bodyLen)))
		builder.WriteRune(']')
	}
	if out.Host != "" {
		builder.WriteString(" [")
		builder.WriteString(color.HiMagentaString(out.Host))
		builder.WriteRune(']')
	}
	if len(out.Technology) != 0 {
		tech := out.Technology
		builder.WriteString(" [")
		builder.WriteString(color.HiCyanString(strings.Join(tech, ",")))
		builder.WriteRune(']')
	}
	if out.Title != "" {
		title := out.Title
		builder.WriteString(" [")
		builder.WriteString(color.HiWhiteString(title))
		builder.WriteRune(']')
	}
	if out.Server != "" {
		server := out.Server
		builder.WriteString(" [")

		builder.WriteString(color.HiYellowString(server))
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
			if err = os.MkdirAll(outputFolder, os.ModePerm); err != nil {
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
			if err = os.MkdirAll(outputFolder, os.ModePerm); err != nil {
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
