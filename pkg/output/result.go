package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type ResultEvent struct {
	TimeStamp     time.Time           `json:"timestamp" csv:"timestamp"`
	URL           string              `json:"target" csv:"url"`
	Path          string              `json:"path"  csv:"path"`
	Method        string              `json:"method" csv:"method"`
	Title         string              `json:"title" csv:"title"`
	Host          string              `json:"host" csv:"host"`
	A             []string            `json:"A" csv:"a"`
	CNAME         []string            `json:"CNAME" csv:"cname"`
	Status        int                 `json:"status" csv:"status"`
	ContentLength int                 `json:"content-length" csv:"content-length"`
	Server        string              `json:"server" csv:"server"`
	Technology    []string            `json:"technology" csv:"technology"`
	ResponseBody  string              `json:"response" csv:"-"`
	RequestBody   string              `json:"request" csv:"-"`
	OriginRequest bool                `json:"originRequest" csv:"originRequest"`
	Links         []string            `json:"-" csv:"-"`
	Header        map[string][]string `json:"-" csv:"-"`
}

func (tr ResultEvent) String() string {

	switch {
	case strings.HasSuffix(tr.URL, "/") && !strings.HasPrefix(tr.Path, "/"):
		return tr.URL + tr.Path
	case !strings.HasSuffix(tr.URL, "/") && strings.HasPrefix(tr.Path, "/"):
		return tr.URL + tr.Path
	case strings.HasSuffix(tr.URL, "/") && strings.HasPrefix(tr.Path, "/"):
		return tr.URL[:len(tr.URL)-1] + tr.Path
	default:
		return tr.URL + "/" + tr.Path
	}

}

func (tr ResultEvent) EventToStdout() string {
	path := tr.String()
	builder := &strings.Builder{}
	statusCode := tr.Status
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

	if tr.ContentLength != 0 {
		bodyLen := int(tr.ContentLength)
		builder.WriteString(" [")
		builder.WriteString(color.HiWhiteString(strconv.Itoa(bodyLen)))
		builder.WriteRune(']')
	}
	if tr.Host != "" {
		builder.WriteString(" [")
		builder.WriteString(color.HiMagentaString(tr.Host))
		builder.WriteRune(']')
	}
	if len(tr.Technology) != 0 {
		tech := tr.Technology
		builder.WriteString(" [")
		builder.WriteString(color.HiCyanString(strings.Join(tech, ",")))
		builder.WriteRune(']')
	}
	if tr.Title != "" {
		title := tr.Title
		builder.WriteString(" [")
		builder.WriteString(color.HiWhiteString(title))
		builder.WriteRune(']')
	}
	if tr.Server != "" {
		server := tr.Server
		builder.WriteString(" [")

		builder.WriteString(color.HiYellowString(server))
		builder.WriteRune(']')
	}
	return builder.String()
}

func (tr ResultEvent) EventToStdoutNoColor() string {
	path := tr.String()
	builder := &strings.Builder{}
	statusCode := tr.Status
	builder.WriteString(path)
	builder.WriteString(" [")
	builder.WriteString(strconv.Itoa(statusCode))
	builder.WriteRune(']')

	if tr.ContentLength != 0 {
		bodyLen := int(tr.ContentLength)
		builder.WriteString(" [")
		builder.WriteString(strconv.Itoa(bodyLen))
		builder.WriteRune(']')
	}
	if tr.Host != "" {
		builder.WriteString(" [")
		builder.WriteString(tr.Host)
		builder.WriteRune(']')
	}
	if len(tr.Technology) != 0 {
		tech := tr.Technology
		builder.WriteString(" [")
		builder.WriteString(strings.Join(tech, ","))
		builder.WriteRune(']')
	}
	if tr.Title != "" {
		title := tr.Title
		builder.WriteString(" [")
		builder.WriteString(title)
		builder.WriteRune(']')
	}
	if tr.Server != "" {
		server := tr.Server
		builder.WriteString(" [")

		builder.WriteString(server)
		builder.WriteRune(']')
	}
	return builder.String()
}

func (tr ResultEvent) CSV() string {
	buffer := bytes.Buffer{}
	encoder := csv.NewWriter(&buffer)
	var fields []string
	vl := reflect.ValueOf(tr)
	ty := vl.Type()
	for i := 0; i < vl.NumField(); i++ {
		if ty.Field(i).Tag.Get("csv") != "-" {
			fields = append(fields, fmt.Sprint(vl.Field(i).Interface()))
		}

	}
	if err := encoder.Write(fields); err != nil {
		return ""
	}
	encoder.Flush()
	return strings.TrimSpace(buffer.String())
}

func (tr ResultEvent) CSVHeader() ([]byte, error) {
	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)
	ty := reflect.TypeOf(tr)
	var headers []string
	for i := 0; i < ty.NumField(); i++ {
		if ty.Field(i).Tag.Get("csv") != "-" {
			headers = append(headers, ty.Field(i).Tag.Get("csv"))
		}
	}

	if err := writer.Write(headers); err != nil {
		return nil, errors.Wrap(err, "Could not write headers")
	}
	writer.Flush()
	return []byte(strings.TrimSpace(buffer.String())), nil
}
func (tr ResultEvent) HTML() string {
	marshal, _ := json.Marshal(tr)
	return fmt.Sprintf("data.push(%s);", marshal)
}
