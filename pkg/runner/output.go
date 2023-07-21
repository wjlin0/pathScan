package runner

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/runner"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

var NumberOfCsvFieldsErr = errors.New("exported fields don't match csv tags")

func CSVHeaders(data *result.TargetResult) ([]string, error) {
	ty := reflect.TypeOf(*data)
	var headers []string
	for i := 0; i < ty.NumField(); i++ {
		headers = append(headers, ty.Field(i).Tag.Get("csv"))
	}
	if len(headers) != ty.NumField() {
		return nil, NumberOfCsvFieldsErr
	}
	return headers, nil
}

func CSVFields(d *result.TargetResult) ([]string, error) {
	var fields []string
	vl := reflect.ValueOf(*d)
	for i := 0; i < vl.NumField(); i++ {
		fields = append(fields, fmt.Sprint(vl.Field(i).Interface()))
	}
	if len(fields) != vl.NumField() {
		return nil, NumberOfCsvFieldsErr
	}
	return fields, nil
}

func LivingTargetHeader(path *result.TargetResult) (string, error) {
	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)

	headers, err := CSVHeaders(path)
	if err != nil {

	}
	if err := writer.Write(headers); err != nil {
		errMsg := errors.Wrap(err, "Could not write headers")
		return "", errMsg
	}

	writer.Flush()
	return strings.TrimSpace(buffer.String()), nil

}
func LivingTargetRow(path *result.TargetResult) (string, error) {
	buffer := bytes.Buffer{}
	encoder := csv.NewWriter(&buffer)
	path.TimeStamp = time.Now().UTC()
	rowData, err := CSVFields(path)
	if err != nil {
		return "", err
	}
	if err := encoder.Write(rowData); err != nil {
		errMsg := errors.Wrap(err, "Could not write row")
		return "", errMsg
	}
	encoder.Flush()
	return strings.TrimSpace(buffer.String()), nil
}

func InitHtmlOutput(path string) {
	home, _ := os.UserHomeDir()
	jsPath := filepath.Join(home, ".config", "pathScan", "js")
	template, _ := util.ReadFile(filepath.Join(jsPath, "template.html"))
	antdMinCss, _ := util.ReadFile(filepath.Join(jsPath, "antd.min.css"))
	vueMinJs, _ := util.ReadFile(filepath.Join(jsPath, "vue.min.js"))
	antdMinJs, _ := util.ReadFile(filepath.Join(jsPath, "antd.min.js"))
	template = strings.Replace(template, "<!-- antd.min.css -->", fmt.Sprintf("<style>%s</style>", antdMinCss), -1)
	template = strings.Replace(template, "<!-- vue.min.js -->", fmt.Sprintf("<script>%s</script>", vueMinJs), -1)
	template = strings.Replace(template, "<!-- antd.min.js -->", fmt.Sprintf("<script>%s</script>", antdMinJs), -1)
	_ = util.WriteFile(path, template)
}

func HtmlOutput(m map[string]interface{}, path string) {
	outMap := make(map[string]interface{})
	outMap["request"] = m["request"]
	outMap["response"] = m["response"]
	re := m["re"].(*result.TargetResult)
	outMap["target"] = re.Target
	outMap["path"] = re.Path
	outMap["timestamp"] = re.TimeStamp
	outMap["title"] = re.Title
	outMap["status"] = re.Status
	outMap["technology"] = re.Technology
	jsonData, _ := json.Marshal(outMap)
	output := fmt.Sprintf("data.push(%s);\n  //?a", string(jsonData))

	file, _ := util.ReadFile(path)
	output = strings.Replace(file, "//?a", output, 1)
	util.WriteFile(path, output)
}

func (r *Runner) OutputHandler(target, path string, mapResult map[string]interface{}, outputWriter *runner.OutputWriter) {
	targetResult := mapResult["re"].(*result.TargetResult)
	r.Cfg.Results.AddPathByResult(target, path)
	r.handlerOutputTarget(targetResult)
	var outputStr string
	switch {
	case r.Cfg.Options.Csv:
		row, _ := LivingTargetRow(targetResult)
		outputStr = row
	case r.Cfg.Options.Html && r.Cfg.Options.Output != "":
		outputStr = targetResult.ToString()
		r.Cfg.Rwm.Lock()
		HtmlOutput(mapResult, r.Cfg.Options.Output)
		r.Cfg.Rwm.Unlock()
	default:
		outputStr = targetResult.ToString()
	}
	outputWriter.WriteString(outputStr)
}
func checkInitHtml(filepath string) bool {
	// 打开文件
	file, err := os.Open(filepath)
	if err != nil {
		return false
	}
	defer file.Close()

	// 创建一个Scanner来读取文件内容
	scanner := bufio.NewScanner(file)

	// 遍历每一行，查找是否存在目标字符串
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<title>HTML格式报告</title>") {
			return true
		}
	}

	// 如果未找到目标字符串，则返回false
	return false
}
