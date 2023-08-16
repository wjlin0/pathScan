package writer

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"reflect"
	"strings"
)

type CSVWriter struct {
	file *os.File
}

func NewCSVWriter(path string, data interface{}) (*CSVWriter, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("don't open file: %s", err)
	}
	c := &CSVWriter{file: file}
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() == 0 {
		_, err = c.Write([]byte("\xEF\xBB\xBF")) // 解决打开乱码问题 -> utf-8编码
		b, _ := CSVToStringHeader(data)
		_, _ = c.Write(b)
		_, _ = c.Write([]byte("\n"))
	}
	return &CSVWriter{file: file}, nil
}
func CSVToStringHeader(data interface{}) ([]byte, error) {
	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)
	ty := reflect.TypeOf(data)
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

func CSVToString(data interface{}) ([]byte, error) {
	buffer := bytes.Buffer{}
	encoder := csv.NewWriter(&buffer)
	var fields []string
	vl := reflect.ValueOf(data)
	ty := vl.Type()
	for i := 0; i < vl.NumField(); i++ {
		if ty.Field(i).Tag.Get("csv") != "-" {
			fields = append(fields, fmt.Sprint(vl.Field(i).Interface()))
		}

	}
	if err := encoder.Write(fields); err != nil {
		return nil, errors.Wrap(err, "Could not write row")
	}
	encoder.Flush()
	return []byte(strings.TrimSpace(buffer.String())), nil
}
func (c *CSVWriter) Write(b []byte) (int, error) {
	return c.file.Write(b)
}
func (c *CSVWriter) Close() error {
	return c.file.Close()
}
