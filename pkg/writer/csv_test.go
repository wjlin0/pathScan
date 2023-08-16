package writer

import (
	"github.com/wjlin0/pathScan/pkg/result"
	"testing"
	"time"
)

func TestCSVWriter(t *testing.T) {
	re := result.Result{
		TimeStamp:     time.Now(),
		URL:           "https://www.baidu.com",
		Path:          "/login",
		Title:         "百度知道",
		Host:          "1.1.1.1",
		A:             nil,
		CNAME:         nil,
		Status:        200,
		ContentLength: 1021,
		Server:        "",
		Technology:    nil,
	}
	writer, err := NewCSVWriter("1.csv", result.Result{})
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fields, err := CSVToStringHeader(re)
	if err != nil {
		return
	}
	writer.Write(fields)
}
