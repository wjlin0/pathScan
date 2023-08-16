package writer

import (
	"github.com/wjlin0/pathScan/pkg/result"
	"testing"
	"time"
)

func TestHTMLWriter(t *testing.T) {
	writer, err := NewHTMLWriter("template.html")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
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
	toString, err := HTMLToString(re)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	_, err = writer.Write(toString)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	writer.Close()
}
