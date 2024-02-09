package output

import (
	"bytes"
	_ "embed"
	"fmt"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"io"
	"os"
	"strings"
)

//go:embed js/template.html
var template string

//go:embed js/antd.min.css
var antdMinCss string

//go:embed js/antd.min.js
var antdMinJs string

//go:embed js/vue.min.js
var vueMinJs string

type HTMLWriter struct {
	files        []*os.File
	updateOffset []int64
}

func NewHTMLWriter(paths ...string) (*HTMLWriter, error) {
	html := &HTMLWriter{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		template2 := strings.Replace(template, "<!-- antd.min.css -->", fmt.Sprintf("<style>%s</style>", antdMinCss), -1)
		template2 = strings.Replace(template2, "<!-- vue.min.js -->", fmt.Sprintf("<script>%s</script>", vueMinJs), -1)
		template2 = strings.Replace(template2, "<!-- antd.min.js -->", fmt.Sprintf("<script>%s</script>", antdMinJs), -1)

		file, err := fileutil.OpenOrCreateFile(path)
		if err != nil {
			return nil, err
		}
		if !util.FindStringInFile(path, `<title>HTML格式报告</title>`) {
			_, err = file.WriteString(template2)
			if err != nil {
				return nil, err
			}
		}

		// 定位到指定位置
		offset, err := func(file *os.File, target string) (int64, error) {
			stat, err := file.Stat()
			if err != nil {
				return 0, err
			}

			fileSize := stat.Size()
			bufferSize := 1024 // 可根据需要调整缓冲区大小
			buffer := make([]byte, bufferSize)
			offset := int64(0)

			for offset < fileSize {
				n, readErr := file.ReadAt(buffer, offset)
				if readErr != nil {
					return 0, readErr
				}
				if index := bytes.Index(buffer[:n], []byte(target)); index != -1 {
					return offset + int64(index), nil
				}

				offset += int64(n)
			}
			return 0, fmt.Errorf("not find target")
		}(file, "//?a")
		if err != nil || offset == 0 {
			return nil, fmt.Errorf("don't find offset : %s", err)
		}

		// 将文件指针移动到偏移位置后
		_, err = file.Seek(offset, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("cann't set offset: %s", err)
		}
		html.files = append(html.files, file)
		html.updateOffset = append(html.updateOffset, offset)
	}
	return html, nil
}

func (h *HTMLWriter) Write(b []byte) (int, error) {

	for i, _ := range h.files {
		// 读取指定位置后面的数据
		var remainingData []byte
		var offset int64
		var err error
		_, err = h.files[i].Seek(h.updateOffset[i], io.SeekStart)
		if err != nil {
			continue
		}

		if offset, err = h.files[i].Seek(0, io.SeekCurrent); err == nil {
			remainingData, _ = io.ReadAll(h.files[i])
			_, _ = h.files[i].Seek(offset, io.SeekStart)
		}
		// 将写入的内容和已有数据合并
		str := fmt.Sprintf("%s%s", string(b), remainingData)
		h.updateOffset[i] = offset + int64(len(b))
		_, _ = h.files[i].Write([]byte(str))
	}

	return len(b), nil
}

func (h *HTMLWriter) Close() error {
	for _, file := range h.files {
		_ = file.Close()
	}
	return nil
}

func (h *HTMLWriter) WriteString(data string) {
	_, _ = h.Write([]byte(data))
}
