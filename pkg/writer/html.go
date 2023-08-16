package writer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type HTMLWriter struct {
	file         *os.File
	updateOffset int64
}

func NewHTMLWriter(path string) (*HTMLWriter, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("don't open file: %s", err)
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

	return &HTMLWriter{
		file:         file,
		updateOffset: offset,
	}, nil
}

func HTMLToString(data interface{}) ([]byte, error) {
	marshal, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("data.push(%s);", marshal)), nil
}
func (h *HTMLWriter) Write(b []byte) (int, error) {

	// 读取指定位置后面的数据
	var remainingData []byte
	var offset int64
	var err error
	_, err = h.file.Seek(h.updateOffset, io.SeekStart)
	if err != nil {
		return 0, err
	}
	if offset, err = h.file.Seek(0, io.SeekCurrent); err == nil {
		remainingData, _ = io.ReadAll(h.file)
		_, _ = h.file.Seek(offset, io.SeekStart)
	}
	// 将写入的内容和已有数据合并
	output := fmt.Sprintf("%s%s", string(b), remainingData)
	h.updateOffset = offset + int64(len(b))
	return h.file.Write([]byte(output)) //在文件开头写入合并后的内容
}

func (h *HTMLWriter) Close() error {
	return h.file.Close()
}
