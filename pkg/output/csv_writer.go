package output

import (
	fileutil "github.com/projectdiscovery/utils/file"
	"io"
	"os"
)

type CSVWriter struct {
	files []*os.File
}

func NewCSVWriter(paths ...string) (*CSVWriter, error) {
	c := &CSVWriter{}
	for _, path := range paths {
		if path == "" {
			continue
		}

		file, err := fileutil.OpenOrCreateFile(path)
		if err != nil {
			return nil, err
		}
		stat, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if stat.Size() == 0 {
			_, err = file.Write([]byte("\xEF\xBB\xBF")) // 解决打开乱码问题 -> utf-8编码
			b, _ := ResultEvent{}.CSVHeader()
			_, _ = file.Write(b)
			_, _ = file.Write([]byte("\n"))

		} else {
			// 移动光标
			_, _ = file.Seek(stat.Size(), io.SeekStart)
		}
		c.files = append(c.files, file)

	}

	return c, nil
}

func (c *CSVWriter) Write(b []byte) (int, error) {
	for _, file := range c.files {
		_, _ = file.Write(b)
	}

	return len(b), nil
}
func (c *CSVWriter) Close() error {
	for _, file := range c.files {
		_ = file.Close()
	}
	return nil
}

func (c *CSVWriter) WriteString(data string) {
	_, _ = c.Write([]byte(data))
}
