package util

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// Unzip 覆盖解压
func Unzip(p string, reader *bytes.Reader) error {

	zipReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return fmt.Errorf("failed to uncompress zip file: %w", err)
	}
	for _, f := range zipReader.File {
		filePath := filepath.Join(p, filepath.Base(f.Name))
		if f.FileInfo().IsDir() {
			err := fileutil.CreateFolders(filePath)
			if err != nil {
				return fmt.Errorf("无法打开压缩包: %w\n", err)
			}
			continue
		}
		file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("打开文件是出错: %w\n", err).Error())
			continue
		}
		fileZip, err := f.Open()
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("读取压缩包出错: %w\n", err).Error())
			continue
		}
		_, err = io.Copy(file, fileZip)
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("写入时文件是出错: %w\n", err).Error())
			continue
		}
	}
	return nil

}

func RandStr(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	strByte := []byte(str)
	result := []byte{}
	rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
	for i := 0; i < length; i++ {
		result = append(result, strByte[rand.Intn(len(strByte))])
	}
	return string(result)
}
func DataRoot(elem ...string) string {
	home, _ := os.UserHomeDir()
	var e []string
	home = filepath.Join(home, ".config", "pathScan")
	e = append(e, home)
	e = append(e, elem...)
	return filepath.Join(e...)
}

func AppendCreate(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
}
