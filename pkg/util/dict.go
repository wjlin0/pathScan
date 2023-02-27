package util

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"io"
	"os"
	"path/filepath"
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
