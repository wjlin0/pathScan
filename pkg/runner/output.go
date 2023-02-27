package runner

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/result"
	"io"
	"net/url"
	"reflect"
	"strings"
	"time"
)

func WriteTargetOutput(target string, paths map[string]*result.TargetResult, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}
	for _, path := range paths {
		joinPath, err := url.JoinPath(target, path.Path)
		if err != nil {
			joinPath = target + path.Path
		}
		sb.WriteString(joinPath)
		sb.WriteString("\n")
		_, err = bufwriter.WriteString(sb.String())
		if err != nil {
			_ = bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

type CsvData struct {
	TargetPath string    `json:"target_path,omitempty" csv:"target_path"`
	Title      string    `json:"title,omitempty" csv:"title"`
	Status     int       `json:"status,omitempty" csv:"status"`
	BodyLen    int       `json:"body_len,omitempty" csv:"body_len"`
	Location   string    `json:"location,omitempty" csv:"location"`
	TimeStamp  time.Time `json:"timestamp" csv:"timestamp"`
}

var NumberOfCsvFieldsErr = errors.New("exported fields don't match csv tags")

func (d *CsvData) CSVHeaders() ([]string, error) {
	ty := reflect.TypeOf(*d)
	var headers []string
	for i := 0; i < ty.NumField(); i++ {
		headers = append(headers, ty.Field(i).Tag.Get("csv"))
	}
	if len(headers) != ty.NumField() {
		return nil, NumberOfCsvFieldsErr
	}
	return headers, nil
}

func WriteTargetCsv(paths map[string]*result.TargetResult, header bool, writer io.Writer) error {
	encoder := csv.NewWriter(writer)

	if header {
		writeCSVHeaders(&CsvData{
			TimeStamp: time.Now().UTC(),
		}, encoder)
	}
	for _, path := range paths {
		data := &CsvData{
			TimeStamp: time.Now().UTC(),
		}
		joinPath, err := url.JoinPath(path.Target, path.Path)
		if err != nil {
			joinPath = path.Target
		}
		data.TargetPath = joinPath
		data.Location = path.Location
		data.Title = path.Title
		data.BodyLen = path.BodyLen
		data.Status = path.Status
		writeCSVRow(data, encoder)
	}
	encoder.Flush()
	return nil
}
func writeCSVRow(data *CsvData, writer *csv.Writer) {
	rowData, err := data.CSVFields()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	if err := writer.Write(rowData); err != nil {
		errMsg := errors.Wrap(err, "Could not write row")
		gologger.Error().Msgf(errMsg.Error())
	}
}
func (d *CsvData) CSVFields() ([]string, error) {
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
func writeCSVHeaders(data *CsvData, writer *csv.Writer) {
	headers, err := data.CSVHeaders()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	if err := writer.Write(headers); err != nil {
		errMsg := errors.Wrap(err, "Could not write headers")
		gologger.Error().Msgf(errMsg.Error())
	}
}
