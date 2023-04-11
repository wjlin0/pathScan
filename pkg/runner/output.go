package runner

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"github.com/pkg/errors"
	"pathScan/pkg/result"
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
