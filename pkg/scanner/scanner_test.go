package scanner_test

import (
	"fmt"
	"github.com/wjlin0/pathScan/v2/pkg/input"
	"github.com/wjlin0/pathScan/v2/pkg/output"
	"github.com/wjlin0/pathScan/v2/pkg/scanner"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"os"
	"testing"
)

func TestScanner_ScanOperators(t *testing.T) {
	newScanner, err := scanner.NewScanner(types.DefaultOptions)
	if err != nil {
		return
	}
	os.Setenv("HTTPS_PROXY", "http://localhost:8080")
	newScanner.ScanOperators(&input.Target{
		Host:   "www.wjlin0.com",
		Paths:  []string{"/"},
		Scheme: "https",
	}, func(event output.ResultEvent) {
		fmt.Println(event.EventToStdout())
	})
	//
}
