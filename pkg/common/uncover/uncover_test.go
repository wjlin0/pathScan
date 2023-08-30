package uncover

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"testing"
)

func TestGetTarget(t *testing.T) {
	var (
		err        error
		countArray []string
		target     <-chan string
	)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	target, err = GetTarget(1000, "host", false, "1.csv", []string{"sitedossier"}, []string{"knownsec.com"}, "http://localhost:8080", "")
	if err != nil {
		t.Errorf("rapiddns error:%s", err)
		return
	}
	for result := range target {
		countArray = append(countArray, result)

	}
	if len(countArray) == 0 {
		t.Errorf("sitedossier error")
	}
	fmt.Println(countArray)

}
