package query

import (
	"fmt"
	"testing"
)

func TestQuery(t *testing.T) {
	strings, err := Query(10, 100, 3, 10, []string{
		"baidu.com",
	}, []string{"rapiddns"}, "http://localhost:8080", "")
	if err != nil {
		t.Error(err)
		return
	}
	i := 0
	for str := range strings {
		i++
		fmt.Println(i, str)
	}
}
