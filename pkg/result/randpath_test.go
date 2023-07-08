package result

import (
	"fmt"
	"testing"
)

func TestRandPath(t *testing.T) {
	values1 := []string{"http://baidu.com", "http://wjlin0.com"}
	values2 := []string{"/api/version", "/api/user", "/api/v1"}

	out := Rand(values1, values2)

	for result := range out {
		fmt.Println(result)
	}

	fmt.Println("TestRander completed")
}
