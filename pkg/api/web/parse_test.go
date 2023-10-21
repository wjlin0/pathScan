package web

import "testing"

func TestParseHosts(t *testing.T) {
	// 测试用例1: 包含一个IP地址
	input1 := "Here is an IP address: href='http://192.168.1.1'"
	host1 := "192.168.1.1"
	result1 := parseHosts([]string{host1}, []byte(input1))
	expected1 := []string{"http://192.168.1.1"}
	if !equalSlices(result1, expected1) {
		t.Errorf("Test Case 1: Expected %v, but got %v", expected1, result1)
	}

	// 测试用例2: 包含多个IP地址
	input2 := "Multiple IP addresses: href='https://10.0.0.1' and href='http://192.168.0.2/path'"
	host2 := "10.0.0.1"
	result2 := parseHosts([]string{host2}, []byte(input2))
	expected2 := []string{"https://10.0.0.1"}
	if !equalSlices(result2, expected2) {
		t.Errorf("Test Case 2: Expected %v, but got %v", expected2, result2)
	}

	// 测试用例3: 不包含指定的IP地址
	input3 := "No matching IP address in this text."
	host3 := "192.168.1.1"
	result3 := parseHosts([]string{host3}, []byte(input3))
	if len(result3) != 0 {
		t.Errorf("Test Case 3: Expected an empty result, but got %v", result3)
	}
	// 测试用例4: 包含一个URL
	input4 := "Here is a URL: 'http://example.com'"
	host4 := "example.com"
	result4 := parseHosts([]string{host4}, []byte(input4))
	expected4 := []string{"http://example.com"}
	if !equalSlices(result4, expected4) {
		t.Errorf("Test Case 4: Expected %v, but got %v", expected4, result4)
	}

	// 测试用例5: 包含多个URL
	input5 := "Multiple URLs: 'http://example.com/?sa=123' and 'https://example.com/path'"
	host5 := "example.com"
	result5 := parseHosts([]string{host5}, []byte(input5))
	expected5 := []string{"http://example.com/?sa=123", "https://example.com/path"}
	if !equalSlices(result5, expected5) {
		t.Errorf("Test Case 5: Expected %v, but got %v", expected5, result5)
	}

	// 测试用例6: 不包含指定的host
	input6 := "No matching host in this text."
	host6 := "example.com"
	result6 := parseHosts([]string{host6}, []byte(input6))
	if len(result6) != 0 {
		t.Errorf("Test Case 6: Expected an empty result, but got %v", result6)
	}
}

// 辅助函数，检查两个字符串切片是否相等
func equalSlices(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}
