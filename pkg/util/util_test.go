package util

import (
	"fmt"
	"net/url"
	"testing"
)

func TestIsSubdomainOrSameDomain(t *testing.T) {
	tests := []struct {
		orl   string
		link  string
		valid bool
	}{
		{"https://www.example.com", "https://www.example.com", false},
		{"https://www.example.com", "https://sub.example.com", true},
		{"https://www.example.com", "https://example.com", true},
		{"https://www.example.com:8080", "https://aaa.com", false},
		{"https://example.com:8080", "https://www.example.com", true},
		{"https://example.com", "https://example.com", false},
		{"https://example.com", "https://aa.aaa.example.com", true},
		{"https://1.2.3.4:8080/", "https://1.2.3.4", true},
		{"https://1.2.3.4:8090", "https://1.2.3.5", true},
		{"https://1.2.3.4", "https://example.com", true},
	}

	for _, test := range tests {
		valid := IsSubdomainOrSameDomain(test.orl, test.link)
		if valid != test.valid {
			t.Errorf("Expected IsSubdomainOrSameDomain(%q, %q) to be %t, but got %t", test.orl, test.link, test.valid, valid)
		}
	}
}
func TestExtractURLs(t *testing.T) {
	text := `<p>移步 -&gt; https://book.wjlin0.com 顾大嫂但是</p>
	<footer class="entry-footer">
	  <div class="post-more">
		<a href="https://wjlin0.com/archives/1686209989310">
		  <i class="iconfont icon-caidan"></i>
		</a>
	  </div>
<a href="https://1.1.1.1:888/sss">

`
	urls := ExtractURLs(text)

	// 打印提取到的URL
	for _, url := range urls {
		fmt.Println(url)
	}
}

func TestGetTrueUrl(t *testing.T) {
	var testCases = map[string]string{
		"https://www.wjlin0.com:8090/path/url?a=1":          "https://www.wjlin0.com:8090",
		"https://www.wjlin0.com/path/url?a=1":               "https://www.wjlin0.com",
		"http://example.com":                                "http://example.com",
		"http://example.com:8080/path?param=value":          "http://example.com:8080",
		"https://www.google.com/search?q=url+decoding":      "https://www.google.com",
		"http://127.0.0.1:8080":                             "http://127.0.0.1:8080",
		"https://192.168.0.1":                               "https://192.168.0.1",
		"http://[2001:db8::1]":                              "http://[2001:db8::1]",
		"https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]": "https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
		// 添加更多的测试用例...
	}

	for urlString, expectedResult := range testCases {
		parsedURL, _ := url.Parse(urlString)

		result := GetTrueUrl(parsedURL)
		if result != expectedResult {
			t.Errorf("错误的结果。URL: %s，期望: %s，实际: %s", urlString, expectedResult, result)
		}
	}
}
