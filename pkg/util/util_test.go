package util

import (
	"fmt"
	http "github.com/projectdiscovery/retryablehttp-go"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestGetMainDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"www.wjlin0.com", "wjlin0.com"},
		{"www.wjlin0.com.cn", "wjlin0.com.cn"},
		{"google.www.wjlin0.com", "wjlin0.com"},
		{"test.com", "test.com"},
		{"subdomain.test.com", "test.com"},
		{"example.co.uk", "example.co.uk"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := GetMainDomain(test.input)
			if result != test.expected {
				t.Errorf("Expected %s, but got %s", test.expected, result)
			}
		})
	}
}
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
		{"https://www.baidu.com", "baidu.com/more", true},
	}

	for _, test := range tests {
		valid := IsSubdomainOrSameDomain(test.orl, test.link)
		if valid != test.valid {
			t.Errorf("Expected IsSubdomainOrSameDomain(%q, %q) to be %t, but got %t", test.orl, test.link, test.valid, valid)
		}
	}
}
func TestExtractHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"www.baidu.com/more", "www.baidu.com"},
		{"baidu.com:8080/path", "baidu.com:8080"},
		{"baidu.com", "baidu.com"},
		{"example.com/path", "example.com"},
		{"https://www.example.com/path", "www.example.com"},
		{"https://www.example.com:8080", "www.example.com:8080"},
	}

	for _, test := range tests {
		result := ExtractHost(test.input)
		if result != test.expected {
			t.Errorf("Input: %s, Expected: %s, Got: %s", test.input, test.expected, result)
		}
	}
}
func TestListFilesWithExtension(t *testing.T) {
	dir, _ := os.UserHomeDir()
	dir = filepath.Join(dir, "nuclei-templates")
	fmt.Println(ListFilesWithExtension(dir, ".yaml"))
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

func TestGetRequestPackage(t *testing.T) {
	request, err := http.NewRequest("GET", "https://www.wjlin0.com/", "a=1")
	if err != nil {
		return
	}
	request.Header.Add("Authorization", "none")
	fmt.Println(GetRequestPackage(request))

}
func TestGetResponsePackage(t *testing.T) {
	response, err := http.DefaultClient().Get("https://www.wjlin0.com/")
	if err != nil {
		return
	}
	if err != nil {
		return
	}
	fmt.Println(GetResponsePackage(response, nil, false))
}
