package web

import (
	"bytes"
	"fmt"
	"github.com/wjlin0/pathScan/pkg/util"
	"regexp"
)

func parseHosts(hosts []string, data ...[]byte) (urls []string) {
	var buffer bytes.Buffer
	for i, _ := range data {
		buffer.Write(data[i])
	}
	//var lists []string
	body := buffer.String()
	// 找到 host 的其他路径
	for _, host := range hosts {
		// 正则可视化: https://regex.wjlin0.com/?r=%28%3f%3a%3e%7c%22%7c%27%7c%3d%7c%2c%29%28%68%74%74%70%73%3f%3a%2f%2f%28%3f%3a%5b%61%2d%7a%30%2d%39%5d%28%3f%3a%5b%61%2d%7a%30%2d%39%2d%5d%7b%30%2c%36%31%7d%5b%61%2d%7a%30%2d%39%5d%29%3f%5c%2e%29%7b%30%2c%7d%25%73%28%3f%3a%3a%5b%30%2d%39%5d%7b%31%2c%35%7d%29%3f%28%2f%5c%53%2a%3f%29%3f%7c%68%74%74%70%73%3f%3a%2f%2f%28%3f%3a%32%35%5b%30%2d%35%5d%7c%32%5b%30%2d%34%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%7c%5b%31%2d%39%5d%29%5c%2e%28%3f%3a%32%35%5b%30%2d%35%5d%7c%32%5b%30%2d%34%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%7c%5b%31%2d%39%5d%29%5c%2e%28%3f%3a%32%35%5b%30%2d%35%5d%7c%32%5b%30%2d%34%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%7c%5b%31%2d%39%5d%29%5c%2e%28%3f%3a%32%35%5b%30%2d%35%5d%7c%32%5b%30%2d%34%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%5b%30%2d%39%5d%7c%31%5b%30%2d%39%5d%7c%5b%31%2d%39%5d%29%28%3f%3a%3a%5b%30%2d%39%5d%7b%31%2c%35%7d%29%3f%28%3f%3a%2f%5c%53%2a%3f%29%3f%29%28%3f%3a%3c%7c%22%7c%27%7c%2c%29
		regexHost := regexp.MustCompile(fmt.Sprintf(`(?i)(?:>|"|'|=|,)(https?://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){0,}%s(?::[0-9]{1,5})?(/\S*?)?|https?://(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|1[0-9]|[1-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|1[0-9]|[1-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|1[0-9]|[1-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|1[0-9]|[1-9])(?::[0-9]{1,5})?(?:/\S*?)?)(?:<|"|'|,)`, regexp.QuoteMeta(host)))
		lists := regexHost.FindAllString(body, -1)
		for _, list := range lists {
			if len(list) < 2 {
				continue
			}
			urls = append(urls, list[1:len(list)-1])
		}
	}
	return util.RemoveDuplicateStrings(urls)
}
