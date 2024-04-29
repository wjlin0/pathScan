package scanner

import (
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/wjlin0/pathScan/v2/pkg/output"
	"github.com/wjlin0/pathScan/v2/pkg/util"
	"strconv"
	"strings"
)

func (scanner *Scanner) autoSkip(event *Response, base *Response) bool {
	if event.StatusCode != 200 {
		for _, status := range checkStatus(scanner.options.BlackStatus) {
			if event.StatusCode == status {
				return true
			}
		}
		for _, status := range checkStatus(scanner.options.WafStatus) {
			if event.StatusCode == status {
				return true
			}
		}

		eventLocation, ok1 := event.Headers["Location"]
		randLocation, ok2 := base.Headers["Location"]
		if event.StatusCode >= 300 && event.StatusCode <= 399 && ok1 && ok2 {
			if strings.Join(eventLocation, "") == strings.Join(randLocation, "") {
				return true
			}
		}
		if event.StatusCode == base.StatusCode {
			return true
		}

	}
	if event.ContentLength == base.ContentLength {
		if event.BodyMd5 == base.BodyMd5 {
			return true
		}
	} else if i := event.ContentLength - base.ContentLength; (i < 16 && i > 0) || (i > -16 && i < 0) {
	} else {

		if strings.Contains(string(base.Data), base.Response.Request.URL.Path) {

		} else {
			return false
		}
	}

	return base.bodyDuplicate(event, 5)

}

func (scanner *Scanner) checkEventSkip(event output.ResultEvent) bool {
	if event.URL == "" {
		return true
	}
	if scanner.options.SkipOutputIsEmpty() {
		return false
	}
	if sliceutil.Contains(scanner.options.SkipCode, strconv.Itoa(event.Status)) {
		return true
	}

	// 循环递归跳过 状态码 例如 5xx 4xx 3xx 500-599 400-499 300-399
	for _, status := range scanner.options.SkipCode {

		if strings.Contains(status, "-") && !strings.Contains(status, "xx") {
			split := strings.Split(status, "-")
			if len(split) != 2 {
				continue
			}
			minStatus, err := strconv.Atoi(split[0])
			if err != nil {
				continue
			}
			maxStatus, err := strconv.Atoi(split[1])
			if err != nil {
				continue
			}
			if event.Status >= minStatus && event.Status <= maxStatus {
				return true
			}
		}
		if strings.Contains(status, "xx") {
			if strings.HasPrefix(status, strconv.Itoa(event.Status)[:1]) {
				return true
			}
		}

	}

	if scanner.options.SkipHash != "" {
		bodyHash, _ := util.GetHash([]byte(event.RequestBody), scanner.options.SkipHashMethod)
		if scanner.options.SkipHash == string(bodyHash) {
			return true
		}
	}
	// 跳过长度逻辑处理
	for _, l := range scanner.options.SkipBodyLen {
		switch strings.Count(l, "-") {
		case 1:
			split := strings.Split(l, "-")
			if len(split) != 2 {
				continue
			}
			minLength, err := strconv.Atoi(split[0])
			if err != nil {
				continue
			}
			maxLength, err := strconv.Atoi(split[1])
			if err != nil {
				continue
			}
			if event.ContentLength >= minLength && event.ContentLength <= maxLength {
				return true
			}
		case 0:
			atoi, err := strconv.Atoi(l)
			if err != nil {
				continue
			}
			if atoi == event.ContentLength {
				return true
			}
		default:
			continue
		}

	}

	for _, l := range scanner.skipBodyRegex {
		// 匹配body
		if l.Match([]byte(event.ResponseBody)) {
			return true
		}
	}

	return false
}

// 状态码处理
func checkStatus(statusSlice []string) []int {
	var statusIntSlice []int

	for _, status := range statusSlice {
		if strings.Contains(status, "-") && !strings.Contains(status, "xx") {
			split := strings.Split(status, "-")
			if len(split) != 2 {
				continue
			}
			minStatus, err := strconv.Atoi(split[0])
			if err != nil {
				continue
			}
			maxStatus, err := strconv.Atoi(split[1])
			if err != nil {
				continue
			}
			if minStatus > maxStatus {
				minStatus, maxStatus = maxStatus, minStatus
			}
			if minStatus < 100 || maxStatus > 999 {
				continue
			}
			for i := minStatus; i <= maxStatus; i++ {
				statusIntSlice = append(statusIntSlice, i)
			}
		}
		if atoi, _ := strconv.Atoi(status[:1]); atoi != 0 && strings.Contains(status, "xx") {
			for i := atoi*100 + 0; i < atoi*100+100; i++ {
				statusIntSlice = append(statusIntSlice, i)
			}
		}
		if atoi, _ := strconv.Atoi(status); atoi >= 100 && atoi <= 999 {
			statusIntSlice = append(statusIntSlice, atoi)
		}

	}
	// 去重
	return sliceutil.Dedupe(statusIntSlice)
}
