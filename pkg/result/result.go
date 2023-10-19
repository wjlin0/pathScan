package result

import (
	"net/url"
	"time"
)

type Result struct {
	TimeStamp     time.Time           `json:"timestamp" csv:"timestamp"`
	URL           string              `json:"target" csv:"url"`
	Path          string              `json:"path"  csv:"path"`
	Method        string              `json:"method" csv:"method"`
	Title         string              `json:"title" csv:"title"`
	Host          string              `json:"host" csv:"host"`
	A             []string            `json:"A" csv:"a"`
	CNAME         []string            `json:"CNAME" csv:"cname"`
	Status        int                 `json:"status" csv:"status"`
	ContentLength int                 `json:"content-length" csv:"content-length"`
	Server        string              `json:"server" csv:"server"`
	Technology    []string            `json:"technology" csv:"technology"`
	ResponseBody  string              `json:"response" csv:"-"`
	RequestBody   string              `json:"request" csv:"-"`
	Links         []string            `json:"-" csv:"-"`
	Header        map[string][]string `json:"-" csv:"-"`
}

func (tr *Result) ToString() string {
	path, err := url.JoinPath(tr.URL, tr.Path)
	if err != nil {
		return tr.URL
	}
	return path
}

type Target struct {
	Host       string
	CustomIP   string
	CustomHost string
}
