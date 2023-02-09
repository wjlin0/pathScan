package result

import (
	"net/url"
)

type Result struct {
	Target     string
	Path       string
	IsRunning  bool
	NotStarted bool
	Ended      bool
	Title      string
	Status     int
	IsAlive    bool
	BodyLen    int
}

func (r *Result) Start() {
	r.IsRunning = true
	r.NotStarted = false
	r.Ended = false
}
func (r *Result) End() {
	r.Ended = true
	r.NotStarted = false
	r.IsRunning = false
}
func NewResult(targets string) *Result {
	u, _ := url.Parse(targets)
	port := ""
	if u.Port() == "" {
		if u.Scheme == "https" {
			port = "443"
		} else if u.Scheme == "http" {
			port = "80"
		}
	} else {
		port = u.Port()
	}

	t := u.Scheme + "://" + u.Hostname() + ":" + port
	p := u.Path
	return &Result{
		Target:     t,
		Path:       p,
		IsRunning:  false,
		NotStarted: true,
		Ended:      false,
		Title:      "",
		Status:     0,
		IsAlive:    true,
	}
}
func (r *Result) TargetPath() string {
	return r.Target + r.Path
}
