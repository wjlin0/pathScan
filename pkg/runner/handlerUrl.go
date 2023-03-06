package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/pathScan/pkg/common/uncover"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (r *Runner) getAllTargets() []string {
	at := make(map[string]struct{})
	var resp *http.Response
	var err error
	if r.Cfg.Options.Url != nil {
		for _, u := range r.Cfg.Options.Url {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasSuffix(u, "/") {
				u, _ = url.JoinPath(u, "/")
			}
			if !strings.HasPrefix(u, "http") {
				u1 := "http://" + u
				u2 := "https://" + u
				at[u1] = struct{}{}
				at[u2] = struct{}{}
			} else {
				at[u] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.UrlFile != nil {
		for _, u := range r.Cfg.Options.UrlFile {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasSuffix(u, "/") {
				u, _ = url.JoinPath(u, "/")
			}
			if !strings.HasPrefix(u, "http") {
				u1 := "http://" + u
				u2 := "https://" + u
				at[u1] = struct{}{}
				at[u2] = struct{}{}
			} else {
				at[u] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.UrlRemote != "" {
		resp, err = http.Get(r.Cfg.Options.UrlRemote)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			for _, u := range strings.Split(string(body), "\n") {
				u = strings.Trim(u, "\r")
				u = strings.Trim(u, "\n")
				if !strings.HasSuffix(u, "/") {
					u, _ = url.JoinPath(u, "/")
				}
				if !strings.HasPrefix(u, "http") {
					u1 := "http://" + u
					u2 := "https://" + u
					at[u1] = struct{}{}
					at[u2] = struct{}{}
				} else {
					at[u] = struct{}{}
				}
			}
		}
	}
	if r.Cfg.Options.Uncover && r.Cfg.Options.UncoverQuery != nil {
		gologger.Info().Msgf("正在运行: %s", strings.Join(r.Cfg.Options.UncoverEngine, ","))
		ch, _ := uncover.GetTargetsFromUncover(r.Cfg.Options.UncoverDelay, r.Cfg.Options.UncoverLimit, r.Cfg.Options.UncoverField, r.Cfg.Options.UncoverEngine, r.Cfg.Options.UncoverQuery)
		if err != nil {
			gologger.Error().Label("WRN").Msg(err.Error())
		}
		for c := range ch {
			c = strings.Trim(c, "\r")
			c = strings.Trim(c, "\n")
			if c == "" {
				continue
			}
			if !strings.HasPrefix(c, "http") {
				c1 := "http://" + c
				c = "https://" + c
				if !strings.HasSuffix(c1, "/") {
					c1, _ = url.JoinPath(c1, "/")
				}
				at[c1] = struct{}{}
			}
			if !strings.HasSuffix(c, "/") {
				c, _ = url.JoinPath(c, "/")
			}
			at[c] = struct{}{}
		}
	}
	for _, skip := range r.Cfg.Options.SkipUrl {
		delete(at, skip)
	}

	var t []string

	for k, _ := range at {
		t = append(t, k)
	}
	return t
}
