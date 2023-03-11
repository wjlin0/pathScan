package runner

import (
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"io"
	"net/http"
	"strings"
)

func (r *Runner) getAllPaths() map[string]struct{} {
	at := make(map[string]struct{})
	var resp *http.Response
	var err error

	if r.Cfg.Options.Path != nil {
		for _, p := range r.Cfg.Options.Path {
			if _, ok := at[p]; !ok {
				p = strings.TrimSpace(p)
				at[p] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.PathFile != nil {
		for _, p := range r.Cfg.Options.PathFile {
			if _, ok := at[p]; !ok {
				p = strings.TrimSpace(p)
				at[p] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.PathRemote != "" {
		request, _ := http.NewRequest("GET", r.Cfg.Options.PathRemote, nil)
		resp, err = r.client.Do(request)
		if err == nil {
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {

				}
			}(resp.Body)
			body, _ := io.ReadAll(resp.Body)
			for _, p := range strings.Split(string(body), "\n") {
				p = strings.Trim(p, "\r")
				p = strings.Trim(p, "\n")
				if p == "" {
					continue
				}
				if _, ok := at[p]; !ok {
					at[p] = struct{}{}
				}

			}
		}
		gologger.Debug().Msg("从远程加载字典 完成...")
	}

	if len(r.targets) == 1 && r.Cfg.Options.Path == nil && r.Cfg.Options.PathFile == nil && r.Cfg.Options.PathRemote == "" {
		u := r.getFilePath("main.txt")
		if u != nil {
			for _, s := range u {
				at[s] = struct{}{}
			}
		}
	}
	if len(at) == 0 {
		at["/"] = struct{}{}
	}
	return at
}

func (r *Runner) getFilePath(filename string) []string {

	path := DataRoot("dict", "v"+Version, filename)
	out, err := fileutil.ReadFile(path)
	if err != nil {
		return nil
	}
	var str []string
	for o := range out {
		str = append(str, o)
	}
	return str
}
