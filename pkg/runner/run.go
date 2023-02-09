package runner

import (
	"errors"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/pkg/result"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	wg         sizedwaitgroup.SizedWaitGroup
	Cfg        *ResumeCfg
	client     *http.Client
	resultChan chan *result.Result
	goChan     chan *result.Result
	wg2        sync.WaitGroup
}

func NewRun(options *Options) (*Runner, error) {
	run := &Runner{}
	if options.ResumeCfg != "" {
		cfg, err := ParserResumeCfg(options.ResumeCfg)
		if err != nil {
			return nil, err
		} else {
			run.Cfg = cfg
		}
	} else {
		run.Cfg = &ResumeCfg{
			Rwm:     &sync.RWMutex{},
			Options: options,
			Results: []*result.Result{},
		}
	}
	err := run.Cfg.Options.Validate()
	if err != nil {
		return nil, err
	}
	run.Cfg.Options.configureOutput()

	run.client = newClient(run.Cfg.Options)
	run.wg = sizedwaitgroup.New(run.Cfg.Options.Rate)
	run.resultChan = make(chan *result.Result)
	run.goChan = make(chan *result.Result)
	return run, nil
}

func newClient(options *Options) *http.Client {
	t := &http.Transport{}
	if options.Proxy != "" {
		proxyUrl, _ := url.Parse(options.Proxy)
		if options.ProxyAuth != "" {
			proxyUrl.User = url.UserPassword(strings.Split(options.ProxyAuth, ":")[0], strings.Split(options.ProxyAuth, ":")[1])
		}
		t.Proxy = http.ProxyURL(proxyUrl)
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: t,
	}
	return client
}

func (r *Runner) Run() error {
	targets, err := r.getAllTargets()
	if err != nil {
		return err
	}
	PathUrls, err := r.getAllPaths()
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	if err != nil {
		return err
	}
	r.wg.Add()
	go func() {
		defer r.wg.Done()
		for _, u := range targets {
			ur := result.NewResult(u)
			if !r.checkAlive(u) {
				ur.IsAlive = false
			}
			r.goChan <- ur
		}
		close(r.goChan)
	}()
	var urls []string
	for u := range r.goChan {
		if u.IsAlive {
			urls = append(urls, u.TargetPath())
		}
	}
	if len(urls) == 0 {
		gologger.Error().Msgf("没有目标对象存活,请检查网络")
	}
	r.wg.Add()
	go func() {
		defer r.wg.Done()
		ch := make(chan struct{}, r.Cfg.Options.RateHttp)
		for _, p := range PathUrls {
			for _, u := range urls {
				t, _ := url.JoinPath(u, p)
				if t_, ok := r.GetTargetByTarget(t); ok {
					r.resultChan <- t_
					continue
				}
				r.wg.Add()
				ch <- struct{}{}
				r.wg2.Add(1)
				go r.handlerRun(result.NewResult(t))
				<-ch
			}
		}
		r.wg2.Wait()
		close(r.resultChan)
	}()

	r.getResult()
	r.wg.Wait()
	return nil
}

func (r *Runner) getAllTargets() ([]string, error) {
	at := make(map[string]struct{})
	var resp *http.Response
	var err error
	if r.Cfg.Options.Url != nil {
		for _, u := range r.Cfg.Options.Url {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasPrefix(u, "http") {
				u = "http://" + u
			}
			if _, ok := at[u]; !ok {
				at[u] = struct{}{}
			}
		}
	}
	if r.Cfg.Options.UrlFile != nil {
		for _, u := range r.Cfg.Options.UrlFile {
			u = strings.Trim(u, "\r")
			u = strings.Trim(u, "\n")
			if !strings.HasPrefix(u, "http") {
				u = "http://" + u
			}
			if _, ok := at[u]; !ok {
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
				if u == "" {
					continue
				}
				if !strings.HasPrefix(u, "http") {
					u = "http://" + u
				}
				if _, ok := at[u]; !ok {
					at[u] = struct{}{}
				}
			}
		}
	}

	var t []string
	for k, _ := range at {
		t = append(t, k)
	}
	if t == nil {
		e := "不存在目标"
		if err != nil {
			e += ":" + err.Error()
		}
		return nil, errors.New(e)
	}
	return t, nil
}

func (r *Runner) getAllPaths() ([]string, error) {
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
			defer resp.Body.Close()
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
		gologger.Info().Msg("从远程加载字典 完成...")
	}
	if at == nil {
		e := "不存在目标"
		if err != nil {
			e += ":" + err.Error()
		}
		return nil, errors.New(e)
	}
	var t []string
	for k, _ := range at {
		t = append(t, k)

	}
	return t, nil
}

func (r *Runner) getAllURL(ts []string, ps []string) ([]string, error) {
	var us []string
	if ts == nil {
		return nil, errors.New("不存在目标")
	}
	for _, p := range ps {
		for _, t := range ts {
			if !strings.HasPrefix(t, "http") {
				t = "http://" + t
			}
			path, _ := url.JoinPath(t, p)
			us = append(us, path)
		}
	}
	if us == nil {
		return nil, errors.New("不存在目标")
	}
	return us, nil
}
