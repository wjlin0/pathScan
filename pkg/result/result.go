package result

import (
	"net/url"
	"sync"
)

type TargetResult struct {
	Target  string `json:"target,omitempty" csv:"target"`
	Path    string `json:"path,omitempty"  csv:"path"`
	Title   string `json:"title,omitempty" csv:"title"`
	Status  int    `json:"status,omitempty" csv:"status"`
	BodyLen int    `json:"body_len,omitempty" csv:"body_len"`
	Server  string `json:"server,omitempty" csv:"server"`
}
type Result struct {
	sync.RWMutex
	TargetPaths map[string]map[string]*TargetResult `json:"target_paths,omitempty"`
	Targets     map[string]struct{}                 `json:"targets,omitempty"`
	Skipped     map[string]map[string]struct{}      `json:"skipped,omitempty"`
}

func (tr *TargetResult) ToString() string {
	path, err := url.JoinPath(tr.Target, tr.Path)
	if err != nil {
		return tr.Target
	}
	return path
}

func NewResult() *Result {
	targetPaths := make(map[string]map[string]*TargetResult)
	targets := make(map[string]struct{})
	skipped := make(map[string]map[string]struct{})
	return &Result{TargetPaths: targetPaths, Targets: targets, Skipped: skipped}
}
func (r *Result) GetTargets() chan string {
	r.RLock()
	out := make(chan string)
	go func() {
		defer close(out)
		defer r.RUnlock()
		for target := range r.Targets {
			out <- target
		}
	}()

	return out
}
func (r *Result) GetPathsByTarget() map[string]map[string]*TargetResult {
	r.RLock()
	defer r.RUnlock()

	return r.TargetPaths
}

func (r *Result) RemoveTargets(k string) {
	r.Lock()
	defer r.Unlock()
	delete(r.Targets, k)
}
func (r *Result) HasTargets() bool {
	r.RLock()
	defer r.RUnlock()
	return len(r.Targets) > 0
}
func (r *Result) AddPathByResult(result *TargetResult) {
	r.Lock()
	defer r.Unlock()
	k := result.Target
	v := result.Path
	if _, ok := r.TargetPaths[k]; !ok {
		r.TargetPaths[k] = make(map[string]*TargetResult)
	}
	r.TargetPaths[k][v] = &TargetResult{
		Target:  k,
		Path:    v,
		Title:   result.Title,
		Status:  result.Status,
		BodyLen: result.BodyLen,
		Server:  result.Server,
	}
	r.Targets[k] = struct{}{}
}
func (r *Result) AddPath(k, v, title, location string, status, bodyLen int) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.TargetPaths[k]; !ok {
		r.TargetPaths[k] = make(map[string]*TargetResult)
	}
	r.TargetPaths[k][v] = &TargetResult{
		Target:  k,
		Path:    v,
		Title:   title,
		Status:  status,
		BodyLen: bodyLen,
		Server:  location,
	}
	r.Targets[k] = struct{}{}
}
func (r *Result) GetPathsCount() int {
	r.RLock()
	defer r.RUnlock()
	num := 0
	for _, v := range r.TargetPaths {
		for _, _ = range v {
			num += 1
		}
	}
	return num
}
func (r *Result) HasPath(k string, v string) bool {
	r.RLock()
	defer r.RUnlock()

	_, ok := r.TargetPaths[k]
	if !ok {
		return false
	}
	_, hasport := r.TargetPaths[k][v]

	return hasport
}
func (r *Result) HasPaths() bool {
	r.RLock()
	defer r.RUnlock()
	return len(r.TargetPaths) > 0

}
func (r *Result) AddTarget(target string) {
	r.Lock()
	defer r.Unlock()
	if r.Targets == nil {
		r.Targets = make(map[string]struct{})
	}
	r.Targets[target] = struct{}{}
}
func (r *Result) HasTarget(target string) bool {
	r.RLock()
	defer r.RUnlock()
	_, ok := r.Targets[target]
	return ok
}
func (r *Result) GetPaths() chan *TargetResult {
	r.Lock()
	out := make(chan *TargetResult)
	go func() {
		defer close(out)
		defer r.Unlock()
		for _, targets := range r.TargetPaths {
			for _, path := range targets {
				out <- path
			}
		}
	}()

	return out
}
func (r *Result) IsEmpty() bool {
	return r.Len() == 0
}
func (r *Result) Len() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.Targets)
}

func (r *Result) AddSkipped(k, v string) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.Skipped[k]; !ok {
		r.Skipped[k] = make(map[string]struct{})
	}
	r.Skipped[k][v] = struct{}{}
}
func (r *Result) HasSkipped(target, path string) bool {
	r.RLock()
	defer r.RUnlock()

	_, ok := r.TargetPaths[target]
	if !ok {
		return ok
	}
	_, haspath := r.TargetPaths[target][path]
	return haspath
}
func (r *Result) DelSkipped(target, path string) {
	r.RLock()
	defer r.RUnlock()
	_, ok := r.Skipped[target]
	if !ok {
		return
	}
	_, ok = r.Skipped[target][path]
	if ok {
		delete(r.Skipped[target], path)
	}
	if _, ok = r.Skipped[target]; !ok {
		delete(r.Skipped, target)
	}
}
func (r *Result) GetSkippedCount() int {
	r.RLock()
	defer r.RUnlock()
	num := 0
	for _, v := range r.Skipped {
		for _, _ = range v {
			num += 1
		}
	}
	return num
}
