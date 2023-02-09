package runner

import "pathScan/pkg/result"

func (r *Runner) isTargetIn(target string) bool {
	for _, r_ := range r.Cfg.Results {
		if r_.TargetPath() == target {
			return true
		}
	}
	return false
}
func (r *Runner) IsTargetEnd(target string) bool {
	r.Cfg.Rwm.RLock()
	defer r.Cfg.Rwm.RUnlock()
	if !r.isTargetIn(target) {
		return false
	}
	for _, r_ := range r.Cfg.Results {
		if r_.TargetPath() == target {
			if r_.Ended == true {
				return true
			}
		}
	}
	return false
}

func (r *Runner) GetTargetByTarget(target string) (*result.Result, bool) {
	r.Cfg.Rwm.RLock()
	defer r.Cfg.Rwm.RUnlock()
	if !r.isTargetIn(target) {
		return nil, false
	}
	for _, r_ := range r.Cfg.Results {
		if r_.TargetPath() == target {
			return r_, true
		}
	}
	return nil, false
}
