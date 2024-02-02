package runner

func (r *Runner) IsRunPathScanMode() bool {
	return (len(r.paths) > 0 && len(r.targets_) > 0 && !r.Cfg.Options.Uncover && !r.Cfg.Options.Subdomain) || r.Cfg.Options.RecursiveRun
}

func (r *Runner) IsRunUncoverMode() bool {
	return r.Cfg.Options.Uncover
}
func (r *Runner) IsRunSubdomainMode() bool {
	return r.Cfg.Options.Subdomain
}
