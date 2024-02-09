package runner

func (r *Runner) IsRunPathScanMode() bool {
	return len(r.targets) > 1 && !r.options.Uncover && !r.options.Subdomain
}

func (r *Runner) IsRunUncoverMode() bool {
	return r.options.Uncover
}
func (r *Runner) IsRunSubdomainMode() bool {
	return r.options.Subdomain
}
