package runner

func (r *Runner) IsRunPathScanMode() bool {
	return !r.options.Uncover && !r.options.Subdomain && !r.options.Operator
}

func (r *Runner) IsRunUncoverMode() bool {
	return r.options.Uncover
}
func (r *Runner) IsRunSubdomainMode() bool {
	return r.options.Subdomain
}
func (r *Runner) IsRunOperatorMode() bool {
	return r.options.Operator
}

func (r *Runner) DisableAutoPathScan() bool {
	return r.options.DisableAutoPathScan
}
func (r *Runner) DisableAliveCheck() bool {
	return !r.IsRunPathScanMode() || r.options.DisableAliveCheck
}
