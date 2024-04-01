package runner

import (
	_ "embed"
	"github.com/fatih/color"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/remeh/sizedwaitgroup"
	"github.com/wjlin0/pathScan/v2/pkg/input"
	"github.com/wjlin0/pathScan/v2/pkg/output"
	"github.com/wjlin0/pathScan/v2/pkg/scanner"
	"github.com/wjlin0/pathScan/v2/pkg/types"
	"github.com/wjlin0/uncover/runner"
	proxyutils "github.com/wjlin0/utils/proxy"
	updateutils "github.com/wjlin0/utils/update"
	"net/url"
	"os"
	"strings"
	"time"
)

type Runner struct {
	options       *types.Options
	targets       []*input.Target
	scanner       *scanner.Scanner
	outputWriter  *output.OutputWriter
	uncoverWriter *output.OutputWriter
}

func NewRunner(options *types.Options) (r *Runner, err error) {
	r = &Runner{}
	r.options = options

	// 初始化scanner
	if r.scanner, err = scanner.NewScanner(options); err != nil {
		return nil, err
	}
	// 设置输出writer
	if err = r.setEventWriter(); err != nil {
		return nil, err
	}

	return r, nil
}
func (r *Runner) Close() {
	r.scanner.Close()
	if r.outputWriter != nil {
		r.outputWriter.Close()
	}
	if r.uncoverWriter != nil {
		r.uncoverWriter.Close()
	}

}
func (r *Runner) RunEnumeration() error {

	var (
		wg = sizedwaitgroup.New(r.options.Thread)
	)
	r.displayRunEnumeration()
	options := r.options
	startTime := time.Now()
	var (
		err                       error
		uncoverResultCallback     func(event string)
		outputResultEventCallback func(event output.ResultEvent)
	)
	if uncoverResultCallback, outputResultEventCallback, err = r.getEventCallback(); err != nil {
		return err
	}

	switch {
	case r.options.Uncover:

		scanUncover, err := r.scanner.ScanUncover(uncoverResultCallback)
		if err != nil {
			return err
		}

		var (
			targets []*input.Target
		)

		for c := range scanUncover {
			target := input.NewTarget(c, r.options.Method, handlerHeaders(r.options), handlerPaths(r.options), r.options.Body)
			found := false
		out:
			for _, t := range targets {
				if t.IsDuplicate(target) {
					found = true
					break out
				}
			}
			if !found {
				targets = append(targets, target)
			}
		}
		r.aliveHosts(targets)

		r.showNumberOfRequests()

		for _, target := range r.targets {
			wg.Add()
			go func(target *input.Target) {
				defer wg.Done()
				r.scanner.Scan(target, outputResultEventCallback)
			}(target)
		}
		wg.Wait()
	case r.options.Subdomain:

		scanUncover, err := r.scanner.ScanUncover(uncoverResultCallback)
		if err != nil {
			return err
		}
		var (
			targets []*input.Target
		)

		for c := range scanUncover {
			target := input.NewTarget(c, r.options.Method, handlerHeaders(r.options), handlerPaths(r.options), r.options.Body)
			found := false
		out3:
			for _, t := range targets {
				if t.IsDuplicate(target) {
					found = true
					break out3
				}
			}
			if !found {
				targets = append(targets, target)
			}

		}

		r.aliveHosts(targets)

		r.showNumberOfRequests()
		for _, target := range r.targets {
			wg.Add()
			go func(target *input.Target) {
				defer wg.Done()
				r.scanner.Scan(target, outputResultEventCallback)
			}(target)
		}

		wg.Wait()
	default:
		var (
			targets []*input.Target
		)
		ch := input.DecomposeHost(handlerTargets(options), options.Method, handlerHeaders(options), handlerPaths(options), options.Body)
		for c := range ch {
			found := false
		out2:
			for _, target := range targets {
				if target.IsDuplicate(c) {
					found = true
					break out2
				}
			}
			if !found {
				targets = append(targets, c)
			}

		}
		r.aliveHosts(targets)
		r.showNumberOfRequests()

		for _, target := range r.targets {
			wg.Add()
			go func(target *input.Target) {
				defer wg.Done()
				r.scanner.Scan(target, outputResultEventCallback)
			}(target)
		}
		wg.Wait()
	}

	gologger.Info().Msgf("This task takes %v seconds", time.Since(startTime).Seconds())
	return nil
}
func (r *Runner) displayRunEnumeration() {

	opts := r.options

	if opts.Silent {
		return
	}

	if !opts.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback(toolName, pathScanRepoName)()
		if err != nil {
			if opts.Debug {
				gologger.Error().Msgf("%s version check failed: %v", toolName, err.Error())
			}
		} else {
			gologger.Info().Msgf("Current %s version v%v %v", toolName, Version, updateutils.GetVersionDescription(Version, latestVersion))
		}

		psMVersion := strings.Replace(PathScanMatchVersion, "v", "", 1)
		latestVersion, err = updateutils.GetToolVersionCallback("", pathScanMatchRepoName)()
		if err != nil {
			if opts.Debug {
				gologger.Error().Msgf("%s version check failed: %v", pathScanMatchRepoName, err.Error())
			}
		} else {
			gologger.Info().Msgf("Current %s version %v %v", pathScanMatchRepoName, psMVersion, updateutils.GetVersionDescription(psMVersion, latestVersion))
		}
		if updateutils.IsOutdated(psMVersion, latestVersion) {
			if err = updateutils.GetUpdateDirFromRepoCallback(pathScanMatchRepoName, DefaultMatchDir, pathScanMatchRepoName)(); err != nil {
				if opts.Debug {
					gologger.Error().Msgf("Failed to update %s: %v", pathScanMatchRepoName, err)
				}
			} else {
				gologger.Info().Msgf("%v sucessfully updated %v -> %v (%s)", toolName, psMVersion, latestVersion, color.HiGreenString("latest"))
				r.scanner.MergeOperators()
			}
		}

	} else {
		gologger.Info().Msgf("Current %s version v%v ", toolName, Version)
		if PathScanMatchVersion != "" {
			gologger.Info().Msgf("Current %s version %v ", pathScanMatchRepoName, PathScanMatchVersion)
		}
	}

	if types.ProxyURL != "" {
		// 展示代理
		parse, _ := url.Parse(types.ProxyURL)
		if parse.Scheme == proxyutils.HTTPS || parse.Scheme == proxyutils.HTTP {
			gologger.Info().Msgf("Using %s as proxy server", parse.String())
		}

		if parse.Scheme == proxyutils.SOCKS5 {
			gologger.Info().Msgf("Using %s as socket proxy server", parse.String())
		}
	}
	if !opts.DisableScanMatch {
		gologger.Info().Msgf("PathScan-match templates loaded for current scan: %d", r.scanner.CountOperators())
	}
	// 输出 uncoverEngine uncoverQuery
	if opts.Uncover {
		gologger.Info().Msgf("Uncover engine: %s", opts.UncoverEngine)
		gologger.Info().Msgf("Uncover query: %s", opts.UncoverQuery)
	}
	if opts.Subdomain {
		gologger.Info().Msgf("Subdomain engine: %s", opts.SubdomainEngine)
		gologger.Info().Msgf("Subdomain query: %s", opts.SubdomainQuery)
	}

}
func (r *Runner) showNumberOfRequests() {
	num := 0
	for _, target := range r.targets {
		tmpNum := 0
		if target.Scheme == input.HTTPandHTTPS {
			tmpNum = 2 * len(target.Paths) * len(target.Methods)
		} else {
			tmpNum = len(target.Paths) * len(target.Methods)
		}
		if sliceutil.Contains(target.Paths, "/") && !r.options.DisableScanMatch {
			tmpNum += r.scanner.CountOperatorsRequest()
		}

		num += tmpNum

	}

	gologger.Info().Msgf("Total number of Requests: %d", num)
}
func (r *Runner) getEventCallback() (uncoverEvent func(event string), pathScanEvent func(event output.ResultEvent), err error) {
	options := r.options

	uncoverEvent = func(event string) {
		r.uncoverWriter.WriteString(event)
	}

	pathScanEvent = func(event output.ResultEvent) {
		switch {
		case r.options.CSV:
			gologger.Print().Msgf(event.CSV())
			r.outputWriter.WriteCSVData(event)
		case r.options.HTML:
			gologger.Print().Msg(event.EventToStdout())
			r.outputWriter.WriteHTMLData(event)
		case r.options.Silent:
			r.outputWriter.WriteString(event.String())
		default:
			r.outputWriter.WriteString(event.EventToStdout())
		}
	}
	if options.ResultEventCallback != nil {
		pathScanEvent = options.ResultEventCallback
	}

	return
}
func (r *Runner) setEventWriter() (err error) {
	var (
		outputWriter  *output.OutputWriter
		uncoverWriter *output.OutputWriter
		uncoverFile   *os.File
	)

	outputWriter, err = output.NewOutputWriter()
	if err != nil {
		return err
	}
	if !(r.options.HTML || r.options.CSV) {
		outputWriter.AddWriters(os.Stdout)
	}
	if r.options.Output != "" {
		switch {
		case r.options.CSV:
			csvWriter, err := output.NewCSVWriter(r.options.Output)
			if err != nil {
				return err
			}
			outputWriter.AddWriters(csvWriter)
		case r.options.HTML:
			htmlWriter, err := output.NewHTMLWriter(r.options.Output)
			if err != nil {
				return err
			}
			outputWriter.AddWriters(htmlWriter)
		default:
			if file, err := fileutil.OpenOrCreateFile(r.options.Output); err != nil {
				return err
			} else {
				outputWriter.AddWriters(file)
			}
		}
	}

	if uncoverWriter, err = output.NewOutputWriter(); err != nil {
		return err
	}

	f := func(path string) error {

		switch {
		case r.options.CSV:
			csvWriter, err := runner.NewCSVWriter(path)
			if err != nil {
				return err
			}

			uncoverWriter.AddWriters(csvWriter)
		default:

			if uncoverFile, err = fileutil.OpenOrCreateFile(path); err != nil {
				return err
			}

			uncoverWriter.AddWriters(uncoverFile)
		}
		return nil
	}

	if r.options.SubdomainOutput != "" {
		if err = f(r.options.SubdomainOutput); err != nil {
			return err
		}

	}
	if r.options.UncoverOutput != "" {
		if err = f(r.options.UncoverOutput); err != nil {
			return err
		}
	}

	r.outputWriter = outputWriter
	r.uncoverWriter = uncoverWriter

	return nil

}

func (r *Runner) aliveHosts(targets []*input.Target) {
	if r.options.DisableAliveCheck {
		gologger.Info().Msgf("Skipping alive check on input host")
		r.targets = targets
		return
	}

	gologger.Info().Msgf("Running check alive on input host")

	var (
		alives []*input.Target
	)

	wg := sizedwaitgroup.New(-1)

	for _, target := range targets {
		wg.Add()
		go func(target *input.Target) {
			defer wg.Done()
			if alive := r.scanner.Alive(target); alive != nil {
				r.scanner.Lock()
				alives = append(alives, alive...)
				r.scanner.Unlock()
			}
		}(target)
	}
	wg.Wait()

	r.targets = alives

	gologger.Info().Msgf("Found %d URL of alive hosts", len(r.targets))

	return
}
