package runner

import (
	"fmt"
	"github.com/wjlin0/pathScan/pkg/writer"
	"sync"
)

type Cached struct {
	CachedString map[string]struct{} `json:"cached-string"`
	Lock         sync.RWMutex        `json:"-"`
}

func NewCached() *Cached {
	return &Cached{
		CachedString: make(map[string]struct{}),
	}
}
func (c *Cached) HasInCached(path string) (ok bool) {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	_, ok = c.CachedString[path]
	return ok
}
func (c *Cached) Set(path string) {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	c.CachedString[path] = struct{}{}
}

func (r *Runner) output(outputWriter *writer.OutputWriter) {
	for out := range r.outputResult {
		path := out.ToString()
		var outputStr []byte
		var err error
		switch {
		case r.Cfg.Options.Csv:
			outputStr, err = writer.CSVToString(*out)
			if err != nil {
				continue
			}
			outputWriter.Write(outputStr)
			fmt.Println(string(outputStr))
		case r.Cfg.Options.Html:
			outputStr, err = writer.HTMLToString(out)
			if err != nil {
				continue
			}

			outputWriter.Write(outputStr)

			fmt.Println(writer.OutputToString(out, r.Cfg.Options.NoColor))
		case r.Cfg.Options.Silent:
			outputStr = []byte(out.ToString())
			outputWriter.Write(outputStr)
			fmt.Println(string(outputStr))
		default:
			switch {
			case !r.Cfg.Options.Silent:
				outputStr = []byte(writer.OutputToString(out, r.Cfg.Options.NoColor))
			case r.Cfg.Options.Silent:
				outputStr = []byte(out.ToString())
			}

			fmt.Println(string(outputStr))

			outputWriter.WriteString(path)
		}

		//r.handlerOutputTarget(out)
	}
}
