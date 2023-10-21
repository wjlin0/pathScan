package runner

import (
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
