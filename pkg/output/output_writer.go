package output

import (
	"crypto/sha1"
	lru "github.com/hashicorp/golang-lru"
	"io"
	"os"
	"sync"
)

type OutputWriter struct {
	cache   *lru.Cache
	writers []io.Writer
	sync.RWMutex
}

func NewOutputWriter() (*OutputWriter, error) {
	lastPrintedCache, err := lru.New(2048)
	if err != nil {
		return nil, err
	}
	return &OutputWriter{cache: lastPrintedCache}, nil
}

func (o *OutputWriter) AddWriters(writers ...io.Writer) {
	o.writers = append(o.writers, writers...)
}

// Write writes the data taken as input using only
// the writer(s) with that name.
func (o *OutputWriter) Write(data []byte) {
	o.Lock()
	defer o.Unlock()

	for _, w := range o.writers {
		_, _ = w.Write(data)
		_, _ = w.Write([]byte("\n"))
	}
}

func (o *OutputWriter) findDuplicate(data string) bool {
	// check if we've already printed this data
	itemHash := sha1.Sum([]byte(data))
	if o.cache.Contains(itemHash) {
		return true
	}
	o.cache.Add(itemHash, struct{}{})
	return false
}

// WriteString writes the string taken as input using only
func (o *OutputWriter) WriteString(data string) {
	if o.findDuplicate(data) {
		return
	}
	o.Write([]byte(data))
}

// Close closes the output writers
func (o *OutputWriter) Close() {
	// Iterate over the writers and close the file writers
	for _, writer := range o.writers {
		if fileWriter, ok := writer.(*os.File); ok {
			fileWriter.Close()
		}
		if htmlWriter, ok := writer.(*HTMLWriter); ok {
			htmlWriter.Close()
		}
		if csvWriter, ok := writer.(*CSVWriter); ok {
			csvWriter.Close()
		}
	}
}
func (o *OutputWriter) WriteCSVData(result ResultEvent) {

	o.WriteString(result.CSV())
}

func (o *OutputWriter) WriteHTMLData(data ResultEvent) {
	o.WriteString(data.HTML())
}
