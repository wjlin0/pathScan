package writer

import (
	"crypto/sha1"
	"fmt"
	"github.com/wjlin0/pathScan/pkg/result"
	"io"
	"os"
	"sync"

	lru "github.com/hashicorp/golang-lru"
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

func (w *OutputWriter) AddWriters(writers ...io.Writer) {
	w.writers = append(w.writers, writers...)
}

// Write writes the data taken as input using only
// the writer(s) with that name.
func (w *OutputWriter) Write(data []byte) {
	w.Lock()
	defer w.Unlock()

	for _, w := range w.writers {
		_, _ = w.Write(data)
		_, _ = w.Write([]byte("\n"))
	}
}

func (w *OutputWriter) findDuplicate(data string) bool {
	// check if we've already printed this data
	itemHash := sha1.Sum([]byte(data))
	if w.cache.Contains(itemHash) {
		return true
	}
	w.cache.Add(itemHash, struct{}{})
	return false
}

// WriteString writes the string taken as input using only
func (w *OutputWriter) WriteString(data string) {
	if w.findDuplicate(data) {
		return
	}
	w.Write([]byte(data))
}

// Close closes the output writers
func (w *OutputWriter) Close() {
	// Iterate over the writers and close the file writers
	for _, writer := range w.writers {
		if fileWriter, ok := writer.(*os.File); ok {
			fileWriter.Close()
		}
	}
}

func (w *OutputWriter) Output(outputResult chan *result.Result, outType int, noColor bool) {
	for out := range outputResult {
		path := out.ToString()
		var outputStr []byte
		var err error
		switch outType {
		case 1:
			outputStr, err = CSVToString(*out)
			if err != nil {
				continue
			}
			w.Write(outputStr)
			fmt.Println(string(outputStr))
		case 2:
			outputStr, err = HTMLToString(out)
			if err != nil {
				continue
			}

			w.Write(outputStr)

			fmt.Println(OutputToString(out, noColor))
		case 3:
			outputStr = []byte(out.ToString())
			w.Write(outputStr)
			fmt.Println(string(outputStr))
		default:
			switch {
			case !noColor:
				outputStr = []byte(OutputToString(out, noColor))
			case noColor:
				outputStr = []byte(out.ToString())
			}

			fmt.Println(string(outputStr))

			w.WriteString(path)
		}

		//r.handlerOutputTarget(out)
	}
}
