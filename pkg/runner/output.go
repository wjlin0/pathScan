package runner

import (
	"bufio"
	"io"
	"pathScan/pkg/result"
	"strconv"
	"strings"
)

func WriteTargetOutput(target string, paths map[string]*result.TargetResult, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}
	sb.WriteString(target)
	sb.WriteString(":\n")
	for _, path := range paths {
		if path.Status != 200 {
			continue
		}
		sb.WriteString("\t\t")
		sb.WriteString(path.Path)
		sb.WriteString(" [" + path.Title + " " + strconv.Itoa(path.BodyLen) + " " + "]")
		sb.WriteString("\n")
		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}
