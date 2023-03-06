package uncover

import (
	"bufio"
	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover"
	"io"
	"strings"
)

func writeTargetOutput(Results []*uncover.Result, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}
	for _, result := range Results {
		sb.WriteString(result.Host)
		sb.WriteString("\n")
		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			_ = bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}
