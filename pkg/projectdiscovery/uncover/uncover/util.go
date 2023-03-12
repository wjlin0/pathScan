package uncover

import (
	"github.com/projectdiscovery/retryablehttp-go"
	"io"
)

func NewHTTPRequest(method, url string, body io.Reader) (*retryablehttp.Request, error) {
	request, err := retryablehttp.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "PathScan - FOSS Project (github.com/wjlin0/pathScan)")
	return request, nil
}
