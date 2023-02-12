package runner

import "testing"

func TestDownloadDict(t *testing.T) {
	err := DownloadDict()
	if err != nil {
		t.Error(err)
	}
}
