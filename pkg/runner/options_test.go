package runner

import (
	"os"
	"testing"
)

func TestParserOptions(t *testing.T) {
	os.Args = []string{os.Args[0], "-u", "https://wjlin0.com/", "-uf", "url_text.txt", "-ps", "/api/user", "-pf", "dict_text.txt"}
	t.Log(ParserOptions())
}
