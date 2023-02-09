package output

import (
	"github.com/fatih/color"
	"testing"
)

func TestDebug(t *testing.T) {
	Debug("https://www.wjlin0.com/", color.BlueString("200,百度一下"))
}
