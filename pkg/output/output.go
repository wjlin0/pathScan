package output

import (
	"fmt"
	"github.com/fatih/color"
	"os"
	"strings"
)

func Debug(i string, str ...string) {
	s := parse(str...)
	c := color.New(color.Bold, color.FgMagenta)
	fmt.Printf("[%s] %s %s\n", c.Sprintf("DBG"), i, s)
}
func Info(i string, str ...string) {
	s := parse(str...)
	c := color.New(color.Bold, color.FgBlue)
	fmt.Printf("[%s] %s %s\n", c.Sprintf("INF"), i, s)
}

func Err(i string, str ...string) {
	s := parse(str...)
	c := color.New(color.Bold, color.FgRed)
	fmt.Printf("[%s] %s %s\n", c.Sprintf("ERR"), i, s)
}

func Warning(i string, str ...string) {
	s := parse(str...)
	c := color.New(color.Bold, color.FgYellow)
	fmt.Printf("[%s] %s %s\n", c.Sprintf("WRN"), i, s)

}
func parse(str ...string) string {
	s := "[ "
	for i := 0; i < len(str); i++ {
		s += str[i] + ","
	}
	s = strings.TrimSuffix(s, ",")
	s += " ]"
	if str == nil {
		s = ""
	}
	return s
}
func FTl(i string, str ...string) {
	s := parse(str...)
	c := color.New(color.Bold, color.FgRed)
	fmt.Printf("[%s] %s %s\n", c.Sprintf("FTL"), i, s)
	os.Exit(1)
}
