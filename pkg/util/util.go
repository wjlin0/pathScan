package util

import (
	"errors"
	"fmt"
	"net/http"
)

func ReconDial(client *http.Client, req *http.Request, i int, max int) (*http.Response, error) {
	get, err := client.Do(req)
	if err != nil {
		if i < max {
			i++
			get, err = ReconDial(client, req, i, max)
		} else {
			err = errors.New(fmt.Sprintf("链接失败超过%v次-> `%v` ", max, req.URL.String()))
		}
	}
	return get, err
}
