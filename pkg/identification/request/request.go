package request

type Request struct {
	Path   []string               `json:"path,omitempty"`
	Method string                 `json:"method,omitempty"`
	Header map[string]interface{} `json:"header,omitempty"`
	Body   string                 `json:"body,omitempty"`
}
