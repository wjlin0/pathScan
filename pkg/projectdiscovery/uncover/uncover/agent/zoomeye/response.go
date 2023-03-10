package zoomeye

type ZoomEyeResponse struct {
	Total  int    `json:"total"`
	List   []data `json:"list"`
	Status int    `json:"status"`
}
type data struct {
	Name      string   `json:"name,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
	Ip        []string `json:"ip,omitempty"`
}
