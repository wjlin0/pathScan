package zone

type Response struct {
	Code     int            `json:"code,omitempty"`
	Message  string         `json:"message,omitempty"`
	Page     int            `json:"page,omitempty"`
	PageSize int            `json:"page_size,omitempty"`
	Total    int            `json:"total,omitempty"`
	Data     []responseData `json:"data"`
}
type responseData struct {
	Ip     string `json:"ip"`
	Port   int    `json:"port"`
	Url    string `json:"url"`
	IpAddr string `json:"ip_addr"`
}
