package quake

type responseData struct {
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Hostname string   `json:"hostname"`
	Service  *service `json:"service"`
}

type pagination struct {
	Count     int   `json:"count"`
	PageIndex int   `json:"page_index"`
	PageSize  int   `json:"page_size"`
	Total     int64 `json:"total"`
}

type meta struct {
	Pagination pagination `json:"pagination"`
}
type service struct {
	Name string        `json:"name"`
	Http *httpResponse `json:"http"`
}
type httpResponse struct {
	Host string `json:"host"`
}
type Response struct {
	Code    int            `json:"code"`
	Data    []responseData `json:"data"`
	Message string         `json:"message"`
	Meta    meta           `json:"meta"`
}
