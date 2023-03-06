package binary

type Response struct {
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
	Total    int      `json:"total"`
	Query    string   `json:"query"`
	Data     []string `json:"events"`
}
