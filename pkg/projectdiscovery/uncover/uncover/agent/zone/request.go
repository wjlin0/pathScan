package zone

type ZoneRequest struct {
	Query     string `json:"query,omitempty"`
	Page      int    `json:"page,omitempty"`
	QueryType string `json:"query_type,omitempty"`
	PageSize  int    `json:"pagesize,omitempty"`
	ZoneKeyId string `json:"zone_key_id,omitempty"`
}
