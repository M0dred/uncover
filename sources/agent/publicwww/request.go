package publicwww

import (
	"net/url"
	"strconv"
)

type Request struct {
	Query string `json:"query"`
	Start int    `json:"start"`
}

func (r *Request) buildURL(key string) string {
	return baseURL +
		baseEndpoint +
		url.QueryEscape(`"`+r.Query+`"`) +
		`/?export=urls&key=` + key +
		`&start=` + strconv.Itoa(r.Start)
}
