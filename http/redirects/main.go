package httpredirects

import (
	"net/http"
)

// HTTPRedirects struct
type HTTPRedirects struct {
	URL          string       `json:"url,omitempty"`
	Redirects    []*Redirects `json:"redirects,omitempty"`
	Error        string       `json:"error,omitempty"`
	ErrorMessage string       `json:"errormessage,omitempty"`
}

// Redirects struct
type Redirects struct {
	StatusCode int    `json:"statuscode,omitempty"`
	URL        string `json:"url,omitempty"`
}

// GetRedirects function
func GetRedirects(starturl string) *HTTPRedirects {
	r := new(HTTPRedirects)
	r.URL = starturl

	myURL := starturl
	nextURL := myURL
	var i int
	for i < 100 {
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}

		resp, err := client.Get(nextURL)

		if err != nil {
			// fmt.Println(err)
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
		}

		redirect := new(Redirects)
		redirect.StatusCode = resp.StatusCode
		redirect.URL = resp.Request.URL.String()
		r.Redirects = append(r.Redirects, redirect)

		// fmt.Println("StatusCode:", resp.StatusCode)
		// fmt.Println(resp.Request.URL)

		if resp.StatusCode == 200 {
			// fmt.Println("Done!")
			break
		} else {
			nextURL = resp.Header.Get("Location")
			i++
		}
	}
	return r
}
