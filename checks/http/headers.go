package httpheaders

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HTTPHeaders struct
type HTTPHeaders struct {
	URL          string `json:"url,omitempty"`
	Method       string `json:"method,omitempty"`
	Header       string `json:"header,omitempty"`
	Result       string `json:"result,omitempty"`
	Status       string `json:"status,omitempty"`
	StatusCode   int    `json:"statuscode,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"errormessage,omitempty"`
}

// GetHTTPHeader function
func GetHTTPHeader(checkurl string, header string, method string) *HTTPHeaders {

	r := new(HTTPHeaders)
	r.URL = checkurl
	r.Method = method
	r.Header = header

	u, err := url.Parse(checkurl)
	if err != nil {
		r.Result = "Failed"
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	_, err = net.LookupIP(u.Host)
	if err != nil {
		r.Result = "Failed"
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	req, err := http.NewRequest(method, checkurl, nil)
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Networking4all Server Checker 1.0")
	if err != nil {
		r.Result = "Failed"
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// http client with timeout, tls-skip and no redirecting.
	hc := &http.Client{
		Timeout:   2 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := hc.Do(req)
	if err != nil {
		r.Result = "Failed"
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}
	r.StatusCode = resp.StatusCode
	r.Status = resp.Status

	switch resp.Header.Get(header) {
	case "":
		r.Result = "Undisclosed"
	default:
		r.Result = resp.Header.Get(header)
	}

	defer resp.Body.Close()
	return r
}
