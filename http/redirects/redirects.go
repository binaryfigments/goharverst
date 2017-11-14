package httpredirects

import (
	"net/http"
	"net/url"

	"github.com/miekg/dns"
)

// HTTPRedirects struct
type HTTPRedirects struct {
	FQDN         string       `json:"fqdn,omitempty"`
	Protocol     string       `json:"protocol,omitempty"`
	Redirects    []*Redirects `json:"redirects,omitempty"`
	Hosts        []*Hosts     `json:"hosts,omitempty"`
	Error        string       `json:"error,omitempty"`
	ErrorMessage string       `json:"errormessage,omitempty"`
}

// Redirects struct
type Redirects struct {
	StatusCode int    `json:"statuscode,omitempty"`
	URL        string `json:"url,omitempty"`
}

type Hosts struct {
	Hostname     string   `json:"hostname,omitempty"`
	IPv4         []string `json:"ipv4,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	CNAME        string   `json:"cname,omitempty"`
	Error        string   `json:"error,omitempty"`
	ErrorMessage string   `json:"errormessage,omitempty"`
}

// Get function
func Get(fqdn string, protocol string) *HTTPRedirects {
	r := new(HTTPRedirects)

	// Create urllist map
	var urllist map[string]bool
	urllist = make(map[string]bool)

	starturl := protocol + "://" + fqdn

	r.FQDN = fqdn
	r.Protocol = protocol

	// myURL := starturl

	// Start URL to urllist
	addurl, _ := hostFromURL(starturl)
	urllist[addurl] = true

	nextURL := starturl
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

		// Only unique hosts in hostlist
		addurl, _ := hostFromURL(resp.Request.URL.String())
		if urllist[addurl] == false {
			urllist[addurl] = true
		}

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

	for key := range urllist {
		host := GetHosts(key)
		r.Hosts = append(r.Hosts, host)
	}

	return r
}

func hostFromURL(geturl string) (string, error) {
	u, err := url.Parse(geturl)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

func GetHosts(geturl string) *Hosts {
	r := new(Hosts)

	r.Hostname = geturl

	cname, err := GetCNAME(r.Hostname, "8.8.4.4")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	if len(cname) > 0 {
		r.CNAME = cname
		return r
	}

	ar, err := GetA(r.Hostname, "8.8.4.4")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}
	r.IPv4 = ar

	aaaar, err := GetAAAA(r.Hostname, "8.8.4.4")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}
	r.IPv6 = aaaar

	return r

}

func GetCNAME(hostname string, nameserver string) (string, error) {
	var cname string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return "none", err
	}
	for _, rin := range in.Answer {
		if r, ok := rin.(*dns.CNAME); ok {
			cname = r.Target
		}
	}
	return cname, nil
}

func GetA(hostname string, nameserver string) ([]string, error) {
	var record []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	for _, rin := range in.Answer {
		if r, ok := rin.(*dns.A); ok {
			record = append(record, r.A.String())
		}
	}

	return record, nil
}

func GetAAAA(hostname string, nameserver string) ([]string, error) {
	var record []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	for _, rin := range in.Answer {
		if r, ok := rin.(*dns.AAAA); ok {
			record = append(record, r.AAAA.String())
		}
	}

	return record, nil
}
