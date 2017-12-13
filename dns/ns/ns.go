package dnsns

import (
	"time"

	"github.com/miekg/dns"
)

// Data struct
type Data struct {
	Domain       string    `json:"domain,omitempty"`
	NS           []string  `json:"nameservers,omitempty"`
	CheckTime    time.Time `json:"time"`
	Error        string    `json:"error,omitempty"`
	ErrorMessage string    `json:"errormessage,omitempty"`
}

// Get for checking soa
func Get(domain string, nameserver string) *Data {
	r := new(Data)
	r.Domain = domain
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}
	var answer []string
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NS); ok {
			answer = append(answer, a.Ns)
		}
	}
	r.NS = answer
	return r
}
