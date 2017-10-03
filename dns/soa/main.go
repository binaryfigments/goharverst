package dnssoa

import (
	"github.com/miekg/dns"
)

// Data struct
type Data struct {
	Domain       string `json:"domain,omitempty"`
	SOA          *SOA   `json:"records,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"errormessage,omitempty"`
}

type SOA struct {
	NS      string `json:"ns,omitempty"`
	Mbox    string `json:"mbox,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minttl  uint32 `json:"minttl,omitempty"`
}

// Get for checking soa
func Get(domain string, nameserver string) *Data {
	r := new(Data)
	r.Domain = domain
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
	}
	s := new(SOA)
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.SOA); ok {
			s.Serial = a.Serial   // uint32
			s.NS = a.Ns           // string
			s.Expire = a.Expire   // uint32
			s.Mbox = a.Mbox       // string
			s.Minttl = a.Minttl   // uint32
			s.Refresh = a.Refresh // uint32
			s.Retry = a.Retry     // uint32
		}
	}
	r.SOA = s
	return r
}
