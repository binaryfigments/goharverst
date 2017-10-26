package emailspf

import (
	"strings"

	"github.com/miekg/dns"
)

// Data struct
type Data struct {
	Domain       string     `json:"domain,omitempty"`
	SPF          []*Records `json:"spf,omitempty"`
	Error        string     `json:"error,omitempty"`
	ErrorMessage string     `json:"errormessage,omitempty"`
}

type Records struct {
	SPF string `json:"spf,omitempty"`
}

func Get(domain string, nameserver string) *Data {
	r := new(Data)
	r.Domain = domain
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.TXT); ok {
			records := new(Records)
			SPFrecord := strings.Join(a.Txt, " ")
			if strings.HasPrefix(SPFrecord, "v=spf1") == true {
				// records.SPF = a.Txt
				records.SPF = SPFrecord
				r.SPF = append(r.SPF, records)
			}

		}
	}
	return r
}
