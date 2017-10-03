package harverstmail

import (
	"github.com/miekg/dns"
)

// EmailMX struct
type EmailMX struct {
	Domain       string       `json:"domain,omitempty"`
	Records      []*MXRecords `json:"records,omitempty"`
	Error        string       `json:"error,omitempty"`
	ErrorMessage string       `json:"errormessage,omitempty"`
}

type MXRecords struct {
	Server     string `json:"server,omitempty"`
	Preference uint16 `json:"preference,omitempty"`
}

func GetMX(domain string, nameserver string) *EmailMX {
	r := new(EmailMX)
	r.Domain = domain
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.MX); ok {
			records := new(MXRecords)
			records.Server = a.Mx
			records.Preference = a.Preference
			r.Records = append(r.Records, records)
		}
	}
	return r
}
