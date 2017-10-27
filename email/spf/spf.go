package emailspf

import (
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Data struct
type Data struct {
	Record       string   `json:"domain,omitempty"`
	SPF          []string `json:"spf,omitempty"`
	Error        string   `json:"error,omitempty"`
	ErrorMessage string   `json:"errormessage,omitempty"`
}

// Get function of this package.
func Get(domain string, nameserver string) *Data {
	r := new(Data)

	domain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}
	r.Record = domain

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(r.Record), dns.TypeTXT)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	switch rcode := in.MsgHdr.Rcode; rcode {
	case dns.RcodeSuccess:
		for _, ain := range in.Answer {
			if a, ok := ain.(*dns.TXT); ok {
				// SPF records zijn langer en kunnen dus in meerdere delen teruggegeven worden.
				// strings.Join plakt ze weer aan elkaar.
				record := strings.Join(a.Txt, "")
				if caseInsenstiveContains(record, "v=spf1") == true {
					r.SPF = append(r.SPF, record)
				}

			}
		}
	default:
		r.Error = "Failed"
		r.ErrorMessage = "No SPF records."
		return r
	}

	// Check for records
	if len(r.SPF) < 1 {
		r.Error = "Failed"
		r.ErrorMessage = "No SPF records."
		return r
	}

	return r
}

func caseInsenstiveContains(a, b string) bool {
	return strings.Contains(strings.ToUpper(a), strings.ToUpper(b))
}
