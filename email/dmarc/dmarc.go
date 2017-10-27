// Do lookup _domainkey.example.org
// if exists -----> DNS response: NOERROR
// if not exists -> DNS response: NXDOMAIN

package emaildmarc

import (
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Data struct
type Data struct {
	Record       string   `json:"domain,omitempty"`
	DMARC        []string `json:"dmarc,omitempty"`
	Error        string   `json:"error,omitempty"`
	ErrorMessage string   `json:"errormessage,omitempty"`
}

func Get(domain string, nameserver string) *Data {
	r := new(Data)

	domain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
	}

	r.Record = "_dmarc." + domain

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

				dmarcrecord := strings.Join(a.Txt, " ")
				if caseInsenstiveContains(dmarcrecord, "v=DMARC1") == true {
					r.DMARC = append(r.DMARC, dmarcrecord)
				}

			}
		}
	default:
		r.Error = "Failed"
		r.ErrorMessage = "No DMARC records."
		return r
	}

	// Check for records
	if len(r.DMARC) < 1 {
		r.Error = "Failed"
		r.ErrorMessage = "No DMARC records."
		return r
	}

	return r
}

func caseInsenstiveContains(a, b string) bool {
	return strings.Contains(strings.ToUpper(a), strings.ToUpper(b))
}
