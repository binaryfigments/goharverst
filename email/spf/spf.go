package emailspf

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Data struct
type Data struct {
	Domain       string     `json:"domain,omitempty"`
	Records      []*Records `json:"records,omitempty"`
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
				r.Records = append(r.Records, records)
			}

		}
	}
	return r
}

func Get2(domain string) *Data {
	r := new(Data)
	r.Domain = domain
	dnstxt, err := net.LookupTXT(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
	}

	// fmt.Println(err)
	// fmt.Println(txt)
	records := new(Records)

	for i := 0; i < len(dnstxt); i++ {
		fmt.Printf("DNS TXT record #%d : %s \n", i, dnstxt[i])
		// if strings.HasPrefix(SPFrecord, "v=spf1") == true {
		if caseInsenstiveContains(dnstxt[i], "v=spf1") == true {
			// records.SPF = a.Txt
			records.SPF = dnstxt[i]
			r.Records = append(r.Records, records)
		}
	}
	if len(r.Records) < 1 {
		r.Error = "Failed"
		r.ErrorMessage = "No SPF records."
	}

	return r

}

func caseInsenstiveContains(a, b string) bool {
	return strings.Contains(strings.ToUpper(a), strings.ToUpper(b))
}
