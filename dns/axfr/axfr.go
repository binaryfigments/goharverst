// Work in progres!

package dnsaxfr

import (
	"net"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type Data struct {
	Domain       string `json:"domain,omitempty"`
	AXFR         bool   `json:"axfr,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"errormessage,omitempty"`
}

func Get(domain string, nameserver string) *Data {
	r := new(Data)

	domain, err := idna.ToASCII(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	// Validate
	domain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	r.Domain = domain
	m := new(dns.Msg)

	// complete domain, create a check for this later
	m.SetAxfr(domain + ".")

	transfer := new(dns.Transfer)
	if a, err := transfer.In(m, net.JoinHostPort(nameserver, "53")); err != nil {
		// fmt.Printf("failed to setup axfr %v for server: %v\n", err, server)
		r.AXFR = false
	} else {
		for ex := range a {
			if ex.Error != nil {
				// fmt.Printf("error %v", ex.Error)
				r.AXFR = false
				return r
				// break
			}
			r.AXFR = true
			/*
				json, err := json.MarshalIndent(ex, "", "  ")
				if err != nil {
					fmt.Println(err)
				}
				fmt.Printf("%s\n", json)
			*/
		}
	}
	return r
}
