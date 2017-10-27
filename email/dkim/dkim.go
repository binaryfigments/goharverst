// Do lookup _domainkey.example.org
// if exists -----> DNS response: NOERROR
// if not exists -> DNS response: NXDOMAIN

package emaildkim

import (
	"strconv"

	"github.com/miekg/dns"
)

// Data struct
type Data struct {
	Domain       string `json:"domain,omitempty"`
	DomainKey    string `json:"domainkey,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"errormessage,omitempty"`
}

func Get(domain string, nameserver string) *Data {
	r := new(Data)
	r.Domain = domain

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_domainkey."+domain), dns.TypeA)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
	}

	switch rcode := in.MsgHdr.Rcode; rcode {
	case dns.RcodeSuccess:
		r.DomainKey = "Success" // NoError (0)
	case dns.RcodeFormatError:
		r.DomainKey = "FormErr" // FormErr (1)
	case dns.RcodeServerFailure:
		r.DomainKey = "ServFail" // ServFail (2)
	case dns.RcodeNameError:
		r.DomainKey = "NXDomain" // NXDomain (3)
	case dns.RcodeNotImplemented:
		r.DomainKey = "NotImp" // NotImp (4)
	case dns.RcodeRefused:
		r.DomainKey = "Refused" // Refused (5)
	default:
		r.DomainKey = "Code: " + strconv.Itoa(rcode)
	}

	return r
}
