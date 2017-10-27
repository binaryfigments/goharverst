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
	case 0:
		r.DomainKey = "Success" // NoError
	case 1:
		r.DomainKey = "FormErr" // FormErr
	case 2:
		r.DomainKey = "ServFail" // ServFail
	case 3:
		r.DomainKey = "NXDomain" // NXDomain
	case 4:
		r.DomainKey = "NotImp" // NotImp
	case 5:
		r.DomainKey = "Refused" // Refused
	default:
		r.DomainKey = "Code: " + strconv.Itoa(rcode)
	}

	return r
}
