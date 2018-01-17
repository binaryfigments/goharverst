package dnsnsec

import (
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Data struct
type Data struct {
	Domain       string    `json:"domain,omitempty"`
	CheckTime    time.Time `json:"time"`
	NSEC         NSEC      `json:"nsec"`
	Error        string    `json:"error,omitempty"`
	ErrorMessage string    `json:"errormessage,omitempty"`
}

// NSEC struct for NSEC type
type NSEC struct {
	Type       string          `json:"type,omitempty"`
	NSEC       *dns.NSEC       `json:"nsec,omitempty"`
	NSEC3      *dns.NSEC3      `json:"nsec3,omitempty"`
	NSEC3PARAM *dns.NSEC3PARAM `json:"nsec3param,omitempty"`
}

// Get function
func Get(domain string, nameserver string) *Data {
	r := new(Data)
	r.Domain = domain
	r.CheckTime = time.Now()

	// Valid domain name (ASCII or IDN)
	domain, err := idna.ToASCII(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	// Validate domain
	domain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	nsec, _ := resolveDomainNSEC(domain, nameserver)
	if nsec != nil {
		r.NSEC.Type = "nsec"
		r.NSEC.NSEC = nsec
	}

	nsec3, _ := resolveDomainNSEC3(domain, nameserver)
	if nsec3 != nil {
		r.NSEC.Type = "nsec3"
		r.NSEC.NSEC3 = nsec3
	}

	nsec3param, _ := resolveDomainNSEC3PARAM(domain, nameserver)
	if nsec3param != nil {
		r.NSEC.Type = "nsec3param"
		r.NSEC.NSEC3PARAM = nsec3param
	}

	return r
}

/*
 * Used functions
 * TODO: Rewrite
 */

func resolveDomainNSEC(domain string, nameserver string) (*dns.NSEC, error) {
	var answer *dns.NSEC
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNSEC)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NSEC); ok {
			answer = a
			return answer, nil
		}
	}
	return nil, nil
}

func resolveDomainNSEC3(domain string, nameserver string) (*dns.NSEC3, error) {
	var answer *dns.NSEC3
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNSEC3)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NSEC3); ok {
			answer = a
			return answer, nil
		}
	}
	return nil, nil
}

func resolveDomainNSEC3PARAM(domain string, nameserver string) (*dns.NSEC3PARAM, error) {
	var answer *dns.NSEC3PARAM
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNSEC3PARAM)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NSEC3PARAM); ok {
			answer = a
			return answer, nil
		}
	}
	return nil, nil
}
