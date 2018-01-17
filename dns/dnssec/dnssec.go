package dnsdnssec

import (
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Data struct
type Data struct {
	Domain       string    `json:"domain,omitempty"`
	Answer       Answer    `json:"answer"`
	CheckTime    time.Time `json:"time"`
	DNSSEC       bool      `json:"dnssec"`
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

// Answer struct the answer of the question.
type Answer struct {
	DSRecordCount     int             `json:"dsrecordcount,omitempty"`
	DNSKEYRecordCount int             `json:"dnskeyrecordcount,omitempty"`
	DSRecords         []*DomainDS     `json:"dsrecords,omitempty"`
	DNSKEYRecords     []*DomainDNSKEY `json:"dnskeyrecords,omitempty"`
	CalculatedDS      []*DomainDS     `json:"calculatedds,omitempty"`
	Matching          Matching        `json:"matching,omitempty"`
}

// Matching struct for information
type Matching struct {
	DS     []*DomainDS     `json:"ds,omitempty"`
	DNSKEY []*DomainDNSKEY `json:"dnskey,omitempty"`
}

// DomainDS struct
type DomainDS struct {
	Algorithm  uint8  `json:"algorithm,omitempty"`
	Digest     string `json:"digest,omitempty"`
	DigestType uint8  `json:"digesttype,omitempty"`
	KeyTag     uint16 `json:"keytag,omitempty"`
}

// DomainDNSKEY struct
type DomainDNSKEY struct {
	Algorithm    uint8     `json:"algorithm,omitempty"`
	Flags        uint16    `json:"flags,omitempty"`
	Protocol     uint8     `json:"protocol,omitempty"`
	PublicKey    string    `json:"publickey,omitempty"`
	CalculatedDS *DomainDS `json:"calculatedds,omitempty"`
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

	tld, _ := publicsuffix.PublicSuffix(domain)

	registryNameserver, err := resolveOneNS(tld, nameserver)
	domainNameserver, err := resolveOneNS(domain, nameserver)

	/*
	 * DS and DNSKEY information
	 */

	// Domain nameservers at Hoster
	domainds, err := resolveDomainDS(domain, registryNameserver)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}
	r.Answer.DSRecords = domainds
	r.Answer.DSRecordCount = cap(domainds)

	// Wel of geen error, geen probleem.
	dnskey, _ := resolveDomainDNSKEY(domain, domainNameserver)

	r.Answer.DNSKEYRecords = dnskey
	r.Answer.DNSKEYRecordCount = cap(r.Answer.DNSKEYRecords)

	var digest uint8
	if cap(r.Answer.DSRecords) != 0 {
		digest = r.Answer.DSRecords[0].DigestType
	}

	if r.Answer.DSRecordCount > 0 && r.Answer.DNSKEYRecordCount > 0 {
		// Wel of geen error, geen probleem.
		calculatedDS, _ := calculateDSRecord(domain, digest, domainNameserver)
		r.Answer.CalculatedDS = calculatedDS
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

	if r.Answer.DSRecordCount > 0 && r.Answer.DNSKEYRecordCount > 0 {
		filtered := []*DomainDS{}
		dnskeys := []*DomainDNSKEY{}
		for _, e := range r.Answer.DSRecords {
			for i, f := range r.Answer.CalculatedDS {
				if f.Digest == e.Digest {
					filtered = append(filtered, f)
					dnskeys = append(dnskeys, r.Answer.DNSKEYRecords[i])
				}
			}
		}
		r.Answer.Matching.DS = filtered
		r.Answer.Matching.DNSKEY = dnskeys
		r.DNSSEC = true
	} else {
		r.DNSSEC = false
	}

	return r
}

/*
 * Used functions
 * TODO: Rewrite
 */

func resolveOneNS(domain string, nameserver string) (string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return "none", err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NS); ok {
			answer = append(answer, a.Ns)
		}
	}
	if len(answer) < 1 {
		return "none", err
	}
	return answer[0], nil
}

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

func resolveDomainNS(domain string, nameserver string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NS); ok {
			answer = append(answer, a.Ns)
		}
	}
	return answer, nil
}

func resolveDomainDS(domain string, nameserver string) ([]*DomainDS, error) {
	ds := []*DomainDS{}
	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		// log.Println("[FAIL] No DS records found.")
		return ds, err
	}
	// fmt.Println(cap(in.Answer))
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DS); ok {
			readkey := new(DomainDS)
			readkey.Algorithm = a.Algorithm
			readkey.Digest = a.Digest
			readkey.DigestType = a.DigestType
			readkey.KeyTag = a.KeyTag
			ds = append(ds, readkey)
		}
	}
	return ds, nil
}

func resolveDomainDNSKEY(domain string, nameserver string) ([]*DomainDNSKEY, error) {
	dnskey := []*DomainDNSKEY{}

	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return dnskey, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			readkey := new(DomainDNSKEY)
			readkey.Algorithm = a.Algorithm
			readkey.Flags = a.Flags
			readkey.Protocol = a.Protocol
			readkey.PublicKey = a.PublicKey
			dnskey = append(dnskey, readkey)
		}
	}
	return dnskey, err
}

/*
 * calculateDSRecord function for generating DS records from the DNSKEY.
 * Input: domainname, digest and nameserver from the hoster.
 * Output: one of more structs with DS information
 */

func calculateDSRecord(domain string, digest uint8, nameserver string) ([]*DomainDS, error) {
	calculatedDS := []*DomainDS{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return calculatedDS, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			calckey := new(DomainDS)
			calckey.Algorithm = a.ToDS(digest).Algorithm
			calckey.Digest = a.ToDS(digest).Digest
			calckey.DigestType = a.ToDS(digest).DigestType
			calckey.KeyTag = a.ToDS(digest).KeyTag
			calculatedDS = append(calculatedDS, calckey)
		}
	}
	return calculatedDS, nil
}
