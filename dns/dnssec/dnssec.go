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
	Error        string    `json:"error,omitempty"`
	ErrorMessage string    `json:"errormessage,omitempty"`
}

// Answer struct the answer of the question.
type Answer struct {
	Registry          Registry        `json:"tld,omitempty"`
	Nameservers       Nameservers     `json:"nameservers,omitempty"`
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

// Registry struct for information
type Registry struct {
	TLD   string `json:"tld,omitempty"`
	ICANN bool   `json:"icann,omitempty"`
}

// Nameservers struct for information
type Nameservers struct {
	Root     []string `json:"root,omitempty"`
	Registry []string `json:"registry,omitempty"`
	Domain   []string `json:"domain,omitempty"`
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

	// Validate
	domain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	// Go check DNS!

	domainstate := checkDomainState(domain)
	if domainstate != "OK" {

		r.Error = "Failed"
		r.ErrorMessage = domainstate
		return r
	}

	tld, tldicann := publicsuffix.PublicSuffix(domain)
	r.Answer.Registry.TLD = tld
	r.Answer.Registry.ICANN = tldicann

	// Root nameservers
	rootNameservers, err := resolveDomainNS(".", nameserver)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}
	r.Answer.Nameservers.Root = rootNameservers

	// TLD nameserver
	registryNameservers, err := resolveDomainNS(tld, nameserver)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	r.Answer.Nameservers.Registry = registryNameservers
	registryNameserver := registryNameservers[0]

	// Domain nameservers at zone
	domainNameservers, err := resolveDomainNS(domain, nameserver)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	r.Answer.Nameservers.Domain = domainNameservers
	domainNameserver := domainNameservers[0]

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

	dnskey, err := resolveDomainDNSKEY(domain, domainNameserver)
	if err != nil {
		// log.Println("DNSKEY lookup failed: .", err)
	}
	// log.Println("[OK] DNSKEY record lookup done.")

	r.Answer.DNSKEYRecords = dnskey
	r.Answer.DNSKEYRecordCount = cap(r.Answer.DNSKEYRecords)

	var digest uint8
	if cap(r.Answer.DSRecords) != 0 {
		digest = r.Answer.DSRecords[0].DigestType
		// log.Println("[OK] DS digest type found:", digest)
	}

	if r.Answer.DSRecordCount > 0 && r.Answer.DNSKEYRecordCount > 0 {
		calculatedDS, err := calculateDSRecord(domain, digest, domainNameserver)
		if err != nil {
			// log.Println("[ERROR] DS calc failed: .", err)
		}
		r.Answer.CalculatedDS = calculatedDS
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

// checkDomainState
func checkDomainState(domain string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)

Redo:
	in, _, err := c.Exchange(m, "8.8.8.8:53")

	if err == nil {
		switch in.MsgHdr.Rcode {
		case dns.RcodeServerFailure:
			return "500, 502, The name server encountered an internal failure while processing this request (SERVFAIL)"
		case dns.RcodeNameError:
			return "500, 503, Some name that ought to exist, does not exist (NXDOMAIN)"
		case dns.RcodeRefused:
			return "500, 505, The name server refuses to perform the specified operation for policy or security reasons (REFUSED)"
		default:
			return "OK"
		}
	} else if err == dns.ErrTruncated {
		c.Net = "tcp"
		goto Redo
	} else {
		return "500, 501, DNS server could not be reached"
	}
}
