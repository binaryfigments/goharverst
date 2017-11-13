package pkicertificate

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/smtp"
	"strconv"

	"github.com/zmap/zcrypto/x509"
	"golang.org/x/net/idna"
)

// Certificates struct
type Certificates struct {
	FQDN         string `json:"fqdn,omitempty"`
	Port         int    `json:"port,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"errormessage,omitempty"`
	// Certificates []*x509.Certificate      `json:"certificates,omitempty"`
	// Parsed []*x509.ParseCertificate `json:"parsed,omitempty"`
	Parsed []*x509.Certificate `json:"parsed,omitempty"`
	Raw    []byte              `json:"raw,omitempty"`
}

// Get function for starting the check
func Get(fqdn string, port int, protocol string) *Certificates {
	r := new(Certificates)

	r.FQDN = fqdn
	r.Port = port

	// Valid server name (ASCII or IDN)
	fqdn, err := idna.ToASCII(fqdn)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	_, err = net.ResolveIPAddr("ip", fqdn)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		return r
	}

	var peerChain []*x509.Certificate

	switch protocol {
	case "https":
		dialconf := &tls.Config{
			InsecureSkipVerify: true,
		}

		fqdnport := fqdn + ":" + strconv.Itoa(port)

		conn, err := tls.Dial("tcp", fqdnport, dialconf)
		if err != nil {
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
			return r
		}

		connState := conn.ConnectionState()
		peerChain := connState.PeerCertificates
		if len(peerChain) == 0 {
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
			return r
		}
		conn.Close()
	case "smtp":
		tlsconfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         fqdn,
		}

		c, err := smtp.Dial(fqdn)
		if err != nil {
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
			return r
		}

		c.StartTLS(tlsconfig)

		cs, ok := c.TLSConnectionState()
		if !ok {
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
			return r
		}
		c.Quit()

		peerChain := cs.PeerCertificates
		if len(peerChain) == 0 {
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
			return r
		}
	}

	// r.Certificates = peerChain
	for _, peer := range peerChain {
		parsed, err := x509.ParseCertificate(peer.Raw)
		if err != nil {
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
			return r
		}
		r.Parsed = append(r.Parsed, parsed)
	}

	return r
}

// For later use
func parseCert(in []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate")
		}
		in = p.Bytes
	}
	return x509.ParseCertificate(in)
}

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return parseCert(in)
}
