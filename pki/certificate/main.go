// TODO: Need some restructureing!

package pkicertificate

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"golang.org/x/net/idna"

	log "github.com/Sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint"
)

func Get(fqdn string) CertWithLint {
	raw, err := getRemoteCertificate(fqdn)
	var result string
	var resultmessage string
	if err != nil {
		result = "FAILED"
		resultmessage = "Could not get remote certificate. (1)"
		checkResult := CertWithLint{
			Result:        result,
			ResultMessage: resultmessage,
		}
		return checkResult
	}
	// raw := getCertificate("test2.cer")
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		result = "FAILED"
		resultmessage = "Could not parse certificate. (2)"
		checkResult := CertWithLint{
			Result:        result,
			ResultMessage: resultmessage,
		}
		return checkResult
	}

	zlintResult := zlint.LintCertificate(parsed)
	result = "OK"
	checkResult := CertWithLint{
		Result:        result,
		ResultMessage: resultmessage,
		Raw:           parsed.Raw,
		Parsed:        parsed,
		ZLint:         zlintResult,
	}

	return checkResult
}

func getCertificate(file string) []byte {
	derBytes, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	// decode pem
	block, _ := pem.Decode(derBytes)
	if block != nil {
		derBytes = block.Bytes
	}
	return derBytes
}

func getRemoteCertificate(fqdn string) ([]byte, error) {
	fqdn, err := idna.ToASCII(fqdn)
	if err != nil {
		return nil, err
	}

	_, err = net.ResolveIPAddr("ip", fqdn)
	if err != nil {
		return nil, err
	}

	dialconf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", fqdn+":443", dialconf)
	if err != nil {
		log.Fatalf("dial error: %s", err)
		return nil, err
	}

	connState := conn.ConnectionState()
	peerChain := connState.PeerCertificates
	if len(peerChain) == 0 {
		err = errors.New("invalid certificate presented")
		if err != nil {
			return nil, err
		}
	}

	return peerChain[0].Raw, nil
}

// CertWithLint struct
type CertWithLint struct {
	Result        string            `json:"result,omitempty"`
	ResultMessage string            `json:"resultmessage,omitempty"`
	Parsed        *x509.Certificate `json:"parsed,omitempty"`
	ZLint         *zlint.ResultSet  `json:"zlint,omitempty"`
	Raw           []byte            `json:"raw,omitempty"`
}

// ResponseHeaders struct
type ResponseHeaders struct {
	Result        string      `json:"result,omitempty"`
	ResultMessage string      `json:"resultmessage,omitempty"`
	Headers       interface{} `json:"headers,omitempty"`
}
