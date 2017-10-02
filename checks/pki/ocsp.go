// TODO: Need some restructureing!

package pkiocsp

import (
	"bytes"
	"crypto"
	_ "crypto/sha256" // useg for crypto
	"crypto/tls"
	"crypto/x509"
	"encoding/base64" // used in requesting OCSP response
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/idna"
)

// Run function for starting the check
func Run(cn string) *OCSPInfo {
	r := new(OCSPInfo)
	r.CommonName = cn

	// Some vars for use later.
	var (
		err              error
		cert             *x509.Certificate
		ocspResponse     *ocsp.Response
		ocspServer       string
		ocspUnauthorised = []byte{0x30, 0x03, 0x0a, 0x01, 0x06}
		ocspMalformed    = []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
		hasPort          = regexp.MustCompile(`:\d+$`)
	)

	// Valid server name (ASCII or IDN)
	cn, err = idna.ToASCII(cn)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		// r.ErrorMessage = "Non ASCII or IDN characters in domain."
		return r
	}

	_, err = net.ResolveIPAddr("ip", cn)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		// r.ErrorMessage = "Error resolving an IP address for: " + server
		return r
	}

	if !hasPort.MatchString(cn) {
		cn += ":443"
	}

	dialconf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", cn, dialconf)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = err.Error()
		// r.ErrorMessage = "Error connecting to server:" + cn
		return r
	}

	connState := conn.ConnectionState()
	peerChain := connState.PeerCertificates
	if len(peerChain) == 0 {
		r.Error = "Failed"
		r.ErrorMessage = "invalid certificate presented"
		return r
	}

	cert = peerChain[0]

	res := conn.OCSPResponse()
	if res != nil {
		r.Stapled = "Yes"
		ocspResponse, err = ocsp.ParseResponse(res, nil)
		if err != nil {
			r.Error = "Failed"
			r.ErrorMessage = err.Error()
			// r.ErrorMessage = "Error: Can not get stapling response"
			return r
		}

		r.OCSPResponse = showOCSPResponse(ocspResponse, nil)
		conn.Close()
		return r
	}
	conn.Close()

	ocspURLs := cert.OCSPServer

	if len(ocspURLs) == 0 {
		if ocspServer == "" {
			r.Error = "Failed"
			r.ErrorMessage = "Error: No OCSP URLs found in cert, and none given from the app."
			return r
		}
		ocspURLs = []string{ocspServer}
	}
	var issuer *x509.Certificate
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			continue
		}
		break
	}

	if issuer == nil {
		r.Error = "Failed"
		r.ErrorMessage = "Error: No issuing certificate could be found."
		return r
	}

	opts := ocsp.RequestOptions{
		Hash: crypto.SHA1,
	}

	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &opts)
	if err != nil {
		r.Error = "Failed"
		r.ErrorMessage = "Error in ocspRequest"
		return r
	}

	for _, ocspserver := range ocspURLs {
		r.Stapled = "No"
		r.OCSPServer = ocspserver

		var resp *http.Response
		if len(ocspRequest) > 256 {
			buf := bytes.NewBuffer(ocspRequest)
			resp, err = http.Post(ocspserver, "application/ocsp-request", buf)
		} else {
			reqURL := ocspserver + "/" + base64.StdEncoding.EncodeToString(ocspRequest)
			resp, err = http.Get(reqURL)
		}

		if err != nil {
			r.OCSPResponseMessage = "Unknown error OCSP lookup."
			continue
		}

		if resp.StatusCode != http.StatusOK {
			r.OCSPResponseMessage = "Invalid OCSP response from server" + ocspserver
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			r.OCSPResponseMessage = "Failed to read response body."
			continue
		}
		resp.Body.Close()

		if bytes.Equal(body, ocspUnauthorised) {
			r.OCSPResponseMessage = "OCSP request unauthorised."
			continue
		}

		if bytes.Equal(body, ocspMalformed) {
			r.OCSPResponseMessage = "OCSP server did not understand the request."
			continue
		}

		ocspResponse, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			r.OCSPResponseMessage = "Invalid OCSP response from server."
			ioutil.WriteFile("/tmp/ocsp.bin", body, 0644)
			continue
		}

		r.OCSPResponse = showOCSPResponse(ocspResponse, issuer)
	}
	return r
}

func showOCSPResponse(res *ocsp.Response, issuer *x509.Certificate) *OCSPResponse {
	OcspResp := new(OCSPResponse)
	switch res.Status {
	case ocsp.Good:
		OcspResp.CertificateStatus = "Good"
	case ocsp.Revoked:
		OcspResp.CertificateStatus = "Revoked"
	case ocsp.ServerFailed:
		OcspResp.CertificateStatus = "Server Failed"
	case ocsp.Unknown:
		OcspResp.CertificateStatus = "Unknown"
	default:
		OcspResp.CertificateStatus = "Unknown response received from server"
	}

	OcspResp.CertificateSerial = res.SerialNumber
	OcspResp.TimeStatusProduced = res.ProducedAt
	OcspResp.TimeCurrentUpdate = res.ThisUpdate
	OcspResp.TimeNextUpdate = res.NextUpdate

	if res.Status == ocsp.Revoked {
		OcspResp.CertificateRevokedAt = res.RevokedAt
		OcspResp.CertificateRevocationReason = res.RevocationReason
	}

	if issuer != nil && res.Certificate == nil {
		if err := res.CheckSignatureFrom(issuer); err == nil {
			OcspResp.SignatureStatus = "OK"
		} else {
			OcspResp.SignatureStatus = "Bad signature on response (maybe wrong OCSP issuer cert?)"
		}
	}
	return OcspResp
}

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

// OCSPInfo struct
type OCSPInfo struct {
	CommonName          string        `json:"commonname,omitempty"`
	Error               string        `json:"error,omitempty"`
	ErrorMessage        string        `json:"errormessage,omitempty"`
	Stapled             string        `json:"stapled,omitempty"`
	OCSPServer          string        `json:"ocsp_server,omitempty"`
	OCSPResponse        *OCSPResponse `json:"ocsp_response,omitempty"`
	OCSPResponseMessage string        `json:"ocsp_response_message,omitempty"`
}

// OCSPResponse struct
type OCSPResponse struct {
	CertificateStatus           string    `json:"certificate_status"`
	CertificateSerial           *big.Int  `json:"certificate_cerial"`
	TimeStatusProduced          time.Time `json:"time_status_produced"`
	TimeCurrentUpdate           time.Time `json:"time_current_update"`
	TimeNextUpdate              time.Time `json:"time_next_update"`
	SignatureStatus             string    `json:"signature_status"`
	CertificateRevokedAt        time.Time `json:"certificate_revoked_at"`
	CertificateRevocationReason int       `json:"certificate_revocation_reason"`
}
