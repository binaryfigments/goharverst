package main

import (
	"encoding/json"
	"fmt"

	"github.com/binaryfigments/goharvest/dns/soa"
	"github.com/binaryfigments/goharvest/email/dkim"
	"github.com/binaryfigments/goharvest/email/dmarc"
	"github.com/binaryfigments/goharvest/email/mx"
	"github.com/binaryfigments/goharvest/email/spf"
	"github.com/binaryfigments/goharvest/http/headers"
	"github.com/binaryfigments/goharvest/http/redirects"
	"github.com/binaryfigments/goharvest/pki/certificate"
	"github.com/binaryfigments/goharvest/pki/ocsp"
)

func main() {

	URL := "www.ssl.nu"
	Header := "Server"
	Method := "GET"

	go jsonize(httpredirects.GetRedirects("http://ssl.nu"))
	go jsonize(pkiocsp.Run(URL))
	go jsonize(httpheaders.GetHTTPHeader("https://"+URL, Header, Method))
	go jsonize(emailmx.Get("networking4all.com", "8.8.8.8"))
	go jsonize(dnssoa.Get("ssl.nu", "8.8.8.8"))
	go jsonize(pkicertificate.Get("www.ssl.nu"))
	go jsonize(emaildkim.Get("networking4all.net", "8.8.8.8"))
	go jsonize(emaildmarc.Get("zwdelta.nl", "8.8.8.8"))

	testdata := emailspf.Get("ncsc.nl", "8.8.8.8")
	json, err := json.MarshalIndent(testdata, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)

}

func jsonize(data interface{}) {
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
}
