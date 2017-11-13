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

	URL := "ssl.nu"
	Header := "Server"
	Method := "GET"

	go jsonize(httpredirects.Get("http://" + URL))
	go jsonize(pkiocsp.Run(URL))
	go jsonize(httpheaders.GetHTTPHeader("https://"+URL, Header, Method))
	go jsonize(dnssoa.Get(URL, "8.8.8.8"))
	go jsonize(pkicertificate.Get(URL))
	go jsonize(emaildkim.Get(URL, "8.8.8.8"))
	go jsonize(emaildmarc.Get(URL, "8.8.8.8"))
	go jsonize(emailmx.Get(URL, "8.8.8.8"))

	testdata := emailspf.Get(URL, "8.8.8.8")
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
