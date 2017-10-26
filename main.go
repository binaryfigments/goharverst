package main

import (
	"encoding/json"
	"fmt"

	"github.com/binaryfigments/goharvest/dns/soa"
	"github.com/binaryfigments/goharvest/email/mx"
	"github.com/binaryfigments/goharvest/email/spf"
	"github.com/binaryfigments/goharvest/http/headers"
	"github.com/binaryfigments/goharvest/http/redirects"
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

	// go jsonize(pkicertificate.Get("www.ssl.nu"))
	/*
		certdata := pkicertificate.Get("www.ssl.nu")
		json, err := json.MarshalIndent(certdata, "", "  ")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%s\n", json)
	*/
	spfdata := emailspf.Get("networking4all.com", "8.8.8.8")

	json, err := json.MarshalIndent(spfdata, "", "  ")
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
