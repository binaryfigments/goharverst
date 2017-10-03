package main

import (
	"encoding/json"
	"fmt"

	"github.com/binaryfigments/goharverst/dns/soa"
	"github.com/binaryfigments/goharverst/email/mx"
	"github.com/binaryfigments/goharverst/http/headers"
	"github.com/binaryfigments/goharverst/http/redirects"
	"github.com/binaryfigments/goharverst/pki/ocsp"
)

func main() {

	URL := "www.ssl.nu"
	Header := "Server"
	Method := "GET"

	httpserver := httpheaders.GetHTTPHeader("https://"+URL, Header, Method)

	jsonserver, err := json.MarshalIndent(httpserver, "", "   ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", jsonserver)

	ocsp := pkiocsp.Run(URL)
	jsonocsp, err := json.MarshalIndent(ocsp, "", "   ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", jsonocsp)

	redirs := httpredirects.GetRedirects("http://ssl.nu")
	jsonredirs, err := json.MarshalIndent(redirs, "", "   ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", jsonredirs)

	mailmx := emailmx.Get("networking4all.com", "8.8.8.8")
	jsonmailmx, err := json.MarshalIndent(mailmx, "", "   ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", jsonmailmx)

	getsoa := dnssoa.Get("ssl.nu", "8.8.8.8")
	jsongetsoa, err := json.MarshalIndent(getsoa, "", "   ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", jsongetsoa)
}
