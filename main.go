package main

import (
	"encoding/json"
	"fmt"

	"github.com/binaryfigments/goharverst/checks/http"
	"github.com/binaryfigments/goharverst/checks/pki"
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

	redirs := httpheaders.GetRedirects("http://ssl.nu")
	jsonredirs, err := json.MarshalIndent(redirs, "", "   ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", jsonredirs)

}
