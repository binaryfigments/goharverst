package main

// This is an example, not for real use.

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/binaryfigments/goharvest/dns/dnssec"
)

func main() {
	// var wg *sync.WaitGroup
	// TODO: Some testing
	// wg.Add(1)
	// go jsonizewg(pkicertificate.Get("www.ssl.nu", 443, "https"), wg)
	// wg.Wait()

	dnssecdata := dnsdnssec.Get("sslcertificaten.co.nl", "8.8.8.8")
	json, err := json.MarshalIndent(dnssecdata, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
}

func jsonizewg(data interface{}, wg *sync.WaitGroup) {
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
	wg.Done()
}
