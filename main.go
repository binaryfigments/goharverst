package main

// This is an example, not for real use.

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/binaryfigments/goharvest/dns/axfr"
)

func main() {
	// var wg *sync.WaitGroup
	// TODO: Some testing
	// wg.Add(1)
	// go jsonizewg(pkicertificate.Get("www.ssl.nu", 443, "https"), wg)
	// wg.Wait()

	axfrdata := dnsaxfr.Get("zonetransfer.me", "nsztm1.digi.ninja.")
	json, err := json.MarshalIndent(axfrdata, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)

	fmt.Println("Done")
}

func jsonizewg(data interface{}, wg *sync.WaitGroup) {
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
	wg.Done()
}
