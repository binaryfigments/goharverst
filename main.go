package main

// This is an example, not for real use.

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/binaryfigments/goharvest/pki/certificate"
)

func main() {
	var wg sync.WaitGroup

	// TODO: Some testing

	// wg.Add(1)
	// go jsonizewg(httpheaders.ReturnHeaders("ssl.nu", "https"), &wg)
	// wg.Add(1)
	// go jsonizewg(httpredirects.Get("http://ssl.nu"), &wg)
	wg.Add(1)
	go jsonizewg(pkicertificate.Get("www.ssl.nu", 443, "https"), &wg)

	wg.Wait()
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
