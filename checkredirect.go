package main

import (
	"encoding/json"
	"fmt"

	"github.com/binaryfigments/goharvest/http/redirects"
)

func main() {
	jsonize(httpredirects.Get("http://ssl.nu"))
}

func jsonize(data interface{}) {
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
}
