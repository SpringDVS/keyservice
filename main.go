package main 

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	fmt.Println("Spring Key Management Service (v1.0)")
    http.HandleFunc("/genkey", HandleActionGenerateKey)
    http.HandleFunc("/expand", HandleActionExpandKey)
    http.HandleFunc("/sign", HandleActionSignKey)
    http.HandleFunc("/update", HandleActionUpdateKey)

  	
    log.Fatal(http.ListenAndServe(":55500", nil))
}

