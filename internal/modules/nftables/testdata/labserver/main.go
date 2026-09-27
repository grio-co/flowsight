// labserver answers HTTP on each address:port given, with a body naming
// what answered, for the nftables lab test (lab_test.go).
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	for _, addr := range os.Args[1:] {
		a := addr
		go func() {
			err := http.ListenAndServe(a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "answered by %s\n", a)
			}))
			fmt.Fprintln(os.Stderr, a, err)
		}()
	}
	select {}
}
