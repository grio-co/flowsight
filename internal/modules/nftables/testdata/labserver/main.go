// labserver answers HTTP on each address:port given, with a body naming
// what answered, for the nftables and web labs (lab_test.go,
// test/web-lab.sh). An address given as tls:address:port answers HTTPS
// instead, with a self-signed certificate for lab.test.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

func selfSigned() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lab.test"},
		DNSNames: []string{"lab.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	for _, addr := range os.Args[1:] {
		a := addr
		go func() {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "answered by %s\n", a)
			})
			var err error
			if l, ok := strings.CutPrefix(a, "tls:"); ok {
				srv := &http.Server{Addr: l, Handler: h,
					TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned()}}}
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = http.ListenAndServe(a, h)
			}
			fmt.Fprintln(os.Stderr, a, err)
		}()
	}
	select {}
}
