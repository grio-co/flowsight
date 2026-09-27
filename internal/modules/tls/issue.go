package tls

// Server certificates for FlowSight itself, signed by the inspection CA.
//
// The web interface and API are served over HTTPS so a token or session
// cookie never crosses the network in clear. A device that already trusts
// the inspection CA (it was installed for TLS inspection) trusts this
// certificate too, without a warning; everything else sees the usual
// untrusted-certificate prompt, which is still encryption.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"time"
)

// IssueServerCert returns a PEM certificate and key for the given names and
// addresses, valid for days, signed by the inspection CA. It fails when
// there is no CA; the caller then makes its own self-signed certificate.
func (m *Module) IssueServerCert(names []string, ips []net.IP, days int) ([]byte, []byte, error) {
	cb, err := os.ReadFile(m.certPath())
	if err != nil {
		return nil, nil, errors.New("no inspection CA")
	}
	kb, err := os.ReadFile(m.keyPath())
	if err != nil {
		return nil, nil, errors.New("no inspection CA key")
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, nil, errors.New("unreadable inspection CA")
	}
	ca, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caKey, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if days <= 0 || days > 397 {
		days = 397 // the ceiling browsers accept for a server certificate
	}
	cn := "flowsight"
	if len(names) > 0 {
		cn = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"FlowSight"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  ips,
	}
	if tmpl.NotAfter.After(ca.NotAfter) {
		tmpl.NotAfter = ca.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPEM = append(certPEM, cb...) // the chain, so clients that know the CA need nothing else
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
