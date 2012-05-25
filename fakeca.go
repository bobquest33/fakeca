// Command fakeca allows for generating a fake CA certificate and
// allows for issuing certificates based on a given CA.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

var (
	baseName = flag.String(
		"name",
		os.Getenv("USER")+" CA",
		"The name used for various purposes.")
	maxAge = flag.Duration(
		"max-age",
		time.Hour*24*365*5,
		"The validity period of he certificate.")
)

func certFileName() string {
	return *baseName + " Certificate.pem"
}

func keyFileName() string {
	return *baseName + " Key.pem"
}

func genCACert() {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   *baseName,
			Organization: []string{*baseName},
		},
		NotBefore:    now.Add(-5 * time.Minute).UTC(),
		NotAfter:     now.Add(*maxAge),
		IsCA:         true,
		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create CA Certificate: %s", err)
		return
	}

	certOut, err := os.Create(certFileName())
	if err != nil {
		log.Fatalf("Failed to open "+certFileName()+" for writing: %s", err)
		return
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("Written " + certFileName() + "\n")

	keyOut, err := os.OpenFile(keyFileName(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("Failed to open "+keyFileName()+" for writing:", err)
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("Written " + keyFileName() + "\n")
}

func showCert() {
	certIn, err := ioutil.ReadFile(certFileName())
	if err != nil {
		log.Fatalf("Failed to open "+certFileName()+" for reading: %s", err)
	}
	b, _ := pem.Decode(certIn)
	if b == nil {
		log.Fatalf("Failed to find a certificate in " + certFileName())
	}
	caCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate in " + certFileName())
	}
	log.Printf("%+v", caCert)
}

func main() {
	genCACert()
	showCert()
}
