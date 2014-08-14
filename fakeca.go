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
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/facebookgo/stackerr"
)

type Generator struct {
	MaxAge       time.Duration
	RootLocation string
	RootName     string
}

func (g *Generator) certFileName() string {
	return filepath.Join(g.RootLocation, "root-cert.pem")
}

func (g *Generator) keyFileName() string {
	return filepath.Join(g.RootLocation, "root-key.pem")
}

func (g *Generator) genRootCA() error {
	certFileName := g.certFileName()
	keyFileName := g.keyFileName()

	if _, err := os.Stat(certFileName); !os.IsNotExist(err) {
		return stackerr.Newf("%s must not exist", certFileName)
	}
	if _, err := os.Stat(keyFileName); !os.IsNotExist(err) {
		return stackerr.Newf("%s must not exist", keyFileName)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return stackerr.Wrap(err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: g.RootName,
		},
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.Add(g.MaxAge),
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return stackerr.Wrap(err)
	}

	certOut, err := os.Create(certFileName)
	if err != nil {
		return stackerr.Wrap(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("Written " + certFileName + "\n")

	keyOut, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return stackerr.Wrap(err)
	}
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	keyOut.Close()
	log.Print("Written " + keyFileName + "\n")
	return nil
}

func (g *Generator) loadPem(filename string) (*pem.Block, error) {
	in, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, stackerr.Wrap(err)
	}
	b, _ := pem.Decode(in)
	if b == nil {
		return nil, stackerr.Newf("failed to pem decode %s", filename)
	}
	return b, nil
}

func (g *Generator) loadRootCA() (*x509.Certificate, error) {
	p, err := g.loadPem(g.certFileName())
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, stackerr.Wrap(err)
	}
	return cert, nil
}

func (g *Generator) loadRootCAKey() (*rsa.PrivateKey, error) {
	p, err := g.loadPem(g.keyFileName())
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return nil, stackerr.Wrap(err)
	}
	return key, nil
}

func (g *Generator) genForNames(names string) error {
	certFileName := "cert.pem"
	keyFileName := "key.pem"

	rootCert, err := g.loadRootCA()
	if err != nil {
		return err
	}

	rootKey, err := g.loadRootCAKey()
	if err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return stackerr.Wrap(err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: names,
		},
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.Add(g.MaxAge),
		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, rootCert, &priv.PublicKey, rootKey)
	if err != nil {
		return stackerr.Wrap(err)
	}

	certOut, err := os.Create(certFileName)
	if err != nil {
		return stackerr.Wrap(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("Written " + certFileName + "\n")

	keyOut, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return stackerr.Wrap(err)
	}
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	keyOut.Close()
	log.Print("Written " + keyFileName + "\n")
	return nil
	return nil
}

func defaultLocation() string {
	u, _ := user.Current()
	if u != nil {
		return filepath.Join(u.HomeDir, ".ca")
	}
	return ""
}

func main() {
	g := Generator{MaxAge: time.Hour * 24 * 365 * 10}

	flag.StringVar(
		&g.RootLocation,
		"dir",
		defaultLocation(),
		"Default location to store root certificate and key.")
	flag.StringVar(
		&g.RootName,
		"name",
		strings.Title(os.Getenv("USER")+" CA"),
		"The name used for various purposes.")

	genRoot := flag.Bool("root", false, "generate root certificate and key")
	genNames := flag.String("names", "", "generate certificate with given names")

	flag.Parse()

	if !*genRoot && *genNames == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *genRoot {
		if err := g.genRootCA(); err != nil {
			log.Fatal(err)
		}
	}

	if *genNames != "" {
		if err := g.genForNames(*genNames); err != nil {
			log.Fatal(err)
		}
	}
}
