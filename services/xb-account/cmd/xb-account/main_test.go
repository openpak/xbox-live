package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestMutualTLSWorkloadAuthorization(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test xb CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	server.TLS = workloadTLS(pool)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.Certificate())
	for index, tc := range []struct {
		uri  string
		want bool
	}{
		{"spiffe://openpak/xb-auth", true}, {"spiffe://openpak/xb-gateway", true}, {"spiffe://openpak/xb-enroll", true}, {"spiffe://openpak/xb-social", true},
		{"spiffe://openpak/x360-auth", false}, {"spiffe://openpak/xb-tou", false},
		{"", false}, {"missing-certificate", false},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			tlsConfig := &tls.Config{RootCAs: serverRoots, MinVersion: tls.VersionTLS13}
			if tc.uri != "missing-certificate" {
				clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				cert := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 2)), Subject: pkix.Name{CommonName: "test client"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
				if tc.uri != "" {
					uri, _ := url.Parse(tc.uri)
					cert.URIs = []*url.URL{uri}
				}
				leaf, err := x509.CreateCertificate(rand.Reader, cert, root, &clientKey.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				private, err := x509.MarshalPKCS8PrivateKey(clientKey)
				if err != nil {
					t.Fatal(err)
				}
				identity, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
				if err != nil {
					t.Fatal(err)
				}
				tlsConfig.Certificates = []tls.Certificate{identity}
			}
			transport := &http.Transport{TLSClientConfig: tlsConfig}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := client.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != tc.want {
				t.Fatalf("TLS result %v, want authorized=%v", err, tc.want)
			}
		})
	}
}
