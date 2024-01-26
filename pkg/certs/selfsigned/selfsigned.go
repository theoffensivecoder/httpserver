package selfsigned

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// New generates a self-signed certificate for the given hostname and email address
// using ECDSA and P-256.
// Based largely on https://go.dev/src/crypto/tls/generate_cert.go
func New(hostname string, email string) (tls.Certificate, error) {
	// Generate private key
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	caCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"4ARMED Certificate Authority"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 1),
		KeyUsage:  keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		EmailAddresses:        []string{email},
		IsCA:                  true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caCert, &caCert, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		return tls.Certificate{}, err
	}

	caKeyBytes, err := x509.MarshalECPrivateKey(caPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	caPrivateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivateKeyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: caKeyBytes})
	if err != nil {
		return tls.Certificate{}, err
	}

	// We have now created our CA certificate and private key
	// in caPEM and caPrivateKeyPEM.
	// Now we create a cert for our server signed by the CA.

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"4ARMED"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 1),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		DNSNames:     []string{hostname},
		EmailAddresses: []string{
			email,
		},
	}

	if hostname == "" {
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
	}

	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &cert, &caCert, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return tls.Certificate{}, err
	}

	certKeyBytes, err := x509.MarshalECPrivateKey(certPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPrivateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivateKeyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: certKeyBytes})
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM.Bytes(), certPrivateKeyPEM.Bytes())
}
