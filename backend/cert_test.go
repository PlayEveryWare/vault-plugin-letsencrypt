package backend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCert_NonExistent(t *testing.T) {
	storage := &logical.InmemStorage{}

	cert, err := getCert(t.Context(), storage, "nonexistent/path")
	require.NoError(t, err)
	assert.Nil(t, cert)
}

func TestCert_Serialization(t *testing.T) {
	storage := &logical.InmemStorage{}

	notAfter := time.Now().Add(265 * 24 * time.Hour)
	leaf, key := generateSelfSignedCert(t, "test.example.com", nil, notAfter)
	intermediate, _ := generateSelfSignedCert(t, "ca.example.com", nil, notAfter)

	originalCert := &cert{
		CertificateChain: []*x509.Certificate{leaf, intermediate},
		Key:              key,
	}

	const path = "certs/test"
	err := originalCert.write(t.Context(), storage, path)
	require.NoError(t, err)

	cert, err := getCert(t.Context(), storage, path)
	require.NoError(t, err)
	require.NotNil(t, cert)

	assertCertEqual(t, originalCert, cert)
}

func assertCertEqual(t *testing.T, expected *cert, actual *cert) {
	assertAccountKeyEqual(t, &expected.Key, &actual.Key)

	require.Equal(t, len(expected.CertificateChain), len(actual.CertificateChain))
	for ii, expectedCert := range expected.CertificateChain {
		actualCert := actual.CertificateChain[ii]
		assert.Equal(t, expectedCert.Raw, actualCert.Raw)
		assert.Equal(t, expectedCert.Subject, actualCert.Subject)
		assert.Equal(t, expectedCert.NotAfter, actualCert.NotAfter)
	}
}

func generateSelfSignedCert(t *testing.T, fqdn string, ips []net.IP, notAfter time.Time) (*x509.Certificate, accountKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Pebble Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              []string{fqdn},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	assertCertMatchesKey(t, cert, privateKey)

	return cert, accountKey{privateKey}
}

func assertCertMatchesKey(t *testing.T, cert *x509.Certificate, key crypto.PrivateKey) {
	pub := cert.PublicKey

	switch priv := key.(type) {
	case *rsa.PrivateKey:
		pubKey, ok := pub.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, 0, pubKey.N.Cmp(priv.N))
		assert.Equal(t, priv.E, pubKey.E)

	case *ecdsa.PrivateKey:
		pubKey, ok := pub.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, 0, pubKey.X.Cmp(priv.X))
		assert.Equal(t, 0, pubKey.Y.Cmp(priv.Y))

	case *ed25519.PrivateKey:
		pubKey, ok := pub.(*ed25519.PublicKey)
		require.True(t, ok)
		assert.True(t, pubKey.Equal(priv.Public().(ed25519.PublicKey)))

	default:
		t.Fatalf("Unhandled private key %T", priv)
	}
}
