package backend

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathCerts_ExistingCertificate(t *testing.T) {
	b := createTestBackend(t)

	const (
		account  = "test-account"
		provider = "none"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	leaf, key := generateSelfSignedCert(t, fqdn, nil, time.Now(), notAfter)

	originalCert := &cert{
		CertificateChain: []*x509.Certificate{leaf},
		Key:              key,
	}
	err := originalCert.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req := &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	require.NotNil(t, resp.Secret)
	assert.Equal(t, path, resp.Secret.InternalData["path"])

	expectedTTL := time.Until(notAfter) - 30*24*time.Hour
	if expectedTTL < 1*time.Hour {
		expectedTTL = 1 * time.Hour
	}
	actualTTL := resp.Secret.LeaseOptions.TTL
	assert.True(t, actualTTL >= time.Hour, "TTL should be at least 1 hour")
	assert.InDelta(t, expectedTTL.Seconds(), actualTTL.Seconds(), 300)
	assert.True(t, resp.Secret.LeaseOptions.Renewable)

	privateKeyPEM, ok := resp.Data["private_key"].(string)
	require.True(t, ok)
	block, _ := pem.Decode([]byte(privateKeyPEM))
	require.NotNil(t, block)
	newPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	certPEM, ok := resp.Data["certificate"].(string)
	require.True(t, ok)
	block, _ = pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	newCertificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	newCert := &cert{
		CertificateChain: []*x509.Certificate{newCertificate},
		Key:              accountKey{newPrivateKey},
	}
	assertCertEqual(t, originalCert, newCert)
}

func TestPathCerts_NonExistentAccount(t *testing.T) {
	b := createTestBackend(t)

	const (
		account  = "test-account"
		provider = "none"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	req := &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Error(t, resp.Error())
}

func TestPathCerts_BadProvider(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const (
		account  = "test-account"
		provider = "error-provider"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	providerError := errors.New("bad DNS provider")
	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return nil, providerError
	})

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "DNS")
}

func TestPathCerts_IssuesNew(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const (
		account  = "test-account"
		provider = "test-dns"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return as, nil
	})

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	certs, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	require.NotEmpty(t, certs)

	key, err := certcrypto.ParsePEMPrivateKey([]byte(resp.Data["private_key"].(string)))
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Contains(t, certcrypto.ExtractDomains(certs[0]), fqdn)
	assertCertMatchesKey(t, certs[0], key)
}

func TestPathCerts_IssuesNew_AltNames(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const (
		account  = "test-account"
		provider = "test-dns"
		fqdn     = "node1.example.com"
		alt1     = "service.example.com"
		alt2     = "node1-alt.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return as, nil
	})

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
		Data: map[string]interface{}{
			"alt_names": []string{alt1, alt2},
		},
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	certs, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	require.NotEmpty(t, certs)

	domains := certcrypto.ExtractDomains(certs[0])
	assert.Contains(t, domains, fqdn)
	assert.Contains(t, domains, alt1)
	assert.Contains(t, domains, alt2)

	stored, err := getCert(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{alt1, alt2}, stored.AltNames)

	// Renewal-style read with no alt_names supplied. Cert is still in
	// the renewal window so the cached cert should come back unchanged,
	// preserving the stored AltNames.
	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	cached, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	cachedDomains := certcrypto.ExtractDomains(cached[0])
	assert.Contains(t, cachedDomains, fqdn)
	assert.Contains(t, cachedDomains, alt1)
	assert.Contains(t, cachedDomains, alt2)
}

func TestPathCerts_AltNamesChange_ForcesReissue(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const (
		account  = "test-account"
		provider = "test-dns"
		fqdn     = "node1.example.com"
		alt1     = "service.example.com"
		alt2     = "node1-alt.example.com"
		altNew   = "extra.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return as, nil
	})

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	// First issuance with alt1+alt2.
	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
		Data: map[string]interface{}{
			"alt_names": []string{alt1, alt2},
		},
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NoError(t, resp.Error())

	firstCerts, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	firstSerial := firstCerts[0].SerialNumber

	// Re-read with the same set in a different order — should be a
	// cache hit (no re-issuance), so the serial number stays the same.
	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
		Data: map[string]interface{}{
			"alt_names": []string{alt2, alt1},
		},
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NoError(t, resp.Error())

	sameOrderCerts, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	assert.Equal(t, 0, firstSerial.Cmp(sameOrderCerts[0].SerialNumber),
		"reorder-only alt_names should not force re-issuance")

	// Re-read with a genuinely different list — should re-issue
	// (different serial) and update the stored AltNames.
	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
		Data: map[string]interface{}{
			"alt_names": []string{alt1, altNew},
		},
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NoError(t, resp.Error())

	newCerts, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	assert.NotEqual(t, 0, firstSerial.Cmp(newCerts[0].SerialNumber),
		"changed alt_names should force re-issuance")

	newDomains := certcrypto.ExtractDomains(newCerts[0])
	assert.Contains(t, newDomains, fqdn)
	assert.Contains(t, newDomains, alt1)
	assert.Contains(t, newDomains, altNew)
	assert.NotContains(t, newDomains, alt2)

	stored, err := getCert(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{alt1, altNew}, stored.AltNames)
}

func TestPathCerts_IssuesNew_AccountDNSResolvers(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	// Move the test resolver from the backend (test back-door) onto the
	// account so this test exercises the per-account configuration path.
	resolvers := b.dnsResolvers
	b.dnsResolvers = nil
	b.skipAuthoritativeNSCheck = false

	const (
		account  = "test-account"
		provider = "test-dns"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return as, nil
	})

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":                       "test@example.com",
			"directory_url":               as.DirectoryURL,
			"tos_agreed":                  true,
			"dns_resolvers":               resolvers,
			"skip_authoritative_ns_check": true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	certs, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	require.NotEmpty(t, certs)
	assert.Contains(t, certcrypto.ExtractDomains(certs[0]), fqdn)
}

func TestPathCerts_Renew(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const (
		account  = "test-account"
		provider = "test-dns"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return as, nil
	})

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	notAfter := time.Now().Add(-time.Hour)
	leaf, key := generateSelfSignedCert(t, fqdn, nil, time.Now(), notAfter)

	originalCert := &cert{
		CertificateChain: []*x509.Certificate{leaf},
		Key:              key,
	}
	err = originalCert.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	certs, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	require.NotEmpty(t, certs)

	privKey, err := certcrypto.ParsePEMPrivateKey([]byte(resp.Data["private_key"].(string)))
	require.NoError(t, err)
	require.NotNil(t, privKey)

	assert.Contains(t, certcrypto.ExtractDomains(certs[0]), fqdn)
	assertCertMatchesKey(t, certs[0], privKey)
	assert.True(t, certs[0].NotAfter.After(time.Now()))
}

func TestPathCerts_LeaseRenewal(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const (
		account  = "test-account"
		provider = "test-dns"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return as, nil
	})

	// Create account
	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	// Issue initial certificate
	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	require.NotNil(t, resp.Secret)
	assert.True(t, resp.Secret.LeaseOptions.Renewable, "Secret should be renewable")
	assert.Equal(t, path, resp.Secret.InternalData["path"])

	req = &logical.Request{
		Storage:   b.Storage,
		Secret:    resp.Secret,
		Operation: logical.RenewOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	certPEM, ok := resp.Data["certificate"].(string)
	require.True(t, ok, "Certificate should be present in response")
	require.NotEmpty(t, certPEM)

	privateKeyPEM, ok := resp.Data["private_key"].(string)
	require.True(t, ok, "Private key should be present in response")
	require.NotEmpty(t, privateKeyPEM)

	initialCerts, err := certcrypto.ParsePEMBundle([]byte(certPEM))
	require.NoError(t, err)
	require.NotEmpty(t, initialCerts)
	assert.Contains(t, certcrypto.ExtractDomains(initialCerts[0]), fqdn)
}

func TestPathCerts_LeaseRevoke(t *testing.T) {
	b := createTestBackend(t)

	const (
		account  = "test-account"
		provider = "none"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	leaf, key := generateSelfSignedCert(t, fqdn, nil, time.Now(), notAfter)

	originalCert := &cert{
		CertificateChain: []*x509.Certificate{leaf},
		Key:              key,
	}
	err := originalCert.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req := &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Secret)

	req = &logical.Request{
		Storage:   b.Storage,
		Secret:    resp.Secret,
		Operation: logical.RevokeOperation,
	}

	_, err = b.HandleRequest(t, req)
	require.NoError(t, err)

	cert, err := getCert(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestPathCerts_Issues_Nil(t *testing.T) {
	b := createTestBackend(t)

	cleanup := WithEnvOverrides(map[string]string{
		"PEBBLE_VA_ALWAYS_VALID": "1",
	})
	defer cleanup()

	as := b.startACMEServer(t, WithoutDNSResolver())
	defer as.Close()

	const (
		account  = "test-account"
		provider = "nil"
		fqdn     = "test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	certs, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	require.NotEmpty(t, certs)

	key, err := certcrypto.ParsePEMPrivateKey([]byte(resp.Data["private_key"].(string)))
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Contains(t, certcrypto.ExtractDomains(certs[0]), fqdn)
	assertCertMatchesKey(t, certs[0], key)
}

func TestPathCerts_IssuesNew_Wildcard(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const (
		account  = "test-account"
		provider = "test-dns"
		fqdn     = "*.test.example.com"
	)

	path := MakeDNS01Path(account, provider, fqdn)

	b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
		return as, nil
	})

	accountPath := "accounts/" + account
	req := &logical.Request{
		Path:      accountPath,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	req = &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	certs, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
	require.NoError(t, err)
	require.NotEmpty(t, certs)

	key, err := certcrypto.ParsePEMPrivateKey([]byte(resp.Data["private_key"].(string)))
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Contains(t, certcrypto.ExtractDomains(certs[0]), fqdn)
	assertCertMatchesKey(t, certs[0], key)
}

func TestPathCerts_Renews_TwoThirds(t *testing.T) {
	type testCase struct {
		Desc        string
		NotBefore   time.Time
		NotAfter    time.Time
		ShouldRenew bool
	}

	tests := []testCase{
		// Current 90 day certs
		{
			Desc:        "90d-cert do-not-renew",
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(90 * 24 * time.Hour),
			ShouldRenew: false,
		},
		{
			Desc:        "90d-cert needs-renew",
			NotBefore:   time.Now().Add(-61 * 24 * time.Hour),
			NotAfter:    time.Now().Add(29 * 24 * time.Hour),
			ShouldRenew: true,
		},

		// Current shortlived (6 day) certs
		{
			Desc:        "6d-cert do-not-renew",
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(6 * 24 * time.Hour),
			ShouldRenew: false,
		},
		{
			Desc:        "6d-cert needs-renew",
			NotBefore:   time.Now().Add(-5 * 24 * time.Hour),
			NotAfter:    time.Now().Add(1 * 24 * time.Hour),
			ShouldRenew: true,
		},

		// Future 64 day certs
		{
			Desc:        "64d-cert do-not-renew",
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(64 * 24 * time.Hour),
			ShouldRenew: false,
		},
		{
			Desc:        "64d-cert needs-renew",
			NotBefore:   time.Now().Add(-41 * 24 * time.Hour),
			NotAfter:    time.Now().Add(20 * 24 * time.Hour),
			ShouldRenew: true,
		},

		// Future 45 day certs
		{
			Desc:        "45d-cert do-not-renew",
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(45 * 24 * time.Hour),
			ShouldRenew: false,
		},
		{
			Desc:        "45d-cert needs-renew",
			NotBefore:   time.Now().Add(-31 * 24 * time.Hour),
			NotAfter:    time.Now().Add(14 * 24 * time.Hour),
			ShouldRenew: true,
		},
	}

	for _, tc := range tests {

		func() {
			b := createTestBackend(t)

			as := b.startACMEServer(t)
			defer as.Close()

			const (
				account  = "test-account"
				provider = "test-dns"
				fqdn     = "test.example.com"
			)

			path := MakeDNS01Path(account, provider, fqdn)

			b.RegisterDNSProvider(provider, func() (challenge.Provider, error) {
				return as, nil
			})

			accountPath := "accounts/" + account
			req := &logical.Request{
				Path:      accountPath,
				Operation: logical.UpdateOperation,
				Data: map[string]interface{}{
					"email":         "test@example.com",
					"directory_url": as.DirectoryURL,
					"tos_agreed":    true,
				},
			}

			resp, err := b.HandleRequest(t, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NoError(t, resp.Error())

			leaf, key := generateSelfSignedCert(t, fqdn, nil, tc.NotBefore, tc.NotAfter)

			originalCert := &cert{
				CertificateChain: []*x509.Certificate{leaf},
				Key:              key,
			}
			err = originalCert.write(t.Context(), b.Storage, path)
			require.NoError(t, err)

			req = &logical.Request{
				Path:      path,
				Operation: logical.ReadOperation,
			}

			resp, err = b.HandleRequest(t, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NoError(t, resp.Error())

			certs, err := certcrypto.ParsePEMBundle([]byte(resp.Data["certificate"].(string)))
			require.NoError(t, err)
			require.NotEmpty(t, certs)

			privKey, err := certcrypto.ParsePEMPrivateKey([]byte(resp.Data["private_key"].(string)))
			require.NoError(t, err)
			require.NotNil(t, privKey)

			assert.Contains(t, certcrypto.ExtractDomains(certs[0]), fqdn)
			if tc.ShouldRenew {
				assertCertMatchesKey(t, certs[0], privKey)
				assert.Truef(t, certs[0].NotAfter.After(tc.NotAfter), "%s", tc.Desc)
			} else {
				assert.Equalf(t, tc.NotAfter.Year(), certs[0].NotAfter.Year(), tc.Desc)
				assert.Equalf(t, tc.NotAfter.YearDay(), certs[0].NotAfter.YearDay(), tc.Desc)
			}
		}()
	}
}
