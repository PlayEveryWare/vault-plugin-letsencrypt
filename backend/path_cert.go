package backend

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	certsHelpSynopsis    = "Issue and manage ACME certificates"
	certsHelpDescription = "This endpoint allows you to issue, " +
		"read, and revoke ACME certificates using DNS-01 challenges"
)

func MakeDNS01Path(account, provider, fqdn string) string {
	return fmt.Sprintf("certs/dns-01/%s/%s/%s", account, provider, fqdn)
}

func pathCerts(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "certs/dns-01/" +
				framework.GenericNameRegex("account") + "/" +
				framework.GenericNameRegex("provider") + "/" +
				`(?P<fqdn>[^/]+)`,
			Fields: map[string]*framework.FieldSchema{
				"account": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Vault ACME account to use",
				},
				"provider": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "LEGO dns-01 provider to use",
				},
				"fqdn": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "FQDN to manage",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.certsRead,
					Summary: "Acquire a certificate+key for the FQDN, issuing " +
						"or renewing as required",
				},
			},
			HelpSynopsis:    certsHelpSynopsis,
			HelpDescription: certsHelpDescription,
		},
	}
}

func (b *backend) certsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	account := data.Get("account").(string)
	provider := data.Get("provider").(string)
	fqdn := data.Get("fqdn").(string)

	// check existing certificate
	c, err := getCert(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, errwrap.Wrapf("failed to load certificate: {{err}}", err)
	}

	if c != nil && len(c.CertificateChain) > 0 && c.Key.PrivateKey != nil {

		timeUntilRenwal := time.Until(c.RenewalDeadline())
		if timeUntilRenwal > 0 {
			return b.certResponse(ctx, c, req, account, provider)
		}
	}

	actPath := fmt.Sprintf("accounts/%s", account)
	act, err := getAccount(ctx, req.Storage, actPath)
	if err != nil {
		return nil, errwrap.Wrapf("failed to get account: {{err}}", err)
	}
	if act == nil {
		return logical.ErrorResponse("Account does not exist"), nil
	}

	client, err := act.NewClient(b.tlsConfig)
	if err != nil {
		return nil, err
	}

	// Temporarily override DNS provider environment variables
	cleanup := WithEnvOverrides(act.DNSProviderEnv)
	defer cleanup()

	dnsProvider, err := b.NewDNSChallengeProviderByName(provider)
	if err != nil {
		return nil, errwrap.Wrapf("failed to create DNS provider: {{err}}", err)
	}

	b.Logger().Debug("Using dns challenge provider", "provider", provider)

	var opts []dns01.ChallengeOption

	if len(b.dnsResolvers) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(dns01.ParseNameservers(b.dnsResolvers)))
		b.Logger().Debug("Setting DNS nameservers to", "dns-resolvers", b.dnsResolvers)
	}

	if b.skipAuthoritativeNSCheck || provider == "nil" {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
		b.Logger().Debug("Skipping authoritative NS checks")
	}

	if provider == "nil" {
		opts = append(opts, dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			return true, nil
		}))

		b.Logger().Debug("Skipping DNS progagation in challenge")
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider, opts...); err != nil {
		return nil, err
	}

	certReq := certificate.ObtainRequest{
		Domains: []string{fqdn},
		Bundle:  true,
	}

	certRes, err := client.Certificate.Obtain(certReq)
	if err != nil {
		return nil, err
	}

	certChain, err := certcrypto.ParsePEMBundle(certRes.Certificate)
	if err != nil {
		return nil, errwrap.Wrapf("failed to parse certificate chain: {{err}}", err)
	}

	keyBlock, _ := pem.Decode(certRes.PrivateKey)
	if keyBlock == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	var privateKey crypto.PrivateKey
	if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		privateKey = key
	} else if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		privateKey = key
	} else if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		privateKey = key
	} else {
		return nil, errwrap.Wrapf("failed to parse private key: {{err}}", err)
	}

	c = &cert{
		CertificateChain: certChain,
		Key:              accountKey{privateKey},
	}

	err = c.write(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, errwrap.Wrapf("failed to save certificate: {{err}}", err)
	}

	return b.certResponse(ctx, c, req, account, provider)
}

func (b *backend) certResponse(ctx context.Context, c *cert, req *logical.Request, account, provider string) (*logical.Response, error) {
	var certPEM []byte
	for _, cert := range c.CertificateChain {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		certPEM = append(certPEM, pem.EncodeToMemory(block)...)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(c.Key.PrivateKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	keyPem := pem.EncodeToMemory(block)

	ttl := time.Until(c.RenewalDeadline())
	if ttl < 1*time.Hour {
		ttl = 1 * time.Hour
	}

	response := b.Secret(SecretCertType).Response(map[string]interface{}{
		"certificate": string(certPEM),
		"private_key": string(keyPem),
	}, map[string]interface{}{
		"path": req.Path,
	})

	response.Secret.TTL = ttl
	response.Secret.MaxTTL = ttl

	return response, nil
}
