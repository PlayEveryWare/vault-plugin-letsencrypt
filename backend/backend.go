package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	backendHelp = `LetsEncrypt Backend`
)

var (
	projectVersion string
)

type backend struct {
	*framework.Backend
	tlsConfig                *tls.Config
	dnsResolvers             []string
	skipAuthoritativeNSCheck bool
	CustomDNSProviders       map[string]func() (challenge.Provider, error)
	CustomDNSProvidersLock   sync.RWMutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := new(backend)

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathAccounts(b),
			pathCerts(b),
		),
		Secrets: []*framework.Secret{
			secretCert(b),
		},
		//Invalidate:     b.Invalidate,
		RunningVersion: projectVersion,
	}

	if conf == nil {
		return nil, errors.New("backend configuration is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	b.RegisterDNSProvider("nil", newNilDNSProvider)

	b.Logger().Info("plugin backend succesfully initialized")
	return b, nil
}

func (b *backend) RegisterDNSProvider(name string, factory func() (challenge.Provider, error)) {
	b.CustomDNSProvidersLock.Lock()
	if b.CustomDNSProviders == nil {
		b.CustomDNSProviders = make(map[string]func() (challenge.Provider, error))
	}
	b.CustomDNSProviders[name] = factory
	b.CustomDNSProvidersLock.Unlock()
}

func (b *backend) NewDNSChallengeProviderByName(name string) (challenge.Provider, error) {
	b.CustomDNSProvidersLock.RLock()
	factory, ok := b.CustomDNSProviders[name]
	b.CustomDNSProvidersLock.RUnlock()
	if ok && factory != nil {
		return factory()
	}

	return dns.NewDNSChallengeProviderByName(name)
}

type nilDNSProvider struct{}

func newNilDNSProvider() (challenge.Provider, error) {
	return &nilDNSProvider{}, nil
}

func (*nilDNSProvider) Present(domain, token, keyAuth string) error {
	return nil
}

func (*nilDNSProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}
