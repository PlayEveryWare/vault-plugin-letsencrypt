package backend

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type cert struct {
	CertificateChain []*x509.Certificate
	Key              accountKey
}

func getCert(ctx context.Context, storage logical.Storage, path string) (*cert, error) {
	entry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	cert := new(cert)
	if err := entry.DecodeJSON(&cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *cert) NotBefore() time.Time {
	if len(c.CertificateChain) > 0 {
		return c.CertificateChain[0].NotBefore
	}

	return time.Time{}
}

func (c *cert) NotAfter() time.Time {
	if len(c.CertificateChain) > 0 {
		return c.CertificateChain[0].NotAfter
	}

	return time.Time{}
}

func (c *cert) RenewalDeadline() time.Time {
	var (
		validDuration     = c.NotAfter().Sub(c.NotBefore())
		twoThirdsDuration = validDuration * 2 / 3
		deadline          = c.NotBefore().Add(twoThirdsDuration)
	)
	return deadline
}

func (c *cert) write(ctx context.Context, storage logical.Storage, path string) error {
	entry, err := logical.StorageEntryJSON(path, c)
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}

type certJSON struct {
	CertificateChain [][]byte
	Key              accountKey
}

func (c *cert) MarshalJSON() ([]byte, error) {
	cj := &certJSON{
		CertificateChain: make([][]byte, len(c.CertificateChain)),
		Key:              c.Key,
	}

	for ii := range c.CertificateChain {
		cj.CertificateChain[ii] = c.CertificateChain[ii].Raw
	}

	return json.Marshal(cj)
}

func (c *cert) UnmarshalJSON(data []byte) error {
	cj := new(certJSON)
	if err := json.Unmarshal(data, cj); err != nil {
		return err
	}

	c.CertificateChain = make([]*x509.Certificate, len(cj.CertificateChain))
	c.Key = cj.Key

	for ii := range cj.CertificateChain {
		cert, err := x509.ParseCertificate(cj.CertificateChain[ii])
		if err != nil {
			return err
		}

		c.CertificateChain[ii] = cert
	}

	return nil
}
