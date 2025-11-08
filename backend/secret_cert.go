package backend

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const SecretCertType = "cert"

func secretCert(b *backend) *framework.Secret {
	return &framework.Secret{
		Type:            SecretCertType,
		DefaultDuration: 90 * 24 * time.Hour,
		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type:        framework.TypeString,
				Description: "Certificate chain in PEM format",
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "Private key in PEM format",
			},
		},

		Renew:  b.secretCertRenew,
		Revoke: b.secretCertRevoke,
	}
}

func (b *backend) secretCertRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path, ok := req.Secret.InternalData["path"]
	if !ok {
		return nil, errors.New("secret is missing path internal data")
	}

	req = &logical.Request{
		Path:      path.(string),
		Operation: logical.ReadOperation,
		Storage:   req.Storage,
	}

	return b.HandleRequest(ctx, req)
}

func (b *backend) secretCertRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
