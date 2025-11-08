package backend

import (
	"context"

	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	accountsHelpSynopsis    = "Manage ACME accounts for certificate issuance"
	accountsHelpDescription = "This enpoint allows you to create " +
		"read, and delete ACME accounts. Account keys are automatically " +
		"generated and stored securely."
)

func pathAccounts(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "accounts/" + framework.GenericNameRegex("account"),
			Fields: map[string]*framework.FieldSchema{
				"account": {
					Type:     framework.TypeString,
					Required: true,
				},
				"email": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "ACME account email address",
				},
				"directory_url": {
					Type:        framework.TypeString,
					Default:     "https://acme-v02.api.letsencrypt.org/directory",
					Description: "ACME directory URL",
				},
				"tos_agreed": {
					Type:        framework.TypeBool,
					Default:     false,
					Required:    true,
					Description: "Set to true to signal acceptance of directory_url TOS",
				},
				"key_type": {
					Type:          framework.TypeString,
					Default:       KeyTypeEC256,
					AllowedValues: AllowedKeyTypes(),
					Description:   "Key type to create for account",
				},
				"dns_provider_env": {
					Type:        framework.TypeKVPairs,
					Description: "Environment variables to set when performing dns-01 challenges",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.accountsRead,
					Summary:  "Read ACME account information",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.accountsWrite,
					Summary:  "Create or register an ACME account",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.accountsDelete,
					Summary:  "Delete an ACME account",
				},
			},
			HelpSynopsis:    accountsHelpSynopsis,
			HelpDescription: accountsHelpDescription,
		},
	}
}

func (b *backend) accountsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	a, err := getAccount(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("Account does not exist"), nil
	}

	resp := map[string]interface{}{
		"email":         a.Email,
		"directory_url": a.DirectoryURL,
		"key_exists":    a.Key.PrivateKey != nil,
		"key_type":      a.Key.KeyType(),
	}

	if a.Registration != nil {
		resp["registration"] = a.Registration.URI
	}

	if a.DNSProviderEnv == nil {
		resp["dns_provider_env"] = map[string]string{}
	} else {
		resp["dns_provider_env"] = a.DNSProviderEnv
	}

	return &logical.Response{
		Data: resp,
	}, nil
}

func (b *backend) accountsWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}

	email := data.Get("email").(string)
	directoryURL := data.Get("directory_url").(string)
	tosAgreed := data.Get("tos_agreed").(bool)
	keyType := data.Get("key_type").(string)

	act, err := getAccount(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}

	updateAccount := false
	if act == nil {
		act = &account{
			DirectoryURL: directoryURL,
		}

		b.Logger().Info("Generating key pair for new account")
		if err := act.Key.Generate(keyType); err != nil {
			return nil, errwrap.Wrapf("Failed to generate account key: {{err}}", err)
		}

	} else {
		updateAccount = true
		if directoryURL != act.DirectoryURL {
			return logical.ErrorResponse("Cannot change directory_url"), nil
		}
		if keyType != act.Key.KeyType() {
			return logical.ErrorResponse("Cannot change key_type"), nil
		}
	}

	act.Email = email

	// patch DNS provider enviornment variables
	if dnsEnvRaw, ok := data.GetOk("dns_provider_env"); ok {
		dnsEnv := dnsEnvRaw.(map[string]string)

		if act.DNSProviderEnv == nil {
			act.DNSProviderEnv = make(map[string]string)
		}

		for k, v := range dnsEnv {
			act.DNSProviderEnv[k] = v
		}
	}

	client, err := act.NewClient(b.tlsConfig)
	if err != nil {
		return nil, err
	}

	options := registration.RegisterOptions{
		TermsOfServiceAgreed: tosAgreed,
	}

	var reg *registration.Resource
	if updateAccount {
		b.Logger().Info("Updating ACME account")
		reg, err = client.Registration.UpdateRegistration(options)
	} else {
		b.Logger().Info("Registering new ACME account")
		reg, err = client.Registration.Register(options)
	}

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	act.Registration = reg
	if err := act.write(ctx, req.Storage, req.Path); err != nil {
		return nil, err
	}

	return b.accountsRead(ctx, req, data)
}

func (b *backend) accountsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	a, err := getAccount(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("Account does not exist"), err
	}

	if a.Registration != nil {
		client, err := a.NewClient(b.tlsConfig)
		if err != nil {
			return nil, errwrap.Wrapf("Failed to instance ACME client: {{err}}", err)
		}

		err = client.Registration.DeleteRegistration()
		if err != nil {
			return nil, errwrap.Wrapf("Failed to deactivate ACME registration: {{err}}", err)
		}
	}

	err = req.Storage.Delete(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	b.Logger().Info("ACME account deleted", "email", a.Email)
	return nil, nil
}
