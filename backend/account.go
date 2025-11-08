package backend

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	KeyTypeEC256   = "EC256"
	KeyTypeEC384   = "EC384"
	KeyTypeRSA2048 = "RSA2048"
	KeyTypeRSA4096 = "RSA4096"
	KeyTypeRSA8192 = "RSA8192"
)

func AllowedKeyTypes() []interface{} {
	return []interface{}{
		KeyTypeEC256,
		KeyTypeEC384,
		KeyTypeRSA2048,
		KeyTypeRSA4096,
		KeyTypeRSA8192,
	}
}

type accountKey struct {
	PrivateKey crypto.PrivateKey
}

type account struct {
	Email          string
	Registration   *registration.Resource
	Key            accountKey
	DirectoryURL   string
	DNSProviderEnv map[string]string
}

// LEGO registration.User interface
func (a *account) GetEmail() string {
	return a.Email
}
func (a *account) GetRegistration() *registration.Resource {
	return a.Registration
}
func (a *account) GetPrivateKey() crypto.PrivateKey {
	return a.Key.PrivateKey
}

func (a *account) NewClient(tlsConfig *tls.Config) (*lego.Client, error) {
	config := lego.NewConfig(a)
	config.CADirURL = a.DirectoryURL
	config.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return lego.NewClient(config)
}

func getAccount(ctx context.Context, storage logical.Storage, path string) (*account, error) {
	entry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	a := new(account)
	if err := entry.DecodeJSON(&a); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *account) write(ctx context.Context, storage logical.Storage, path string) error {

	entry, err := logical.StorageEntryJSON(path, a)
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}

func (ac accountKey) MarshalJSON() ([]byte, error) {
	if ac.PrivateKey == nil {
		return json.Marshal(nil)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(ac.PrivateKey)
	if err != nil {
		return nil, err
	}

	return json.Marshal(pkcs8Bytes)
}

func (ac *accountKey) UnmarshalJSON(data []byte) error {
	var pkcs8Bytes []byte
	if err := json.Unmarshal(data, &pkcs8Bytes); err != nil {
		return err
	}

	if len(pkcs8Bytes) == 0 {
		ac.PrivateKey = nil
		return nil
	}

	key, err := x509.ParsePKCS8PrivateKey(pkcs8Bytes)
	if err != nil {
		return err
	}

	ac.PrivateKey = key
	return nil
}

func (ak *accountKey) Generate(keyType string) error {
	var cryptoType certcrypto.KeyType
	switch keyType {
	case KeyTypeEC256:
		cryptoType = certcrypto.EC256
		break
	case KeyTypeEC384:
		cryptoType = certcrypto.EC384
		break
	case KeyTypeRSA2048:
		cryptoType = certcrypto.RSA2048
		break
	case KeyTypeRSA4096:
		cryptoType = certcrypto.RSA4096
		break
	case KeyTypeRSA8192:
		cryptoType = certcrypto.RSA8192
		break
	default:
		return fmt.Errorf("unsupported key type %q", keyType)
	}

	key, err := certcrypto.GeneratePrivateKey(cryptoType)
	if err != nil {
		return err
	}

	ak.PrivateKey = key
	return nil
}

func (ak *accountKey) KeyType() string {
	if ak.PrivateKey == nil {
		return ""
	}

	switch typedKey := ak.PrivateKey.(type) {
	case *rsa.PrivateKey:
		switch typedKey.N.BitLen() {
		case 2048:
			return KeyTypeRSA2048
		case 4096:
			return KeyTypeRSA4096
		case 8192:
			return KeyTypeRSA8192
		}
	case *ecdsa.PrivateKey:
		switch typedKey.Curve {
		case elliptic.P256():
			return KeyTypeEC256
		case elliptic.P384():
			return KeyTypeEC384
		}
	}

	return ""
}
