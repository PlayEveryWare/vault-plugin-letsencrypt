package backend

import (
	"errors"
	"testing"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathAccounts_Read_FromStorage(t *testing.T) {
	b := createTestBackend(t)

	const path = "accounts/test-account"
	act := &account{
		Email:        "test@example.com",
		DirectoryURL: "https://acme.example.com/directory",
		Registration: &registration.Resource{
			URI: "https://registration.example.com/reg/123",
			Body: acme.Account{
				TermsOfServiceAgreed: true,
			},
		},
	}
	err := act.Key.Generate(KeyTypeEC256)
	require.NoError(t, err)

	err = act.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req := &logical.Request{
		Path:      path,
		Operation: logical.ReadOperation,
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, act.Email, resp.Data["email"])
	assert.Equal(t, true, resp.Data["key_exists"])
	assert.Equal(t, act.Key.KeyType(), resp.Data["key_type"])
	assert.NotNil(t, resp.Data["registration"])
	assert.Equal(t, act.Registration.URI, resp.Data["registration"])
	assert.Equal(t, act.DirectoryURL, resp.Data["directory_url"])
}

func TestPathAccounts_Read_NonExistent(t *testing.T) {
	b := createTestBackend(t)

	req := &logical.Request{
		Path:      "accounts/nonexistent",
		Operation: logical.ReadOperation,
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Error(t, resp.Error())
	assert.Contains(t, resp.Error().Error(), "Account does not exist")
}

func TestPathAccountsRead_StorageError(t *testing.T) {
	b := createTestBackend(t)
	b.Storage.GetError = errors.New("storage error")

	req := &logical.Request{
		Path: "accounts/test",
	}

	resp, err := b.HandleRequest(t, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestPathAccounts_Write_CreateNew(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	path := "accounts/test-account"
	email := "test@example.com"
	keyType := KeyTypeEC256

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         email,
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
			"key_type":      keyType,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, email, resp.Data["email"])
	assert.Equal(t, true, resp.Data["key_exists"])
	assert.Equal(t, keyType, resp.Data["key_type"])
	assert.NotEmpty(t, resp.Data["registration"])
	assert.Equal(t, as.DirectoryURL, resp.Data["directory_url"])
}

func TestPathAccounts_Write_CreateNewRequiresTOS(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const path = "accounts/test-account"

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    false,
			"key_type":      KeyTypeEC256,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Error(t, resp.Error())
	assert.ErrorContains(t, resp.Error(), "terms of service")
}

func TestPathAccounts_Write_UpdateExisting(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	path := "accounts/test-account"
	email := "test@example.com"
	keyType := KeyTypeEC256

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         email,
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
			"key_type":      keyType,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, email, resp.Data["email"])
	assert.Equal(t, true, resp.Data["key_exists"])
	assert.Equal(t, keyType, resp.Data["key_type"])
	assert.NotEmpty(t, resp.Data["registration"])
	assert.Equal(t, as.DirectoryURL, resp.Data["directory_url"])

	email = "test2@example.com"
	req.Data["email"] = email

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, email, resp.Data["email"])
	assert.Equal(t, true, resp.Data["key_exists"])
	assert.Equal(t, keyType, resp.Data["key_type"])
	assert.NotEmpty(t, resp.Data["registration"])
	assert.Equal(t, as.DirectoryURL, resp.Data["directory_url"])

	act, err := getAccount(t.Context(), b.Storage, path)
	require.NoError(t, err)
	require.NotNil(t, act)
	assert.Equal(t, act.Email, email)
	assert.NotNil(t, act.Registration)
	assert.Contains(t, act.Registration.Body.Contact, "mailto:"+email)

}

func TestPathAccounts_Write_ValidationErrors(t *testing.T) {
	b := createTestBackend(t)

	path := "accounts/test-account"
	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
	}

	req.Data = map[string]interface{}{
		"email":         "test@example.com",
		"directory_url": "https://acme.example.com/directory",
		"key_type":      "INVALID_TYPE",
		"tos_agreed":    true,
	}

	_, err := b.HandleRequest(t, req)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unsupported key type")
}

func TestPathAccounts_Write_CannotChangeDiscoveryURL(t *testing.T) {
	b := createTestBackend(t)

	const path = "accounts/test-account"
	act := &account{
		Email:        "test@example.com",
		DirectoryURL: "https://acme.example.com/directory",
		Registration: &registration.Resource{
			URI: "https://registration.example.com/reg/123",
			Body: acme.Account{
				TermsOfServiceAgreed: true,
			},
		},
	}
	err := act.Key.Generate(KeyTypeEC256)
	require.NoError(t, err)

	err = act.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         act.Email,
			"directory_url": "https://localhost/directory",
			"key_type":      act.Key.KeyType(),
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.ErrorContains(t, resp.Error(), "Cannot change directory_url")
}

func TestPathAccounts_Write_CannotChangeKeyType(t *testing.T) {
	b := createTestBackend(t)

	const path = "accounts/test-account"
	act := &account{
		Email:        "test@example.com",
		DirectoryURL: "https://acme.example.com/directory",
		Registration: &registration.Resource{
			URI: "https://registration.example.com/reg/123",
			Body: acme.Account{
				TermsOfServiceAgreed: true,
			},
		},
	}
	err := act.Key.Generate(KeyTypeEC256)
	require.NoError(t, err)

	err = act.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         act.Email,
			"directory_url": act.DirectoryURL,
			"key_type":      KeyTypeRSA2048,
			"tos_agreed":    true,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "Cannot change key_type")
}

func TestPath_Accounts_Write_StorageError(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const path = "accounts/test-account"

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
			"key_type":      KeyTypeEC256,
		},
	}

	b.Storage.PutError = errors.New("storage put error")
	resp, err := b.HandleRequest(t, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestPathAccounts_Write_WithDNSEnv(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	path := "accounts/test-account"
	email := "test@example.com"
	dnsEnv := map[string]string{
		"DO_AUTH_TOKEN":  "digital-ocean-token",
		"LINODE_API_KEY": "linode-api-key",
	}

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":            email,
			"directory_url":    as.DirectoryURL,
			"tos_agreed":       true,
			"dns_provider_env": dnsEnv,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, dnsEnv, resp.Data["dns_provider_env"])

	act, err := getAccount(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.NotNil(t, act)
	assert.Equal(t, dnsEnv, act.DNSProviderEnv)
}

func TestPathAccounts_Write_WithDNSEnv_Replace(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	path := "accounts/test-account"
	email := "test@example.com"
	dnsEnv := map[string]string{
		"DO_AUTH_TOKEN":  "digital-ocean-token",
		"LINODE_API_KEY": "linode-api-key",
	}

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":            email,
			"directory_url":    as.DirectoryURL,
			"tos_agreed":       true,
			"dns_provider_env": dnsEnv,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	dnsEnv["DO_AUTH_TOKEN"] = "new_token"
	req.Data["dns_provider_env"] = map[string]string{
		"DO_AUTH_TOKEN": dnsEnv["DO_AUTH_TOKEN"],
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, dnsEnv, resp.Data["dns_provider_env"])

	act, err := getAccount(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.NotNil(t, act)
	assert.Equal(t, dnsEnv, act.DNSProviderEnv)
}

func TestPathAccounts_Write_WithDNSEnv_Merge(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	path := "accounts/test-account"
	email := "test@example.com"
	dnsEnv := map[string]string{
		"DO_AUTH_TOKEN": "digital-ocean-token",
	}

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":            email,
			"directory_url":    as.DirectoryURL,
			"tos_agreed":       true,
			"dns_provider_env": dnsEnv,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, dnsEnv, resp.Data["dns_provider_env"])

	dnsEnv["LINODE_API_KEY"] = "linode-api-key"
	req.Data["dns_provider_env"] = map[string]string{
		"LINODE_API_KEY": dnsEnv["LINODE_API_KEY"],
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.NotNil(t, resp.Data)

	assert.Equal(t, dnsEnv, resp.Data["dns_provider_env"])

	act, err := getAccount(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.NotNil(t, act)
	assert.Equal(t, dnsEnv, act.DNSProviderEnv)
}

func TestPathAccounts_Delete_WithoutRegistration(t *testing.T) {
	b := createTestBackend(t)

	const path = "accounts/test-account"
	act := &account{
		Email:        "test@example.com",
		DirectoryURL: "https://acme.example.com/directory",
	}
	err := act.Key.Generate(KeyTypeEC256)
	require.NoError(t, err)

	err = act.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req := &logical.Request{
		Path:      path,
		Operation: logical.DeleteOperation,
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	assert.Nil(t, resp)
	require.NoError(t, resp.Error())

	act, err = getAccount(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.Nil(t, act)
}

func TestPathAccounts_Delete_WithRegistration(t *testing.T) {
	b := createTestBackend(t)

	as := b.startACMEServer(t)
	defer as.Close()

	const path = "accounts/test-account"

	req := &logical.Request{
		Path:      path,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"email":         "test@example.com",
			"directory_url": as.DirectoryURL,
			"tos_agreed":    true,
			"key_type":      KeyTypeEC256,
		},
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())

	req = &logical.Request{
		Path:      path,
		Operation: logical.DeleteOperation,
	}

	resp, err = b.HandleRequest(t, req)
	require.NoError(t, err)
	assert.Nil(t, resp)

	act, err := getAccount(t.Context(), b.Storage, path)
	require.NoError(t, err)
	assert.Nil(t, act)
}

func TestPathAccounts_Delete_NonExistent(t *testing.T) {
	b := createTestBackend(t)

	req := &logical.Request{
		Path:      "accounts/nonexistent",
		Operation: logical.DeleteOperation,
	}

	resp, err := b.HandleRequest(t, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "Account does not exist")
}

func TestPathAccounts_Delete_StorageError(t *testing.T) {
	b := createTestBackend(t)
	b.Storage.DeleteError = errors.New("storage delete error")

	path := "accounts/test-account"

	act := &account{
		Email:        "test@example.com",
		DirectoryURL: "https://acme.example.com/directory",
	}

	err := act.Key.Generate(KeyTypeEC256)
	require.NoError(t, err)

	err = act.write(t.Context(), b.Storage, path)
	require.NoError(t, err)

	req := &logical.Request{
		Path:      path,
		Operation: logical.DeleteOperation,
	}

	resp, err := b.HandleRequest(t, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
}
