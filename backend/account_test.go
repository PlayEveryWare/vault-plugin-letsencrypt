package backend

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertAccountKeyEqual(t *testing.T, expected *accountKey, actual *accountKey) {
	expectedBytes, err := x509.MarshalPKCS8PrivateKey(expected.PrivateKey)
	require.NoError(t, err)

	actualBytes, err := x509.MarshalPKCS8PrivateKey(actual.PrivateKey)
	require.NoError(t, err)

	assert.Equal(t, expectedBytes, actualBytes)
	assert.Equal(t, expected.KeyType(), actual.KeyType())
}

func TestAccountKey_Generation(t *testing.T) {
	allowedTypes := AllowedKeyTypes()

	for _, keyTypeGeneric := range allowedTypes {
		keyType := keyTypeGeneric.(string)
		ac := new(accountKey)
		err := ac.Generate(keyType)
		require.NoError(t, err)
		assert.Equal(t, keyType, ac.KeyType())
	}
}

func TestAccountKey_Serialization(t *testing.T) {
	allowedTypes := AllowedKeyTypes()

	for _, keyTypeGeneric := range allowedTypes {
		keyType := keyTypeGeneric.(string)

		originalKey := new(accountKey)
		originalKey.Generate(keyType)

		serialized, err := json.Marshal(originalKey)
		require.NoError(t, err)

		newKey := new(accountKey)
		err = json.Unmarshal(serialized, newKey)
		require.NoError(t, err)

		assertAccountKeyEqual(t, originalKey, newKey)
	}
}

func TestAccountKey_NilSerialization(t *testing.T) {
	originalKey := new(accountKey)
	serialized, err := json.Marshal(originalKey)
	require.NoError(t, err)

	newKey := new(accountKey)
	err = json.Unmarshal(serialized, newKey)
	require.NoError(t, err)

	assert.Nil(t, newKey.PrivateKey)
	assert.Equal(t, "", newKey.KeyType())
}

func TestAccountKey_InvalidType(t *testing.T) {
	ac := new(accountKey)
	err := ac.Generate("invalid-key-type")
	assert.Error(t, err)
}

func TestAccount_LEGOInterface(t *testing.T) {
	a := &account{
		Email: "test@example.com",
		Registration: &registration.Resource{
			URI: "https://acme.example.com/reg/123",
		},
	}
	a.Key.Generate(KeyTypeEC256)

	assert.Equal(t, a.Email, a.GetEmail())
	assert.Equal(t, a.Registration, a.GetRegistration())
	assert.Equal(t, a.Key.PrivateKey, a.GetPrivateKey())
	assert.Equal(t, a.Registration, a.GetRegistration())
	assert.Equal(t, a.Registration.URI, a.GetRegistration().URI)
}

func TestAccount_NewClient(t *testing.T) {
	a := &account{
		Email:        "test@example.com",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
	}

	// nil key
	assert.Nil(t, a.GetPrivateKey())
	client, err := a.NewClient(nil)
	assert.Nil(t, client)
	assert.Error(t, err)

	for _, keyTypeGeneric := range AllowedKeyTypes() {
		err := a.Key.Generate(keyTypeGeneric.(string))
		require.NoError(t, err)

		client, err := a.NewClient(nil)
		require.NoError(t, err)
		assert.NotNil(t, client)
	}
}

func TestGetAccount_NonExistent(t *testing.T) {
	storage := &logical.InmemStorage{}

	account, err := getAccount(t.Context(), storage, "nonexistent/path")
	require.NoError(t, err)
	assert.Nil(t, account)
}

func TestAccount_Storage(t *testing.T) {
	storage := &logical.InmemStorage{}

	// Create and write an account
	act := &account{
		Email:        "test@example.com",
		DirectoryURL: "https://acme.example.com/directory",
		Registration: &registration.Resource{
			URI: "https://acme.example.com/reg/123",
		},
	}

	for _, keyTypeGeneric := range AllowedKeyTypes() {
		err := act.Key.Generate(keyTypeGeneric.(string))
		require.NoError(t, err)

		path := fmt.Sprintf("test/%s", keyTypeGeneric)
		err = act.write(t.Context(), storage, path)
		require.NoError(t, err)

		retrievedAccount, err := getAccount(t.Context(), storage, path)
		require.NoError(t, err)
		require.NotNil(t, retrievedAccount)
		require.NotNil(t, retrievedAccount.Registration)
		assert.Equal(t, act.Email, retrievedAccount.Email)
		assert.Equal(t, act.DirectoryURL, retrievedAccount.DirectoryURL)
		assert.Equal(t, act.Registration.URI, retrievedAccount.Registration.URI)
		assertAccountKeyEqual(t, &act.Key, &retrievedAccount.Key)
	}
}
