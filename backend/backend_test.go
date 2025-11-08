package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	//"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testBackend struct {
	*backend
	Storage *mockStorage
}

type mockStorage struct {
	ls          logical.Storage
	GetError    error
	PutError    error
	DeleteError error
}

// createTestBackend creates a backend instance for testing
func createTestBackend(t *testing.T) *testBackend {
	ms := &mockStorage{
		ls: &logical.InmemStorage{},
	}
	config := &logical.BackendConfig{
		StorageView: ms,
	}

	b, err := Factory(t.Context(), config)
	require.NoError(t, err)
	require.NotNil(t, b)

	return &testBackend{
		backend: b.(*backend),
		Storage: ms,
	}
}

func (tb *testBackend) HandleRequest(t *testing.T, req *logical.Request) (*logical.Response, error) {
	t.Helper()

	req.Storage = tb.Storage

	resp, err := tb.backend.HandleRequest(t.Context(), req)
	return resp, err
}

func (ms *mockStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if ms.GetError != nil {
		return nil, ms.GetError
	}

	return ms.ls.Get(ctx, key)
}

func (ms *mockStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if ms.PutError != nil {
		return ms.PutError
	}

	return ms.ls.Put(ctx, entry)
}

func (ms *mockStorage) Delete(ctx context.Context, key string) error {
	if ms.DeleteError != nil {
		return ms.DeleteError
	}

	return ms.ls.Delete(ctx, key)
}

func (ms *mockStorage) List(ctx context.Context, key string) ([]string, error) {
	return ms.ls.List(ctx, key)
}
