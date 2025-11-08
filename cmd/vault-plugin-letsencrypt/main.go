package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	"github.com/playeveryware/vault-plugin-letsencrypt/backend"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}

	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logAndExit(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProvider := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    tlsProvider,
	}); err != nil {
		logAndExit(err)
	}
}

func logAndExit(err error) {
	hclog.New(&hclog.LoggerOptions{}).Error(
		"plugin shutting down",
		"erorr",
		err,
	)

	os.Exit(1)
}
