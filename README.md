# Vault Plugin: Let's Encrypt

A HashiCorp Vault secrets plugin that provides automated SSL/TLS certificate management using Let's Encrypt and the ACME protocol. This plugin enables you to issue, renew, and manage certificates directly from Vault using DNS-01 challenges.

## Features

- **ACME Account Management**: Create and manage ACME accounts with automatic key generation
- **Certificate Issuance**: Automatically issue SSL/TLS certificates for domains using DNS-01 challenges
- **Automatic Renewal**: Certificates are automatically renewed when they approach expiration (30 days before expiry)
- **DNS Provider Support**: Supports all DNS providers available in the [LEGO](https://github.com/go-acme/lego) library
- **Custom DNS Providers**: Register custom DNS challenge providers
- **Secure Storage**: Account keys and certificates are stored securely in Vault's storage backend
- **Multiple Accounts**: Support for multiple ACME accounts with different configurations
- **Environment Variable Support**: Configure DNS provider credentials via environment variables per account

## Requirements

- HashiCorp Vault 1.0 or later
- Go 1.25.0 or later (for building from source)
- Access to a DNS provider that supports API-based DNS record management (for DNS-01 challenges)

## Installation

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/playeveryware/vault-plugin-letsencrypt.git
cd vault-plugin-letsencrypt
```

2. Build the plugin:
```bash
go build -o vault-plugin-letsencrypt ./cmd/vault-plugin-letsencrypt
```

3. Register the plugin with Vault (see [Vault Plugin Registration](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-registration))

### Plugin Registration

1. Place the compiled plugin binary in a location accessible by Vault
2. Calculate the SHA256 checksum:
```bash
sha256sum vault-plugin-letsencrypt
```

3. Register the plugin in Vault:
```bash
vault plugin register \
  -sha256=<checksum> \
  secret vault-plugin-letsencrypt
```

4. Enable the plugin:
```bash
vault secrets enable -path=letsencrypt vault-plugin-letsencrypt
```

## Configuration

### Backend Configuration

The plugin can be configured with the following options (if supported by your Vault version):

- Custom DNS resolvers
- TLS configuration
- Custom DNS provider registration

## Usage

### Creating an ACME Account

Create a new ACME account for certificate issuance:

```bash
vault write letsencrypt/accounts/myaccount \
  email="admin@example.com" \
  tos_agreed=true \
  directory_url="https://acme-v02.api.letsencrypt.org/directory" \
  key_type="EC256" \
  dns_provider_env=CLOUDFLARE_API_TOKEN=your-cloudflare-dns-token \
  dns_provider_env=LINODE_TOKEN=your-linode-dns-token \
  dns_provider_env=DO_AUTH_TOKEN=your-digitalocean-dns-token \
  ;
```

You can find the dns environment variable by inspecting the LEGO source code.

Start at https://github.com/go-acme/lego/blob/master/providers/dns, then locate
your DNS provider.

For example, DigitalOcean > https://github.com/go-acme/lego/blob/master/providers/dns/digitalocean

https://github.com/go-acme/lego/blob/465d7918a80d1887d84f6eeb8aaee2e71622114c/providers/dns/digitalocean/digitalocean.go#L22-L25
```go
// Environment variables names.
const (
	envNamespace = "DO_"

	EnvAuthToken = envNamespace + "AUTH_TOKEN"
	EnvAPIUrl    = envNamespace + "API_URL"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)
```

The `dns_provider_env` in this case is `DO_AUTH_TOKEN`

**Parameters:**
- `email` (required): Email address for the ACME account
- `tos_agreed` (required): Set to `true` to accept the Terms of Service
- `directory_url` (optional): ACME directory URL (defaults to Let's Encrypt production)
- `key_type` (optional): Key type for the account key (`EC256`, `EC384`, `RSA2048`, `RSA4096`, `RSA8192`)
- `dns_provider_env` (optional): Key-value pairs of environment variables to set for DNS provider authentication

### Reading Account Information

```bash
vault read letsencrypt/accounts/myaccount
```

### Issuing a Certificate

Issue or retrieve a certificate for a domain:

```bash
vault read letsencrypt/certs/dns-01/myaccount/cloudflare/example.com
```

**Path Format:** `certs/dns-01/{account}/{provider}/{fqdn}`

- `account`: The ACME account name to use
- `provider`: The DNS provider name (e.g., `cloudflare`, `route53`, `gcloud`, etc.)
- `fqdn`: The fully qualified domain name for the certificate

**Response:**
The response includes:
- `certificate`: PEM-encoded certificate chain
- `private_key`: PEM-encoded private key

The secret has a TTL set to expire 30 days before the certificate expires, ensuring automatic renewal.

### Supported DNS Providers

The plugin supports all DNS providers available in the LEGO library, including:

- Cloudflare
- AWS Route53
- Google Cloud DNS
- Azure DNS
- DigitalOcean
- And many more...

See the [LEGO DNS Providers documentation](https://go-acme.github.io/lego/dns/) for a complete list and required environment variables.

### Deleting an Account

```bash
vault delete letsencrypt/accounts/myaccount
```

This will deactivate the ACME account registration and remove it from Vault.

## API Endpoints

### Accounts

- `GET /accounts/{account}` - Read account information
- `POST /accounts/{account}` - Create or update an account
- `DELETE /accounts/{account}` - Delete an account

### Certificates

- `GET /certs/dns-01/{account}/{provider}/{fqdn}` - Issue or retrieve a certificate

## Development

### Running Tests

```bash
go test ./...
```

### Project Structure

```
.
├── backend/          # Plugin backend implementation
│   ├── account.go    # ACME account management
│   ├── cert.go       # Certificate handling
│   ├── path_*.go     # API endpoint handlers
│   └── ...
├── cmd/
│   └── vault-plugin-letsencrypt/
│       └── main.go   # Plugin entry point
└── go.mod           # Go module definition
```

## Security Considerations

- Account private keys are stored securely in Vault's storage backend
- Certificate private keys are returned as Vault secrets with appropriate TTLs
- DNS provider credentials are configured via the `dns_provider_env` parameter when creating accounts; the plugin handles setting these environment variables internally during certificate issuance
- Use Vault's access control policies to restrict access to accounts and certificates
- Consider using separate accounts for different environments (production, staging, etc.)

## Troubleshooting

### Certificate Not Issuing

1. Verify the ACME account exists and is properly registered
2. Check that DNS provider credentials are correctly configured
3. Ensure the DNS provider has API access enabled
4. Verify DNS propagation is working for the domain
5. Check Vault logs for detailed error messages

### DNS Challenge Failures

- Ensure the DNS provider API credentials have permissions to create TXT records
- Verify the domain is properly configured with the DNS provider
- Check that DNS propagation delays are accounted for (some providers may take time)

## License

This project is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.
