package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/internalshared/configutil"
)

type sealConfig struct {
	Type                string                  `json:"type,omitempty"`
	TransitConfig       transitSealConfig       `json:"transit_config,omitempty"`
	GcpCkmsConfig       gcpCkmsSealConfig       `json:"gcp_ckms_config,omitempty"`
	AzureKeyVaultConfig azurekeyvaultSealConfig `json:"azure_key_vault_config,omitempty"`
	AwsKmsConfig        awsKmsSealConfig        `json:"aws_kms_config,omitempty"`
}

type transitSealConfig struct {
	Address       string `json:"address,omitempty"`
	KeyName       string `json:"key_name,omitempty"`
	MountPath     string `json:"mount_path,omitempty"`
	TlsSkipVerify bool   `json:"ssl_skip_verify,omitempty"`
	Token         string `json:"token,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	TlsCaCert     string `json:"tls_ca_cert,omitempty"`
}

type gcpCkmsSealConfig struct {
	UserAgent   string `json:"user_agent,omitempty"`
	Credentials string `json:"credentials,omitempty"`
	Project     string `json:"project,omitempty"`
	Region      string `json:"region,omitempty"`
	KeyRing     string `json:"key_ring,omitempty"`
	CryptoKey   string `json:"crypto_key,omitempty"`
}

type azurekeyvaultSealConfig struct {
	TenantID     string `json:"tenant_id,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Resource     string `json:"resource,omitempty"`
	VaultName    string `json:"vault_name,omitempty"`
	KeyName      string `json:"key_name,omitempty"`
}

type awsKmsSealConfig struct {
	Region               string `json:"region,omitempty"`
	Endpoint             string `json:"endpoint,omitempty"`
	AccessKey            string `json:"access_access,omitempty"`
	SecretKey            string `json:"secret_key,omitempty"`
	SessionToken         string `json:"session_token,omitempty"`
	SharedCredsFile      string `json:"shared_creds_file,omitempty"`
	SharedCredsProfile   string `json:"shared_creds_profile,omitempty"`
	WebIdentityTokenFile string `json:"web_identity_token_file,omitempty"`
	RoleSessionName      string `json:"role_session_name,omitempty"`
	RoleArn              string `json:"role_arn,omitempty"`
}

func (e *encryptionData) loadConfig(vaultConfigFile string) error {
	file, err := os.ReadFile(vaultConfigFile)
	if err != nil {
		return fmt.Errorf("failed to locate Vault configuration file: %v", err)
	}

	config, err := server.ParseConfig(string(file), vaultConfigFile)
	if err != nil {
		return fmt.Errorf("failed to parse Vault server configuration file: %v", err)
	}

	// Identity seal type and set config
	// Vault supports multuple seal configurations, but this tool does not so we
	// will break after the first seal is found
	var seal *configutil.KMS
	for _, k := range config.Seals {
		seal = k
		break
	}

	// Check for seal configuration and load the seal parameters to
	// encryptionData.SealConfig
	if seal == nil {
		fmt.Println("no seals found in Vault configuration file, proceeding with Shamir seal type assumed")
		e.SealConfig.Type = "shamir"
	} else {
		e.SealConfig.Type = seal.Type
	}

	if e.SealConfig.Type == "transit" {
		// A Vault token for the Vault cluster providing the Transit engine is
		// needed for Transit auto-unseal, and for this tool
		// We can source that token from an the environment variable VAULT_TOKEN or
		// read it from the Vault configuration file
		// If neither is provided, return error
		if os.Getenv("VAULT_TOKEN") != "" {
			e.SealConfig.TransitConfig.Token = os.Getenv("VAULT_TOKEN")
		} else {
			if seal.Config["token"] != "" {
				e.SealConfig.TransitConfig.Token = seal.Config["token"]
			} else {
				return fmt.Errorf("no Vault token for transit engine in environment variables or provided Vault config")
			}
		}
		if val, ok := seal.Config["address"]; ok {
			e.SealConfig.TransitConfig.Address = val
		}
		if val, ok := seal.Config["key_name"]; ok {
			e.SealConfig.TransitConfig.KeyName = val
		}
		if val, ok := seal.Config["mount_path"]; ok {
			e.SealConfig.TransitConfig.MountPath = val
		}
		if val, ok := seal.Config["tls_skip_verify"]; ok {
			sealTlsSkipVerify, _ := strconv.ParseBool(val)
			e.SealConfig.TransitConfig.TlsSkipVerify = sealTlsSkipVerify
		}
		if val, ok := seal.Config["namespace"]; ok {
			e.SealConfig.TransitConfig.Namespace = val
		}
		if val, ok := seal.Config["tls_ca_cert"]; ok {
			e.SealConfig.TransitConfig.TlsCaCert = val
		}
	} else if e.SealConfig.Type == "gcpckms" {
		if val, ok := seal.Config["user_agent"]; ok {
			e.SealConfig.GcpCkmsConfig.UserAgent = val
		}
		if val, ok := seal.Config["credentials"]; ok {
			e.SealConfig.GcpCkmsConfig.Credentials = val
		}
		if val, ok := seal.Config["project"]; ok {
			e.SealConfig.GcpCkmsConfig.Project = val
		}
		if val, ok := seal.Config["region"]; ok {
			e.SealConfig.GcpCkmsConfig.Region = val
		}
		if val, ok := seal.Config["key_ring"]; ok {
			e.SealConfig.GcpCkmsConfig.KeyRing = val
		}
		if val, ok := seal.Config["crypto_key"]; ok {
			e.SealConfig.GcpCkmsConfig.CryptoKey = val
		}
	} else if e.SealConfig.Type == "azurekeyvault" {
		if val, ok := seal.Config["tenant_id"]; ok {
			e.SealConfig.AzureKeyVaultConfig.TenantID = val
		}
		if val, ok := seal.Config["client_id"]; ok {
			e.SealConfig.AzureKeyVaultConfig.ClientID = val
		}
		if val, ok := seal.Config["client_secret"]; ok {
			e.SealConfig.AzureKeyVaultConfig.ClientSecret = val
		}
		if val, ok := seal.Config["resource"]; ok {
			e.SealConfig.AzureKeyVaultConfig.Resource = val
		}
		if val, ok := seal.Config["vault_name"]; ok {
			e.SealConfig.AzureKeyVaultConfig.VaultName = val
		}
		if val, ok := seal.Config["key_name"]; ok {
			e.SealConfig.AzureKeyVaultConfig.KeyName = val
		}
	} else if e.SealConfig.Type == "awskms" {
		if val, ok := seal.Config["region"]; ok {
			e.SealConfig.AwsKmsConfig.Region = val
		}
		if val, ok := seal.Config["endpoint"]; ok {
			e.SealConfig.AwsKmsConfig.Endpoint = val
		}
		if val, ok := seal.Config["access_key"]; ok {
			e.SealConfig.AwsKmsConfig.AccessKey = val
		}
		if val, ok := seal.Config["secret_key"]; ok {
			e.SealConfig.AwsKmsConfig.SecretKey = val
		}
		if val, ok := seal.Config["session_token"]; ok {
			e.SealConfig.AwsKmsConfig.SessionToken = val
		}
		if val, ok := seal.Config["shared_creds_filename"]; ok {
			e.SealConfig.AwsKmsConfig.SharedCredsFile = val
		}
		if val, ok := seal.Config["shared_creds_profile"]; ok {
			e.SealConfig.AwsKmsConfig.SharedCredsProfile = val
		}
		if val, ok := seal.Config["web_identity_token_file"]; ok {
			e.SealConfig.AwsKmsConfig.WebIdentityTokenFile = val
		}
		if val, ok := seal.Config["role_session_name"]; ok {
			e.SealConfig.AwsKmsConfig.RoleSessionName = val
		}
		if val, ok := seal.Config["role_arn"]; ok {
			e.SealConfig.AwsKmsConfig.RoleArn = val
		}
	}

	// A storage config is needed to determine the BoltDB location
	if config.Storage == nil {
		return fmt.Errorf("no storage stanza found in Vault configuration file")
	}

	if val, ok := config.Storage.Config["path"]; ok {
		e.BoltDbFile = val + "/vault.db"
	} else {
		return fmt.Errorf("no path parameter storage stanza found in Vault configuration file")
	}
	fmt.Println("seal type:", e.SealConfig.Type)

	return nil
}
