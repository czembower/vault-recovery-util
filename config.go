package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/internalshared/configutil"
)

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
	var sealConfig sealConfig
	if seal == nil {
		fmt.Println("no seals found in Vault configuration file, proceeding with Shamir seal type assumed")
		sealConfig.Type = "shamir"
	} else {
		sealConfig.Type = seal.Type
	}

	if sealConfig.Type == "transit" {
		// A Vault token for the Vault cluster providing the Transit engine is
		// needed for Transit auto-unseal, and for this tool
		// We can source that token from an the environment variable VAULT_TOKEN or
		// read it from the Vault configuration file
		// If neither is provided, return error
		if os.Getenv("VAULT_TOKEN") != "" {
			sealConfig.Token = os.Getenv("VAULT_TOKEN")
		} else {
			if seal.Config["token"] != "" {
				sealConfig.Token = seal.Config["token"]
			} else {
				return fmt.Errorf("no Vault token for transit engine in environment variables or provided Vault config")
			}
		}
		if val, ok := seal.Config["address"]; ok {
			sealConfig.Address = val
		}
		if val, ok := seal.Config["key_name"]; ok {
			sealConfig.KeyName = val
		}
		if val, ok := seal.Config["mount_path"]; ok {
			sealConfig.MountPath = val
		}
		if val, ok := seal.Config["tls_skip_verify"]; ok {
			sealTlsSkipVerify, _ := strconv.ParseBool(val)
			sealConfig.TlsSkipVerify = sealTlsSkipVerify
		}
		if val, ok := seal.Config["namespace"]; ok {
			sealConfig.Namespace = val
		}
		if val, ok := seal.Config["tls_ca_cert"]; ok {
			sealConfig.TlsCaCert = val
		}
		if val, ok := seal.Config["tls_skip_verify"]; ok {
			bool, err := strconv.ParseBool(val)
			if err != nil {
				return fmt.Errorf("failed to parse bool in configuration file")
			}
			sealConfig.TlsSkipVerify = bool
		}
	} else if sealConfig.Type == "gcpckms" {
		if val, ok := seal.Config["project"]; ok {
			sealConfig.Project = val
		}
		if val, ok := seal.Config["region"]; ok {
			sealConfig.Region = val
		}
		if val, ok := seal.Config["key_ring"]; ok {
			sealConfig.KeyRing = val
		}
		if val, ok := seal.Config["crypto_key"]; ok {
			sealConfig.CryptoKey = val
		}
	} else if sealConfig.Type == "azurekeyvault" {
		if val, ok := seal.Config["tenant_id"]; ok {
			sealConfig.TenantID = val
		}
		if val, ok := seal.Config["client_id"]; ok {
			sealConfig.ClientID = val
		}
		if val, ok := seal.Config["client_secret"]; ok {
			sealConfig.ClientSecret = val
		}
		if val, ok := seal.Config["resource"]; ok {
			sealConfig.Resource = val
		}
		if val, ok := seal.Config["vault_name"]; ok {
			sealConfig.VaultName = val
		}
		if val, ok := seal.Config["key_name"]; ok {
			sealConfig.KeyName = val
		}
	} else if sealConfig.Type == "awskms" {
		if val, ok := seal.Config["region"]; ok {
			sealConfig.Region = val
		}
		if val, ok := seal.Config["endpoint"]; ok {
			sealConfig.Endpoint = val
		}
		if val, ok := seal.Config["access_key"]; ok {
			sealConfig.AccessKey = val
		}
		if val, ok := seal.Config["secret_key"]; ok {
			sealConfig.SecretKey = val
		}
		if val, ok := seal.Config["session_token"]; ok {
			sealConfig.SessionToken = val
		}
		if val, ok := seal.Config["shared_creds_filename"]; ok {
			sealConfig.SharedCredsFile = val
		}
		if val, ok := seal.Config["shared_creds_profile"]; ok {
			sealConfig.SharedCredsProfile = val
		}
		if val, ok := seal.Config["web_identity_token_file"]; ok {
			sealConfig.WebIdentityTokenFile = val
		}
		if val, ok := seal.Config["role_session_name"]; ok {
			sealConfig.RoleArn = val
		}
		if val, ok := seal.Config["role_arn"]; ok {
			sealConfig.RoleArn = val
		}
	}
	e.SealConfig = sealConfig

	// A storage config is needed to determine the BoltDB location
	if config.Storage == nil {
		return fmt.Errorf("no storage stanza found in Vault configuration file")
	}
	storageConfig := config.Storage.Config

	if val, ok := storageConfig["path"]; ok {
		e.BoltDB = val + "/vault.db"
	} else {
		return fmt.Errorf("no path parameter storage stanza found in Vault configuration file")
	}

	fmt.Println("successfully loaded Vault server configuration")
	fmt.Println("seal type:", e.SealConfig.Type)
	return nil
}
