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
	fmt.Println("Vault configuration file path: ", vaultConfigFile)

	config, err := server.ParseConfig(string(file), vaultConfigFile)
	if err != nil {
		return fmt.Errorf("failed to parse Vault server configuration file: %v", err)
	}
	fmt.Println("successfully loaded Vault server configuration")

	// Identity seal type and set config
	// Vault supports multuple seal configurations, but this tool does not so we
	// will break after the first seal is found
	var seal *configutil.KMS
	for _, k := range config.Seals {
		seal = k
		break
	}

	// Check for seal configuration and load the seal parameters to
	// EncryptionData.SealConfig
	if seal == nil {
		return fmt.Errorf("no seals found in Vault configuration file")
	}
	var sealConfig sealConfig
	sealConfig.Type = seal.Type
	sealConfig.Address = seal.Config["address"]
	sealConfig.KeyName = seal.Config["key_name"]
	sealConfig.MountPath = seal.Config["mount_path"]
	sealTlsSkipVerify, _ := strconv.ParseBool(seal.Config["tls_skip_verify"])
	sealConfig.TlsSkipVerify = sealTlsSkipVerify

	if seal.Type == "transit" {
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

		if config.Storage == nil {
			return fmt.Errorf("no storage stanza found in Vault configuration file")
		}
		storageConfig := config.Storage.Config

		if val, ok := storageConfig["path"]; ok {
			e.BoltDB = val + "/vault.db"
			fmt.Println("found storage path:", val)
		} else {
			return fmt.Errorf("no path parameter storage stanza found in Vault configuration file")
		}
	}
	e.SealConfig = sealConfig

	fmt.Println("seal type:", e.SealConfig.Type)
	fmt.Println("boltdb path:", e.BoltDB)
	return nil
}
