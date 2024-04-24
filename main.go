package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"
)

const (
	recoveryKeyPath    = "core/recovery-key"
	recoveryConfigPath = "core/recovery-config"
	rootKeyPath        = "core/hsm/barrier-unseal-keys"
	keyringPath        = "core/keyring"
	AESGCMVersion1     = 0x1
	AESGCMVersion2     = 0x2
)

type recoveryConfig struct {
	Type            string `json:"type"`
	SecretShares    int    `json:"secret_shares"`
	SecretThreshold int    `json:"secret_threshold"`
	PgpKeys         any    `json:"pgp_keys"`
	Nonce           string `json:"nonce"`
	Backup          bool   `json:"backup"`
	StoredShares    int    `json:"stored_shares"`
	Name            string `json:"name"`
}

type sealConfig struct {
	Type          string `json:"type"`
	Address       string `json:"address"`
	KeyName       string `json:"key_name"`
	MountPath     string `json:"mount_path"`
	TlsSkipVerify bool   `json:"ssl_skip_verify"`
	Token         string `json:"token"`
	Project       string `json:"project"`
	Region        string `json:"region"`
	KeyRing       string `json:"key_ring"`
	CryptoKey     string `json:"crypto_key"`
}

type encryptionData struct {
	RootKey        []byte         `json:"root_key"`
	RecoveryKey    []byte         `json:"recovery_key"`
	Keyring        []byte         `json:"keyring"`
	BoltDB         string         `json:"bolt_db"`
	SealConfig     sealConfig     `json:"seal_config"`
	RecoveryConfig recoveryConfig `json:"recovery_config"`
	KeyringData    keyringData    `json:"keyring_data"`
}

type keyringData struct {
	MasterKey string `json:"MasterKey"`
	Keys      []struct {
		Term        int       `json:"Term"`
		Version     int       `json:"Version"`
		Value       string    `json:"Value"`
		InstallTime time.Time `json:"InstallTime"`
		Encryptions int       `json:"encryptions,omitempty"`
	} `json:"Keys"`
	RotationConfig struct {
		Disabled      bool  `json:"Disabled"`
		MaxOperations int64 `json:"MaxOperations"`
		Interval      int   `json:"Interval"`
	} `json:"RotationConfig"`
}

func main() {
	genRecoveryKeyShares := flag.Bool("genRecoveryKeyShares", false, "Set to true to generate new recovery key shares")
	printKeyring := flag.Bool("printKeyring", false, "Display the keyring data, including the data encryption keys and root key")
	vaultConfigFilePath := flag.String("vaultConfig", "./vault.hcl", "Path to the Vault server configuration file")
	readPath := flag.String("readPath", "", "BoltDB path to key that should be decrypted and returning in plain text")
	flag.Parse()

	// Initialize and load the Vault configuration file
	var encData encryptionData
	err := encData.loadConfig(*vaultConfigFilePath)
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	// Retrieve, decrypt, and set the root key, keyring, recovery key/config
	err = encData.getKeys()
	if err != nil {
		log.Fatalf("failed to access values from BoltDB: %v", err)
	}

	// Print the keyring
	if *printKeyring {
		keyringJson, err := json.MarshalIndent(encData.KeyringData, "", "  ")
		if err != nil {
			log.Fatalf("failed to marshal keyring data: %v", err)
		}
		fmt.Printf("%s\n", keyringJson)
	}

	// Calculate new Shamir key shares of the recovery key
	if *genRecoveryKeyShares {
		encData.shamirSplit()
	}

	// Read an arbitrary path from Vault and decrypt using the Keyring
	if *readPath != "" {
		err = getVaultData(encData, encData.KeyringData, *readPath)
		if err != nil {
			log.Fatalf("error retrieving data from specified path: %v", err)
		}
	}
}
