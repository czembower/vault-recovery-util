package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	recoveryKeyPath    = "core/recovery-key"
	recoveryConfigPath = "core/recovery-config"
	rootKeyPath        = "core/hsm/barrier-unseal-keys"
	keyringPath        = "core/keyring"
	shamirConfigPath   = "core/seal-config"
	shamirKekPath      = "core/shamir-kek"
	AESGCMVersion1     = 0x1
	AESGCMVersion2     = 0x2
)

type shamirOrRecoveryConfig struct {
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
	Type                 string `json:"type,omitempty"`
	Address              string `json:"address,omitempty"`
	KeyName              string `json:"key_name,omitempty"`
	MountPath            string `json:"mount_path,omitempty"`
	TlsSkipVerify        bool   `json:"ssl_skip_verify,omitempty"`
	Token                string `json:"token,omitempty"`
	Namespace            string `json:"namespace,omitempty"`
	TlsCaCert            string `json:"tls_ca_cert,omitempty"`
	Project              string `json:"project,omitempty"`
	Region               string `json:"region,omitempty"`
	KeyRing              string `json:"key_ring,omitempty"`
	CryptoKey            string `json:"crypto_key,omitempty"`
	TenantID             string `json:"tenant_id,omitempty"`
	ClientID             string `json:"client_id,omitempty"`
	ClientSecret         string `json:"client_secret,omitempty"`
	Resource             string `json:"resource,omitempty"`
	VaultName            string `json:"vault_name,omitempty"`
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

type encryptionData struct {
	RootKey        []byte                 `json:"root_key,omitempty"`
	RecoveryKey    []byte                 `json:"recovery_key,omitempty"`
	UnsealKey      []byte                 `json:"unseal_key,omitempty"`
	Keyring        []byte                 `json:"keyring,omitempty"`
	BoltDB         string                 `json:"bolt_db,omitempty"`
	SealConfig     sealConfig             `json:"seal_config,omitempty"`
	ShamirConfig   shamirOrRecoveryConfig `json:"shamir_config,omitempty"`
	RecoveryConfig shamirOrRecoveryConfig `json:"recovery_config,omitempty"`
	KeyringData    keyringData            `json:"keyring_data,omitempty"`
}

type keyringData struct {
	MasterKey string `json:"MasterKey"`
	Keys      []struct {
		Term        int       `json:"Term,omitempty"`
		Version     int       `json:"Version,omitempty"`
		Value       string    `json:"Value,omitempty"`
		InstallTime time.Time `json:"InstallTime,omitempty"`
		Encryptions int       `json:"encryptions,omitempty"`
	} `json:"Keys"`
	RotationConfig struct {
		Disabled      bool  `json:"Disabled,omitempty"`
		MaxOperations int64 `json:"MaxOperations,omitempty"`
		Interval      int   `json:"Interval,omitempty"`
	} `json:"RotationConfig"`
}

func main() {
	vaultConfigFilePath := flag.String("vaultConfig", "./vault.hcl", "Path to the Vault server configuration file")
	genRecoveryKeyShares := flag.Bool("genRecoveryKeyShares", false, "Set to true to generate new recovery key shares")
	printSealConfig := flag.Bool("printSealConfig", false, "Display the seal configuration")
	printKeyring := flag.Bool("printKeyring", false, "Display the keyring data, including the data encryption keys and root key in base64 format")
	printRecoveryKey := flag.Bool("printRecoveryKey", false, "Display the recovery key in base64 format")
	printUnsealKey := flag.Bool("printUnsealKey", false, "Display the unseal key in base64 format")
	readPath := flag.String("readPath", "", "BoltDB path to key that should be decrypted and returning in plain text")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
	}

	// Initialize and load the Vault configuration file
	var encData encryptionData
	err := encData.loadConfig(*vaultConfigFilePath)
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	// Retrieve and decrypt the root key, keyring, recovery key/config
	err = encData.getKeys()
	if err != nil {
		log.Fatalf("failed to access values from BoltDB: %v", err)
	}

	// Print the seal configuration
	if *printSealConfig {
		fmt.Println("seal configuration:")
		sealConfig, err := json.MarshalIndent(encData.SealConfig, "", "  ")
		if err != nil {
			log.Fatalf("unable to marshal seal configuration: %v", err)
		}
		fmt.Printf("%v\n", string(sealConfig))
	}

	// Print the keyring
	if *printKeyring {
		fmt.Println("keyring:")
		keyringJson, err := json.MarshalIndent(encData.KeyringData, "", "  ")
		if err != nil {
			log.Fatalf("failed to marshal keyring data: %v", err)
		}
		fmt.Printf("%s\n", keyringJson)
	}

	if *printRecoveryKey {
		if encData.RecoveryKey != nil {
			fmt.Printf("recovery key base64: %s\n", base64.StdEncoding.EncodeToString(encData.RecoveryKey))
		} else {
			log.Fatal("no recovery key available")
		}
	}

	if *printUnsealKey {
		if encData.UnsealKey != nil {
			fmt.Printf("unseal key base64: %s\n", base64.StdEncoding.EncodeToString(encData.UnsealKey))
		} else {
			log.Fatal("no unseal key available")
		}
	}

	// Calculate new Shamir key shares of the recovery key
	if *genRecoveryKeyShares {
		encData.shamirSplit()
	}

	// Read an arbitrary path from BoltDB and decrypt using the keyring
	if *readPath != "" {
		err = getVaultData(encData, encData.KeyringData, *readPath)
		if err != nil {
			log.Fatalf("error retrieving data from specified path: %v", err)
		}
	}

	os.Remove("./vault.db")
}
