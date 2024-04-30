package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
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

func main() {
	vaultConfigFilePath := flag.String("vaultConfig", "./vault.hcl", "Path to the Vault server configuration file")
	genRecoveryKeyShares := flag.Bool("genRecoveryKeyShares", false, "Set to true to generate new recovery key shares")
	printSealConfig := flag.Bool("printSealConfig", false, "Display the seal configuration")
	printKeyring := flag.Bool("printKeyring", false, "Display the keyring data, including the data encryption keys and root key in base64 format")
	printRecoveryKey := flag.Bool("printRecoveryKey", false, "Display the recovery key in base64 format")
	printUnsealKey := flag.Bool("printUnsealKey", false, "Display the unseal key in base64 format")
	listDbKeys := flag.Bool("listDbKeys", false, "Display the BoltDB database contents")
	readPath := flag.String("readPath", "", "BoltDB path to key that should be decrypted and returning in plain text")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
	}

	// Initialize and load the Vault configuration file
	var e encryptionData
	err := e.loadConfig(*vaultConfigFilePath)
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	// Retrieve and decrypt the root key, keyring, recovery key/config
	err = e.getKeys()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Print the seal configuration
	if *printSealConfig {
		fmt.Println("seal configuration:")
		sealConfig, err := json.MarshalIndent(e.SealConfig, "", "  ")
		if err != nil {
			log.Fatalf("unable to marshal seal configuration: %v", err)
		}
		fmt.Printf("%v\n", string(sealConfig))
	}

	// Print the keyring
	if *printKeyring {
		fmt.Println("keyring:")
		keyringJson, err := json.MarshalIndent(e.KeyringData, "", "  ")
		if err != nil {
			log.Fatalf("failed to marshal keyring data: %v", err)
		}
		fmt.Printf("%s\n", keyringJson)
	}

	// Print the recovery key, if present
	if *printRecoveryKey {
		if e.RecoveryKey != nil {
			fmt.Printf("recovery key base64: %s\n", base64.StdEncoding.EncodeToString(e.RecoveryKey))
		} else {
			log.Fatal("no recovery key available")
		}
	}

	// Print the unseal key, if present
	if *printUnsealKey {
		if e.UnsealKey != nil {
			fmt.Printf("unseal key base64: %s\n", base64.StdEncoding.EncodeToString(e.UnsealKey))
		} else {
			log.Fatal("no unseal key available")
		}
	}

	// Calculate new Shamir key shares of the recovery key
	if *genRecoveryKeyShares {
		err := e.shamirSplit()
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	// List BoltDB keys
	if *listDbKeys {
		err := boltList(&e)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	// Read an arbitrary path from BoltDB and decrypt using the keyring
	if *readPath != "" {
		err = getVaultData(e.BoltDB, e.KeyringData, *readPath)
		if err != nil {
			log.Fatalf("error retrieving data from specified path: %v", err)
		}
	}

	os.Remove("./vault.db")
}
