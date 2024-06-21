package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
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

type keyringData struct {
	MasterKey string `json:"MasterKey"`
	Keys      []struct {
		Term        int       `json:"term,omitempty"`
		Version     int       `json:"version,omitempty"`
		Value       string    `json:"value,omitempty"`
		InstallTime time.Time `json:"installTime,omitempty"`
		Encryptions int       `json:"encryptions,omitempty"`
	} `json:"keys"`
	RotationConfig struct {
		Disabled      bool  `json:"disabled,omitempty"`
		MaxOperations int64 `json:"maxOperations,omitempty"`
		Interval      int   `json:"interval,omitempty"`
	} `json:"rotationConfig"`
}

func boltOpen(dbFile string) (*bolt.DB, error) {
	if _, err := os.Stat(dbFile); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("database file not present: %s: %v", dbFile, err)
	}
	db, err := bolt.Open(dbFile, 0o600, &bolt.Options{
		ReadOnly: true,
		Timeout:  2 * time.Second,
	})
	if err != nil {
		fmt.Println("unable to open database file, attempting to copy...")
		err = copyFile(dbFile, "./vault.db")
		if err != nil {
			return nil, fmt.Errorf("error accessing %s: %v", dbFile, err)
		}
		dbFile = "./vault.db"
		db, err = bolt.Open(dbFile, 0700, nil)
		if err != nil {
			return nil, fmt.Errorf("error accessing %s after copy attempt: %v", dbFile, err)
		}
	}
	return db, nil
}

func boltRead(db *bolt.DB, boltKey string) ([]byte, error) {
	var result []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("data"))
		if b == nil {
			return fmt.Errorf("bolt DB bucket \"data\" not found")
		}
		result = b.Get([]byte(boltKey))
		return nil
	})

	return result, err
}

func boltList(db *bolt.DB) error {
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("data"))
		if b == nil {
			return fmt.Errorf("bolt DB bucket \"data\" not found")
		}
		c := b.Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			fmt.Printf("%s\n", k)
		}
		return nil
	})
	return err
}

func (e *encryptionData) getKeys() error {
	// Read the root key and keyring ciphertexts from BoltDB
	rootKeyCiphertext, err := boltRead(e.BoltDB, rootKeyPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	keyringCiphertext, err := boltRead(e.BoltDB, keyringPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	// If using auto-unseal, get the recovery config and recovery key ciphertext
	if e.SealConfig.Type != "shamir" {
		recoveryConfigData, err := boltRead(e.BoltDB, recoveryConfigPath)
		if err != nil {
			return fmt.Errorf("error reading key from boltdb: %v", err)
		}

		recoveryKeyCiphertext, err := boltRead(e.BoltDB, recoveryKeyPath)
		if err != nil {
			return fmt.Errorf("error reading key from boltdb: %v", err)
		}

		// decrypt the recovery key using the seal device
		e.RecoveryKey, err = e.decryptSeal(recoveryKeyCiphertext)
		if err != nil {
			return fmt.Errorf("%v", err)
		}

		// load the recovery config into recoveryConfig
		json.Unmarshal(recoveryConfigData, &e.RecoveryConfig)
		fmt.Println("recovery type:", e.RecoveryConfig.Type)
		// If shamir get the seal config
	} else {
		shamirConfigData, err := boltRead(e.BoltDB, shamirConfigPath)
		if err != nil {
			return fmt.Errorf("error reading key from boltdb: %v", err)
		}

		// load the shamir config into shamirConfig
		json.Unmarshal(shamirConfigData, &e.ShamirConfig)
	}

	// Decrypt the root key
	rootKeyReadBytes, err := e.decryptSeal(rootKeyCiphertext)
	if err != nil {
		return fmt.Errorf("error decrypting root key: %v", err)
	}

	// Load the keyring
	// For auto-unseal with seal wrap, unwrap the keyring ciphertext
	if e.SealConfig.Type != "shamir" && e.SealWrap {
		e.Keyring, err = e.decryptSeal(keyringCiphertext)
		if err != nil {
			return fmt.Errorf("error decrypting keyring: %v", err)
		}
	} else {
		// For Shamir seals (or when seal wrap is disabled), the keyring is not
		// wrapped by the unseal key, so we only need to proto unmarshal the
		// encrypted keyring data and extract the relevant ciphertext portion before
		// we hand to decrypt()
		blobInfo, err := protoUnmarshal(keyringCiphertext)
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		e.Keyring = blobInfo.Ciphertext
	}

	// The unwrapped root key plaintext is an array of base64-encoded strings,
	// but there is only one item in the array, so we extract it
	var strArr []string
	err = json.Unmarshal(rootKeyReadBytes, &strArr)
	if err != nil {
		return fmt.Errorf("failed to unmarshal root key: %v", err)
	}

	// Push the root key through a byte -> string -> base64 decode
	e.RootKey, err = base64.StdEncoding.DecodeString(string([]byte(strArr[0])))
	if err != nil {
		return fmt.Errorf("failed to encode root key base64: %v", err)
	}

	// Decrypt the keyring using the root key and load into keyringData
	var decryptedKeyring []byte
	decryptedKeyring, err = decrypt(e.Keyring, e.RootKey, keyringPath)
	if err != nil {
		return fmt.Errorf("failed to decode keyring: %v", err)
	}
	json.Unmarshal(decryptedKeyring, &e.KeyringData)

	return nil
}

func getVaultData(e *encryptionData, readPath string) error {
	// Read from BoltDB and get ciphertext
	ciphertext, err := boltRead(e.BoltDB, readPath)
	if err != nil || ciphertext == nil {
		return fmt.Errorf("error accessing readPath from boltdb: %v", err)
	}

	secret, err := parseVaultData(ciphertext, readPath, *e)
	if err != nil {
		return fmt.Errorf("error decrypting data from boltdb: %v", err)
	}

	if secret != nil {
		if isASCII(string(secret)) {
			buf := &bytes.Buffer{}
			if err := json.Indent(buf, secret, "", "  "); err == nil {
				fmt.Printf("content:\n%s\n", buf)
			} else {
				fmt.Println("content:", string(secret))
			}
		} else {
			fmt.Println("content:", base64.StdEncoding.EncodeToString(secret))
		}
	}
	return nil
}
