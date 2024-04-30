package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
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

func boltList(e *encryptionData) error {
	db, err := boltOpen(e.BoltDB)
	if err != nil {
		return fmt.Errorf("error opening database file %s: %v", e.BoltDB, err)
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
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

func copyFile(source string, dest string) error {
	input, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	err = os.WriteFile(dest, input, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (e *encryptionData) getKeys() error {
	db, err := boltOpen(e.BoltDB)
	if err != nil {
		return fmt.Errorf("error opening database file %s: %v", e.BoltDB, err)
	}
	defer db.Close()

	// Read the root key and keyring ciphers from BoltDB
	rootKeyCipher, err := boltRead(db, rootKeyPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	keyringCipher, err := boltRead(db, keyringPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	// If using auto-unseal, get the recovery key cipher and config
	if e.SealConfig.Type != "shamir" {
		recoveryKeyCipher, err := boltRead(db, recoveryKeyPath)
		if err != nil {
			return fmt.Errorf("error reading key from boltdb: %v", err)
		}

		recoveryConfigData, err := boltRead(db, recoveryConfigPath)
		if err != nil {
			return fmt.Errorf("error reading key from boltdb: %v", err)
		}

		// decrypt the recovery key using the seal device
		e.RecoveryKey, err = e.decryptSeal(recoveryKeyCipher)
		if err != nil {
			return fmt.Errorf("%v", err)
		}

		// load the recovery config into recoveryConfig
		var recoveryConfig shamirOrRecoveryConfig
		json.Unmarshal(recoveryConfigData, &recoveryConfig)
		e.RecoveryConfig = recoveryConfig
		fmt.Println("recovery type:", e.RecoveryConfig.Type)
		// If shamir get the seal config
	} else {
		shamirConfigData, err := boltRead(db, shamirConfigPath)
		if err != nil {
			return fmt.Errorf("error reading key from boltdb: %v", err)
		}

		// load the shamir config into shamirConfig
		var shamirConfig shamirOrRecoveryConfig
		json.Unmarshal(shamirConfigData, &shamirConfig)
		e.ShamirConfig = shamirConfig
	}

	// Attempt to decrypt the root key and keyring
	rootKeyReadBytes, err := e.decryptSeal(rootKeyCipher)
	if err != nil {
		return fmt.Errorf("error decrypting root key: %v", err)
	}

	if e.SealConfig.Type != "shamir" {
		e.Keyring, err = e.decryptSeal(keyringCipher)
		if err != nil {
			return fmt.Errorf("error decrypting keyring: %v", err)
		}
	} else {
		// The keyring ciphertext must be tweaked for Shamir seals
		lenCipher := len(keyringCipher)
		e.Keyring = keyringCipher[3 : lenCipher-1]
	}

	// The seal-decrypted root key is an array of base64-encoded strings,
	// but there is only one item in the array, so we extract it
	var strArr []string
	_ = json.Unmarshal([]byte(rootKeyReadBytes), &strArr)
	e.RootKey = []byte(strArr[0])

	// Push the root key through a byte -> string -> base64 decode
	rootKeyBytes, err := base64.StdEncoding.DecodeString(string(e.RootKey))
	if err != nil {
		return fmt.Errorf("failed to encode root key base64: %v", err)
	}

	// Decrypt the keyring using the root key and load into keyringData
	var decryptedKeyring []byte
	decryptedKeyring, err = decrypt(e.Keyring, rootKeyBytes, keyringPath)
	if err != nil {
		return fmt.Errorf("failed to decode keyring: %v", err)
	}

	var keyringData keyringData
	json.Unmarshal(decryptedKeyring, &keyringData)
	e.KeyringData = keyringData

	return nil
}

func getVaultData(encData encryptionData, keyringData keyringData, readPath string) error {
	// Initialize the DB reader
	db, err := bolt.Open(encData.BoltDB, 0700, &bolt.Options{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("error accessing boltdb: %v", err)
	}
	defer db.Close()

	// Read from BoltDB and get ciphertext
	ciphertext, err := boltRead(db, readPath)
	if err != nil {
		return fmt.Errorf("error accessing readPath from boltdb: %v", err)
	}

	fmt.Println("data path:", readPath)
	var dek string

	// Set the keyring term based on the ciphertext, and set the appropriate keyring DEK
	if len(ciphertext) == 0 {
		return fmt.Errorf("invalid data path: %v", err)
	}
	term := binary.BigEndian.Uint32(ciphertext[:4])
	for _, keyInfo := range keyringData.Keys {
		if uint32(keyInfo.Term) == term {
			dek = keyInfo.Value
			fmt.Println("data encryption key:", dek)
			fmt.Println("key term:", term)
		}
	}

	keyringKey, err := base64.StdEncoding.DecodeString(dek)
	if err != nil {
		return fmt.Errorf("error base64-decoding keyring key ciphertext: %v", err)
	}

	// Decrypt the ciphertext using the keyring DEK
	secret, err := decrypt(ciphertext, keyringKey, readPath)
	if err != nil {
		fmt.Printf("data at \"%s\" failed to decrypt -- raw storage content will be displayed:\n", readPath)
		fmt.Printf("%s\n", ciphertext)
		return nil
	}

	if secret != nil {
		buf := &bytes.Buffer{}
		if err := json.Indent(buf, secret, "", "  "); err == nil {
			fmt.Printf("decrypted content:\n%s\n", buf)
		} else {
			fmt.Println("decrypted content:\n", string(secret))
		}
	}
	return nil
}
