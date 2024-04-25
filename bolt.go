package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

func boltRead(db *bolt.DB, boltKey string) ([]byte, error) {
	var result []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("data"))
		result = b.Get([]byte(boltKey))
		return nil
	})

	return result, err
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
	// Open the BoltDB file
	db, err := bolt.Open(e.BoltDB, 0400, &bolt.Options{
		ReadOnly: true,
		Timeout:  2 * time.Second,
		OpenFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
			f, err := os.OpenFile(name, os.O_RDONLY, perm)
			if err != nil {
				return nil, err
			}
			return f, nil
		},
	})
	if err != nil {
		fmt.Println("unable to open database file, attempting to copy...")
		err = copyFile(e.BoltDB, "./vault.db")
		if err != nil {
			return fmt.Errorf("error accessing %s: %v", e.BoltDB, err)
		}
		e.BoltDB = "./vault.db"
		db, err = bolt.Open(e.BoltDB, 0700, &bolt.Options{
			ReadOnly: true,
			Timeout:  2 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("error accessing %s after copy attempt: %v", e.BoltDB, err)
		}
	}
	defer db.Close()
	fmt.Println("successfully opened boltdb file:", e.BoltDB)

	rootKeyCipher, err := boltRead(db, rootKeyPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	recoveryKeyCipher, err := boltRead(db, recoveryKeyPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	recoveryConfigData, err := boltRead(db, recoveryConfigPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	keyringCiphertext, err := boltRead(db, keyringPath)
	if err != nil {
		return fmt.Errorf("error reading key from boltdb: %v", err)
	}

	// Depending on the seal type, attempt to decrypt
	var ptRootKey []byte
	var ptRecoveryKey []byte
	var ptKeyring []byte

	ptRootKey, err = decryptSeal(rootKeyCipher, e.SealConfig)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	ptRecoveryKey, err = decryptSeal(recoveryKeyCipher, e.SealConfig)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	ptKeyring, err = decryptSeal(keyringCiphertext, e.SealConfig)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// The seal-decrypted root key is an array of base64-encoded strings,
	// but there is only one item in the array, so we extract it
	var strArr []string
	_ = json.Unmarshal([]byte(ptRootKey), &strArr)
	decryptedRootKey := []byte(strArr[0])

	// Load the recovery config
	var recoveryConfigStruct recoveryConfig
	json.Unmarshal(recoveryConfigData, &recoveryConfigStruct)

	// Set EncryptionData with decrypted bytes
	e.RootKey = decryptedRootKey
	e.RecoveryKey = ptRecoveryKey
	e.Keyring = ptKeyring
	e.RecoveryConfig = recoveryConfigStruct

	// Push the root key through a string -> base64 decode
	rootKeyBase64, err := base64.StdEncoding.DecodeString(string(e.RootKey))
	if err != nil {
		return fmt.Errorf("failed to encode root key base64: %v", err)
	}
	fmt.Println("recovery type:", e.RecoveryConfig.Type)

	// Decrypt the keyring and load into keyringData struct
	decryptedKeyring, err := decrypt(e.Keyring, rootKeyBase64, keyringPath)
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
