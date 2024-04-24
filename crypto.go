package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2"
	transit "github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
	"github.com/hashicorp/vault/sdk/helper/compressutil"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/shamir"
	"google.golang.org/protobuf/proto"
)

func decryptSeal(ciphertext []byte, sealConfig sealConfig) ([]byte, error) {
	// Initialize the seal configuration and set parameters learned Vault configuration file
	ctx := context.Background()
	var wrapper *transit.Wrapper

	switch sealConfig.Type {
	case "transit":
		wrapper = transit.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"mount_path": sealConfig.MountPath,
			"key_name":   sealConfig.KeyName,
			"address":    sealConfig.Address,
			"token":      sealConfig.Token,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
	case "gcpckms":
		wrapper := gcpckms.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"project":    sealConfig.Project,
			"region":     sealConfig.Region,
			"key_ring":   sealConfig.KeyRing,
			"crypto_key": sealConfig.CryptoKey,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
	default:
		return nil, fmt.Errorf("seal type not supported")
	}

	// Load the seal ciphertext into a blobInfo object
	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(ciphertext, blobInfo); err != nil {
		eLen := len(ciphertext)
		if err := proto.Unmarshal(ciphertext[:eLen-1], blobInfo); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ciphertext to blob: %s: %v", err, blobInfo)
		}
	}

	// Decrypt blobInfo
	pt, err := wrapper.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
	}

	return pt, nil
}

func decrypt(ciphertext []byte, key []byte, aadPath string) ([]byte, error) {
	// Initialize
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	// Load ciphertext
	ciphertext = bytes.TrimRight(ciphertext, "\n")
	ciphertext = bytes.TrimRight(ciphertext, "\r")
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	// Parse cipher for nonce and primary content
	sz := gcm.NonceSize()
	nonce, raw := ciphertext[5:5+sz], ciphertext[5+sz:]
	out := make([]byte, 0, len(raw)-gcm.NonceSize())

	// Open and decrypt
	var result []byte
	switch ciphertext[4] {
	case AESGCMVersion1:
		result, err = gcm.Open(out, nonce, raw, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt AESGCMVersion1 ciphertext: %v", err)
		}
	case AESGCMVersion2:
		aad := []byte(nil)
		if keyringPath != "" {
			aad = []byte(aadPath)
		}
		result, err = gcm.Open(out, nonce, raw, aad)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt AESGCMVersion2 ciphertext: %v", err)
		}
	default:
		return nil, fmt.Errorf("version bytes mis-match")
	}

	// Check to see if the returned data is compressed or not
	_, uncompressed, _ := compressutil.Decompress(result)
	if aadPath != keyringPath {
		fmt.Printf("compressed: %t\n", !uncompressed)
	}
	if !uncompressed {
		type VaultDataTable struct {
			Type    string        `json:"type"`
			Entries []interface{} `json:"entries"`
		}

		vaultDataTable := &VaultDataTable{}
		err := jsonutil.DecodeJSON(result, vaultDataTable)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress result: %v", err)
		}
		fmt.Printf("decrypted content:\n%v\n", vaultDataTable)
		return nil, nil
	}

	// Check to see if the returned data is an X.509 certificate
	cert, err := x509.ParseCertificate(result)
	if err == nil {
		publicKeyBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		certPem := string(pem.EncodeToMemory(&publicKeyBlock))
		fmt.Printf("decrypted content:\n%s\n", certPem)
		return nil, nil
	}

	return result, nil
}

func (e *encryptionData) shamirSplit() error {
	shamirBytes, err := shamir.Split(e.RecoveryKey, e.RecoveryConfig.SecretShares, e.RecoveryConfig.SecretThreshold)
	if err != nil {
		log.Fatalf("failed to create Shamir key shares of recovery key: %v", err)
	}

	for idx, keyshare := range shamirBytes {
		fmt.Printf("recovery key share %v: %s\n", idx+1, base64.StdEncoding.EncodeToString(keyshare))
	}

	return nil
}
