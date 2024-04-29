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
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2"
	transit "github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
	"github.com/hashicorp/vault/sdk/helper/compressutil"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/shamir"
	"google.golang.org/protobuf/proto"
)

// decryptSeal uses the auto-unseal device or unseal key to decrypt the provided ciphertext
func (e *encryptionData) decryptSeal(ciphertext []byte) ([]byte, error) {
	// Initialize the seal configuration and set parameters learned Vault configuration file
	ctx := context.Background()

	// Load the seal ciphertext into a blobInfo object
	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(ciphertext, blobInfo); err != nil {
		eLen := len(ciphertext)
		if err := proto.Unmarshal(ciphertext[:eLen-1], blobInfo); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ciphertext to blob: %s: %v", err, blobInfo)
		}
	}

	// Set wrapper configuration based on seal type and decrypt
	// SetConfig uses the following precendence to discover these values:
	// 1. environment variables
	// 2. configuration file
	// 3. instance identity/credentials
	var pt []byte
	switch e.SealConfig.Type {
	case "transit":
		wrapper := transit.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"mount_path":      e.SealConfig.MountPath,
			"key_name":        e.SealConfig.KeyName,
			"address":         e.SealConfig.Address,
			"token":           e.SealConfig.Token,
			"namespace":       e.SealConfig.Namespace,
			"tls_ca_cert":     e.SealConfig.TlsCaCert,
			"tls_skip_verify": strconv.FormatBool(e.SealConfig.TlsSkipVerify),
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "gcpckms":
		wrapper := gcpckms.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"project":    e.SealConfig.Project,
			"region":     e.SealConfig.Region,
			"key_ring":   e.SealConfig.KeyRing,
			"crypto_key": e.SealConfig.CryptoKey,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "azurekeyvault":
		wrapper := azurekeyvault.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"tenant_id":     e.SealConfig.TenantID,
			"client_id":     e.SealConfig.ClientID,
			"client_secret": e.SealConfig.ClientSecret,
			"resource":      e.SealConfig.Resource,
			"vault_name":    e.SealConfig.VaultName,
			"key_name":      e.SealConfig.KeyName,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "awskms":
		wrapper := awskms.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithKeyId(""), wrapping.WithConfigMap(map[string]string{
			"region":                  e.SealConfig.Region,
			"endpoint":                e.SealConfig.Endpoint,
			"access_key":              e.SealConfig.AccessKey,
			"secret_key":              e.SealConfig.SecretKey,
			"session_token":           e.SealConfig.SessionToken,
			"shared_creds_filename":   e.SealConfig.SharedCredsFile,
			"shared_creds_profile":    e.SealConfig.SharedCredsProfile,
			"web_identity_token_file": e.SealConfig.WebIdentityTokenFile,
			"role_session_name":       e.SealConfig.RoleSessionName,
			"role_arn":                e.SealConfig.RoleArn,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "shamir":
		if e.UnsealKey == nil {
			fmt.Println("no unseal key found, collecting key shares from input")
			combinedUnsealKey, err := inputKeyShares(e)
			if err != nil {
				return nil, fmt.Errorf("failed to combine key shares: %s: %v", err, blobInfo)
			}
			e.UnsealKey = combinedUnsealKey
		}
		wrapper := aead.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"key": base64.StdEncoding.EncodeToString(e.UnsealKey),
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	default:
		return nil, fmt.Errorf("seal type not supported")
	}

	return pt, nil
}

// decrypt uses the provided key to open the ciphertext
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
		if aadPath != "" {
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

func inputKeyShares(e *encryptionData) ([]byte, error) {
	inputString := make([]string, e.ShamirConfig.SecretThreshold)
	inputBytes := make([][]byte, e.ShamirConfig.SecretThreshold)

	for idx := range inputString {
		fmt.Printf("unseal key share (%d of %d): ", idx+1, e.ShamirConfig.SecretThreshold)
		fmt.Scanln(&inputString[idx])
		bytes, _ := base64.StdEncoding.DecodeString(inputString[idx])
		inputBytes[idx] = bytes
	}

	combineOutput, err := shamir.Combine(inputBytes)
	if err != nil {
		return nil, fmt.Errorf("error combining input strings: %v", err)
	}
	return combineOutput, nil
}
