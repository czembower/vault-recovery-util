package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
)

// decryptSeal uses the auto-unseal device or unseal key to decrypt the provided ciphertext
func (e *encryptionData) decryptSeal(ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	blobInfo, err := protoUnmarshal(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	// Set wrapper configuration based on seal type and decrypt
	// SetConfig uses the following precendence to discover these values:
	// 1. environment variables
	// 2. configuration file
	// 3. instance identity/credentials
	var value []byte
	switch e.SealConfig.Type {
	case "transit":
		wrapper := transit.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"mount_path":      e.SealConfig.TransitConfig.MountPath,
			"key_name":        e.SealConfig.TransitConfig.KeyName,
			"address":         e.SealConfig.TransitConfig.Address,
			"token":           e.SealConfig.TransitConfig.Token,
			"namespace":       e.SealConfig.TransitConfig.Namespace,
			"tls_ca_cert":     e.SealConfig.TransitConfig.TlsCaCert,
			"tls_skip_verify": strconv.FormatBool(e.SealConfig.TransitConfig.TlsSkipVerify),
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		value, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "gcpckms":
		wrapper := gcpckms.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"user_agent":  e.SealConfig.GcpCkmsConfig.UserAgent,
			"credentials": e.SealConfig.GcpCkmsConfig.Credentials,
			"project":     e.SealConfig.GcpCkmsConfig.Project,
			"region":      e.SealConfig.GcpCkmsConfig.Region,
			"key_ring":    e.SealConfig.GcpCkmsConfig.KeyRing,
			"crypto_key":  e.SealConfig.GcpCkmsConfig.CryptoKey,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		value, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "azurekeyvault":
		wrapper := azurekeyvault.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"tenant_id":     e.SealConfig.AzureKeyVaultConfig.TenantID,
			"client_id":     e.SealConfig.AzureKeyVaultConfig.ClientID,
			"client_secret": e.SealConfig.AzureKeyVaultConfig.ClientSecret,
			"resource":      e.SealConfig.AzureKeyVaultConfig.Resource,
			"vault_name":    e.SealConfig.AzureKeyVaultConfig.VaultName,
			"key_name":      e.SealConfig.AzureKeyVaultConfig.KeyName,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		value, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "awskms":
		wrapper := awskms.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithKeyId(e.SealConfig.AwsKmsConfig.KmsKeyID), wrapping.WithConfigMap(map[string]string{
			"region":                  e.SealConfig.AwsKmsConfig.Region,
			"endpoint":                e.SealConfig.AwsKmsConfig.Endpoint,
			"access_key":              e.SealConfig.AwsKmsConfig.AccessKey,
			"secret_key":              e.SealConfig.AwsKmsConfig.SecretKey,
			"session_token":           e.SealConfig.AwsKmsConfig.SessionToken,
			"shared_creds_filename":   e.SealConfig.AwsKmsConfig.SharedCredsFile,
			"shared_creds_profile":    e.SealConfig.AwsKmsConfig.SharedCredsProfile,
			"web_identity_token_file": e.SealConfig.AwsKmsConfig.WebIdentityTokenFile,
			"role_session_name":       e.SealConfig.AwsKmsConfig.RoleSessionName,
			"role_arn":                e.SealConfig.AwsKmsConfig.RoleArn,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		value, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "shamir":
		if e.UnsealKey == nil {
			fmt.Printf("no unseal key found, collecting key shares from input (threshold: %d)\n", e.ShamirConfig.SecretThreshold)
			combinedUnsealKey, err := inputKeyShares(e.ShamirConfig)
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
		value, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	default:
		return nil, fmt.Errorf("seal type not supported")
	}

	return value, nil
}

// decrypt uses the provided key to open the ciphertext using AES-GCM
func decrypt(ciphertext []byte, key []byte, aadPath string) ([]byte, error) {
	// Load the key into an AES cipher block
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create the GCM from the cipher block
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	sz := gcm.NonceSize()
	if len(ciphertext) < sz {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	// Parse ciphertext for nonce and secret contents,
	// exluding the key term (4) and version (+1=5)
	nonce, raw := ciphertext[5:5+sz], ciphertext[5+sz:]
	out := make([]byte, 0, len(raw)-sz)

	// Open and decrypt
	var result []byte
	switch ciphertext[4] {
	case AESGCMVersion1:
		result, err = gcm.Open(out, nonce, raw, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt AESGCMVersion1 ciphertext: %v", err)
		}
	// Version2 uses the data path as additional authenticated data
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

	compressed, err := checkCompressed(result)
	if aadPath != keyringPath {
		if err == nil {
			fmt.Println("compressed: true")
			result = compressed
		} else {
			fmt.Println("compressed: false")
		}
	}

	pem, err := checkPem(result)
	if err == nil {
		result = pem
	}

	return result, nil
}

func findDek(ciphertext []byte, keyringData keyringData) ([]byte, error) {
	var dek string
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("invalid data path requested - no ciphertext found")
	}

	term := binary.BigEndian.Uint32(ciphertext[:4])
	for _, keyInfo := range keyringData.Keys {
		if uint32(keyInfo.Term) == term {
			dek = keyInfo.Value
			fmt.Printf("DEK: %s (term: %v)\n", dek, term)
		}
	}
	if dek == "" {
		fmt.Println("no DEK associated with this ciphertext")
		return nil, fmt.Errorf("unable to identify a DEK associated with this ciphertext")
	}

	keyringKey, err := base64.StdEncoding.DecodeString(dek)
	if err != nil {
		return nil, fmt.Errorf("error base64-decoding keyring key ciphertext: %v", err)
	}

	return keyringKey, nil
}

func parseVaultData(ciphertext []byte, readPath string, e encryptionData) ([]byte, error) {
	// attempt to find the appropriate DEK
	var secret []byte
	keyringKey, err := findDek(ciphertext, e.KeyringData)
	if err == nil {
		// If we found a DEK, assume that this is keyring-encrypted
		// data and return the decrypted plaintext
		secret, err = decrypt(ciphertext, keyringKey, readPath)
		if err != nil {
			return nil, fmt.Errorf("error decrypting readPath with keyring DEK: %v", err)
		}
		return secret, nil
	}

	// If no DEK was found to match the ciphertext, assume data is seal-wrapped
	var unwrappedSecret []byte
	switch e.SealConfig.Type {
	case "shamir":
		blobInfo, err := protoUnmarshal(ciphertext)
		if err != nil {
			// if this fails, return the raw ciphertext
			fmt.Println("unseal key-wrapped: false (no further decryption required)")
			return ciphertext, nil
		}
		// if it succeeds, extract the ciphertext from the blob and continue
		unwrappedSecret = blobInfo.Ciphertext
	default:
		// for KMS seals, decrypt using the unwrapper
		unwrappedSecret, err = e.decryptSeal(ciphertext)
		// if this fails, return the raw ciphertext
		if err != nil {
			fmt.Println("seal wrapped: false (no further decryption required)")
			return ciphertext, nil
		}
	}

	// if the unwrap via seal device worked, attempt to further decrypt the result
	// start by trying the root key
	fmt.Println("wrapped: true (further decryption will be attempted)")
	secret, err = decrypt(unwrappedSecret, e.RootKey, readPath)
	if err != nil {
		// if root key decryption failed, try to find a keyring key that matches
		fmt.Println("root key encryption: false")
		keyringKey, err := findDek(unwrappedSecret, e.KeyringData)
		// if that failed, return the unwrapped secret in base64 format
		if err != nil {
			fmt.Println("decrypting using seal only")
			secret = []byte(base64.StdEncoding.EncodeToString(unwrappedSecret))
		} else {
			// otherwise, try to decrypt with the found DEK
			secret, err = decrypt(unwrappedSecret, keyringKey, readPath)
			if err != nil {
				return nil, fmt.Errorf("decryption with keyring DEK failed")
			}
		}
	} else {
		fmt.Println("root key encryption: true")
	}

	return secret, nil
}
